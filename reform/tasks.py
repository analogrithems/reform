import base64
import boto3
import botocore
import configparser
import glob
import hashlib
import io
import json
import logging
import os
import pprint
import random
import re
import subprocess
import sys
import tempfile
import time
import traceback

from reform import ConfigManager, SecretsManager, ReformSettings
from jinja2 import Environment, FileSystemLoader
from invoke import task
from invoke.util import debug
from invoke.tasks import call
from pathlib import Path
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.Hash import SHA
from Crypto import Random
from datetime import datetime
from pathlib import Path
from tempfile import mkstemp
from shutil import move
from sys import exit

# A few quick and dirty global configs
# TODO Move these to config file
settings = ReformSettings.ReformSettings()
projects = settings.projects()
quadrants = ", ".join(settings.get_quadrants())
tf_bin = "terraform"
tf_docs_bin = "terraform-docs"
ciphers = "PKCS1_v1_5 (default), RSA_AES, PKCS1_OAEP"
outputs = "text (default), json"
os.environ["TF_IN_AUTOMATION"] = "1"


def p_log(msg, severity="info"):
    """
    This function will output to the console useful information.
    """
    run_time = time.process_time()
    print("%s: %s. (%s)" % (severity.upper(), msg, run_time), file=sys.stderr)


def stat_wrap(func):
    """
    This will give stats at the end to see the time it took.  Helpful when planning prod deployments from stage environments.
    """

    def inner(*args, **kwargs):
        run_time = time.process_time()
        p_log("Completed in %s" % (run_time))
        return func(*args, **kwargs)

    return inner


@task(
    help={
        "path": "Path to the new project, defaults to current working directory",
        "quadrant": "New quadrant you wish to add",
        "bucket": "Which S3 bucket to place your terraform state inside of for a specified quadrant",
        "region": "Region to place the new quadrant in",
    }
)
def create(c, path=None, quadrant=None, bucket=None, region=None):
    """
    Create a new reform project.  This will build the directory skeleton and
    create initial settings files in the root of your project.

    If the -q, --quadrant flag is given, it can also be used to create a new quadrant.
    Quadrants allow you to use the same projects with different configs.
    This is helpful if you need to have an east vs. west quadrant or a dev, stage and prod quadrant etc.

    --bucket - If you specify quadrant you must also specify an existing bucket to place your state file and secrets keys in.

    The --region argument will specify which region your quadrant should live in.

    You should use this tool whenever you need to make a new quadrant.
    This tool will save the location of a quadrants bucket and region in the .reform settings file in the root of your project.
    """
    if path == None:
        path = os.getcwd()

    p_log("Task: Create project %s" % (path))

    ReformSettings.ReformSettings.InitReform(path)

    # If quadrant, bucket and region specified lets build the out
    if quadrant and bucket and region:

        # This will create our new RSA key pair in our bucket and add an entry to or .reform settings file
        key_gen(c, bucket, quadrant, region)
        """
        Since we were told to create a new ENV we will also need to make a config directory and initial config file for our quadrant.
        """
        settings = ReformSettings.ReformSettings()
        result = settings.NewQuadrant(bucket, quadrant, region)

        # TODO - Should we create configs.auto.tvars and state.tf?


# TODO All terraform tasks should be namespaced
@task(
    help={
        "project": "Which project do we want to clean. "
        + "(Available: [%s])" % (projects)
    }
)
def clean(c, project):
    """
    This will clean up the terraform cache directory reform files from your project
    You need to do this between quadrants
    """
    p_log("Task: Clean")
    reform_root = settings.GetReformRoot()
    if project not in projects:
        debug("Clean: Not a valid project: '%s'" % (project))
        p_log("Clean: Not a valid project: '%s'" % (project))
        exit(1)

    project_path = "%s/projects/%s/.terraform" % (reform_root, project)
    project_tf_cache = Path(project_path)
    if not project_tf_cache.is_dir():
        debug("Clean: Project cache path does not exists: '%s'" % (project_path))

    clean = c.run("rm -Rf %s" % (project_path)).stdout.strip()
    debug("Clean Result: %s" % (clean))

    old_project_tfplan = "%s/projects/%s/tfplan" % (reform_root, project)
    old_project_tfplan_path = Path(old_project_tfplan)
    if old_project_tfplan_path.is_file():
        os.remove(old_project_tfplan)
        debug("Clean: Removed '%s'" % (old_project_tfplan))

    # We should also cleanup any preform files at this step just incase they
    # change and get abandoned
    preform_path = "%s/projects/%s/**/preform_*.tf" % (reform_root, project)
    for filename in glob.iglob(preform_path, recursive=True):
        debug("Clean: removing %s" % (filename))
        os.remove(filename)

    # TODO Remove preform files from modules
    preform_path = "%s/modules/%s/**/preform_*.tf" % (reform_root, project)
    for filename in glob.iglob(preform_path, recursive=True):
        debug("Clean: removing %s" % (filename))
        os.remove(filename)


@task(
    help={
        "project": "Which project do we want to init. "
        + "(Available: [%s])" % (projects),
        "quadrant": "Which quadrant to init. (Available: [%s])" % (quadrants),
    }
)
def init(c, project, quadrant):
    """
    Before terraform can run we need to initialize it.
    The init process sets up the backend for state management and insures we don't collide quadrants.
    """
    p_log("Task: Init")
    reform_root = settings.GetReformRoot()

    # TODO build this dynamically
    if project not in projects:
        debug("Init: Not a valid project: '%s'" % (project))
        p_log("Init: Not a valid project: '%s'" % (project))
        exit(1)

    project_path = "%s/projects/%s" % (reform_root, project)
    project_tf = Path(project_path)
    if not project_tf.is_dir():
        debug("Init: Project path does not exists: '%s'" % (project_path))
        p_log("Init: Project path does not exists: '%s'" % (project_path))
        exit(2)

    # Run pre task
    clean(c, project)
    preform(c, quadrant)

    _cmd = "%s init " % (tf_bin)
    with c.cd(project_path):
        _fmt_ = c.run("%s fmt" % (tf_bin)).stdout.strip()
        debug("Init: '%s fmt' output '%s'" % (tf_bin, _fmt_))
        _init_ = c.run(_cmd).stdout.strip()
        debug("Init: %s output '%s'" % (_cmd, _init_))

@task(
    help={
        "project": "Which project do we want to terraform-doc. "
        + "(Available: [%s])" % (projects),
        "quadrant": "Which quadrant to terraform-doc. (Available: [%s])" % (quadrants),
    }
)
def mkdocs(c, project, quadrant):
    """
    This recursively runs terraform-docs on a project
    """
    p_log("Start: terrafrom-docs")
    reform_root = settings.GetReformRoot()

    project_path = "%s/projects/%s" % (reform_root, project)
    project_tf = Path(project_path)
    if not project_tf.is_dir():
        debug("Plan: Project path does not exists: '%s'" % (project_path))
        p_log("Plan: Project path does not exists: '%s'" % (project_path))
        exit(2)

    # Run pre task
    if os.path.isdir(f"{project_path}/.terraform"):
        preform(c, quadrant)
    else:
        init(c, project, quadrant)
    tf_docs_args = os.getenv("TF_DOCS_ARGS", "")

    _cmd = "%s markdown --recursive %s" % (tf_docs_bin, tf_docs_args)

    with c.cd(project_path):
        _init_ = c.run(_cmd).stdout.strip()
        debug("terrafrom-docs: %s output '%s'" % (_cmd, _init_))

    p_log("Complete: terrafrom-docs")

@task(
    help={
        "project": "Which project do we want to terraform plan. "
        + "(Available: [%s])" % (projects),
        "quadrant": "Which quadrant to plan. (Available: [%s])" % (quadrants),
    }
)
def plan(c, project, quadrant):
    """
    This does a standard terraform plan in the project specified.
    It also requires to quadrant to specify what to propose changes for.
    """
    p_log("Start: Plan")
    reform_root = settings.GetReformRoot()

    project_path = "%s/projects/%s" % (reform_root, project)
    project_tf = Path(project_path)
    if not project_tf.is_dir():
        debug("Plan: Project path does not exists: '%s'" % (project_path))
        p_log("Plan: Project path does not exists: '%s'" % (project_path))
        exit(2)

    # Run pre task
    if os.path.isdir(f"{project_path}/.terraform"):
        preform(c, quadrant)
    else:
        init(c, project, quadrant)
    pl = os.getenv("TF_PARALLEL", 10)

    _cmd = "%s plan -out=tfplan -parallelism=%s" % (tf_bin, pl)

    with c.cd(project_path):
        _init_ = c.run(_cmd).stdout.strip()
        debug("Plan: %s output '%s'" % (_cmd, _init_))

    p_log("Complete: Plan")


@task(
    help={
        "project": "Which project do we want to terraform apply. "
        + "(Available: [%s])" % (projects),
        "quadrant": "Which quadrant to apply. (Available: [%s])" % (quadrants),
    }
)
def apply(c, project, quadrant):
    """
    This applies a set of changes to terraform.
    It will run a plan first if a tfplan file is not found
    """
    p_log("Start: Apply")
    reform_root = settings.GetReformRoot()

    # TODO build this dynamically
    if project not in projects:
        debug("Apply: Not a valid project: '%s'" % (project))
        p_log("Apply: Not a valid project: '%s'" % (project))
        exit(1)

    project_path = "%s/projects/%s" % (reform_root, project)
    project_tf = Path(project_path)
    if not project_tf.is_dir():
        debug("Apply: Project path does not exists: '%s'" % (project_path))
        p_log("Apply: Project path does not exists: '%s'" % (project_path))
        exit(2)

    # Run plan if no tfplan exists
    project_tfplan = "%s/tfplan" % (project_path)
    project_tfplan_path = Path(project_tfplan)
    if not project_tfplan_path.is_file():
        plan(c, project, quadrant)
        debug("Apply: produce a plan")

    pl = os.getenv("TF_PARALLEL", 10)
    _cmd = "%s apply -parallelism=%s %s " % (tf_bin, pl, project_tfplan)

    with c.cd(project_path):
        _init_ = c.run(_cmd).stdout.strip()
        debug("Apply: %s output '%s'" % (_cmd, _init_))

    p_log("Complete: Apply")


@task(
    help={
        "project": "Which project do we want to deploy. (Available: [%s])" % (projects),
        "quadrant": "Which quadrant to deploy. (Available: [%s])" % (quadrants),
    }
)
def deploy(c, project, quadrant):
    """
    When we make a change we need to deploy that change to a specified quadrant and project.
    In doing this we will do the following
    * Clean up the project
    * Preform any project templates
    * Initialize the project backend in the specified quadrant
    * Plan the changes
    * Apply the changes
    * Commit the changes if there are any
    """
    p_log("Start: Deploy")
    # Plan also Inits, init also cleans
    plan(c, project, quadrant)

    # Apply our plan if we have not died yet
    apply(c, project, quadrant)
    p_log("Complete: Deploy")


# TODO make a project arg to only preform one project at a time
@task(
    help={
        "quadrant": "Which quadrant to pre-process. (Available: [%s])" % (quadrants),
    }
)
def preform(c, quadrant):
    """
    A simple preprocessor for terraform that processes *\*.tf.tpl* files.
    This is how we work around terraforms lack of loops and conditionals.

    This is also how we seed our dynamic reform configs for state backend and and configs we've defined.
    """
    p_log("Start: Preform")
    projects_base_path = settings.GetReformRoot()

    # TODO Open this more to include modules
    work_dir = settings.GetReformRoot()
    modules_dir = "%s/modules" % (settings.GetReformRoot())
    projects_dir = "%s/projects" % (settings.GetReformRoot())
    template_suffix = ".tpl"
    env = Environment(loader=FileSystemLoader(work_dir), trim_blocks=True)

    # Custom Jinja Filters
    def is_list(value):
        return isinstance(value, list)

    def is_dict(value):
        return isinstance(value, dict)

    env.filters["is_list"] = is_list
    env.filters["is_dict"] = is_dict
    env.filters["jsonify"] = json.dumps

    # Lets load custom helpers
    if os.path.isfile(f"{work_dir}/helpers/__init__.py"):
        p_log("Found custom helper, importing")
        sys.path.insert(1, work_dir)

        try:
            from helpers import preform_hook

            preform_hook()
        except Exception as error:
            p_log(f"An error occurred: {error}")
            p_log(f"Failed to find and run preform_hook() in {work_dir}/helpers")
            traceback.print_exc()
            exit(-22)


    config = ConfigManager.ConfigManager({"env": quadrant}).get_merge_configs()
    secret_manager = SecretsManager.SecretsManager(
        {"key": quadrant, "cipher": "RSA_AES"}
    )
    env_secret = secret_manager.getSecretPath(quadrant)
    secrets = secret_manager.decryptSecretFile(env_secret)
    # Handle modules dir
    for directory, subdirectories, files in os.walk(modules_dir):
        for file in files:
            if file.endswith(template_suffix):
                debug("Found template file: %s" % (file))
                full_file_path = os.path.join(directory, file)
                template = env.get_template(full_file_path.replace(work_dir, ""))
                new_full_file_path = re.sub(
                    template_suffix, "", os.path.join(directory, "preform_" + file)
                )

                debug("Generating file: %s" % (new_full_file_path))
                try:
                    with open(new_full_file_path, "w+") as outfile:
                        redered_template = template.render(
                            config=config,
                            project=os.path.basename(directory),
                            quadrant=quadrant,
                            secrets=secrets,
                        )
                        debug(redered_template)
                        outfile.write(
                            "##################################################\n"
                        )
                        outfile.write(
                            "# This file auto generated by preform, do not edit!\n"
                        )
                        outfile.write("# Instead edit \n")
                        outfile.write("# %s\n" % (full_file_path))
                        outfile.write(
                            "##################################################\n"
                        )
                        outfile.write("\n\n")
                        outfile.write(redered_template)
                        outfile.write("\n\n")
                    outfile.close()
                except:
                    pass

    # Handle projects dir
    for directory, subdirectories, files in os.walk(projects_dir):
        for file in files:
            if '.terraform/' in file:
                continue

            if '.git/' in file:
                continue

            if file.endswith(template_suffix):
                debug("Found template file: %s" % (file))
                full_file_path = os.path.join(directory, file)
                template = env.get_template(full_file_path.replace(work_dir, ""))
                new_full_file_path = re.sub(
                    template_suffix, "", os.path.join(directory, "preform_" + file)
                )

                debug("Generating file: %s" % (new_full_file_path))
                with open(new_full_file_path, "w+") as outfile:
                    redered_template = template.render(
                        config=config,
                        project=os.path.basename(directory),
                        quadrant=quadrant,
                        secrets=secrets,
                    )
                    debug(redered_template)
                    outfile.write(
                        "##################################################\n"
                    )
                    outfile.write(
                        "# This file auto generated by preform, do not edit!\n"
                    )
                    outfile.write("# Instead edit \n")
                    outfile.write("# %s\n" % (full_file_path))
                    outfile.write(
                        "##################################################\n"
                    )
                    outfile.write("\n\n")
                    outfile.write(redered_template)
                    outfile.write("\n\n")
                outfile.close()

    p_log("Complete: Preform")


@task(
    help={
        "bucket": "Name of an AWS bucket to create, must be unique",
        "region": "The AWS Region our bucket should be created in",
    }
)
def mkS3Bucket(c, bucket, region):
    """
    Create the Secure S3 bucket we will store our secret keys in.
    This will use the kms key with alias aws/s3 for encrypting contents
    of S3 bucket.
    """
    p_log("Task: mkS3Bucket")
    # First lets find our kms key with alias kms/s3
    client = boto3.client("kms", region)
    bucket_constraint = {}
    if region == "us-east-1":
        s3c = boto3.client("s3")
    else:
        s3c = boto3.client("s3", region_name=region)
        bucket_constraint = {"LocationConstraint": region}

    p_log("Region: %s" % (region))
    create_args = {"ACL": "private", "Bucket": bucket}
    if region != "us-east-1":
        create_args["CreateBucketConfiguration"] = bucket_constraint

    response = s3c.create_bucket(**create_args)
    response = s3c.put_bucket_versioning(
        Bucket=bucket, VersioningConfiguration={"Status": "Enabled"}
    )
    debug("mkS3Bucket: {}".format(response))
    response = s3c.put_bucket_encryption(
        Bucket=bucket,
        ServerSideEncryptionConfiguration={
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "aws:kms",
                    }
                }
            ]
        },
    )
    debug("mkS3Bucket secure: {}".format(response))
    p_log("%s created in %s" % (bucket, region))


# TODO This function should not be in core, or be reconfigured for more general args
@task()
def get_config(c):
    """
    Fetches part of the config for use in a terraform map.
    Terraform can't handle multidimensional maps, this tool fetches a section of
    map and returns it as json.  Unlike other tasks, this tasks gets it's args
    from a json string sent to stdin.
    """
    p_log("Task: get_config")
    reform_root = settings.GetReformRoot()
    params = {}

    lines = [x.strip() for x in sys.stdin.readlines()]

    lines = list(filter(None, lines))
    if len(lines) != 0:
        params = json.loads(",".join(lines))

    c = {}

    if "cipher" in params and params["cipher"]:
        file = "%s/configs/%s/%s" % (
            reform_root,
            params["env"],
            ReformSettings.ReformSettings.reform_quadrant_secret_file,
        )
        if os.path.exists(file):
            with open(file, "r") as f:
                config = json.loads(f.read())
        else:
            p_log("Nested map not found: %s" % (file))
            exit(5)
    else:
        config = ConfigManager.ConfigManager({"env": params["env"]}).get_merge_configs()

    p_log("args: %s" % (params))

    if "swimlanes" in config:
        members = config["swimlanes"]
        # debug("Nested map found: %s"%(json.dumps(members)))
        if (
            params["client"] in members
            and params["service"] in members[params["client"]]["services"]
        ):
            c = members[params["client"]]["services"][params["service"]]["configstore"]
    else:
        if params["client"] in config and params["service"] in config[params["client"]]:
            c = config[params["client"]][params["service"]]

    if "cipher" in params and params["cipher"]:
        c = SecretsManager.SecretsManager(
            {"key": params["env"], "cipher": params["cipher"]}
        ).secretDecoderRing(c)
    print(json.dumps(c))





@task(help={"length": "Length of password to generate. (Default=10)"})
def pass_gen(c, length=10):
    """
    Creates a strong random password.

    """
    p_log("Task: pass_gen")
    print(SecretsManager.SecretsManager({}).passwordGenerate(length))


@task(
    help={
        "quadrant": "The quadrant to use for crypting messages. (Available: [%s])"
        % (quadrants),
        "encrypt": "Plaintext message to encrypt",
        "decrypt": "Cipher-text message to decrypt",
        "cipher": "Which cipher to use. (Available: [%s])" % (ciphers),
        "output": "Specify your output method. (Available: [%s])" % (outputs),
    }
)
def cryptic(c, quadrant, encrypt="", decrypt="", cipher="PKCS1_v1_5", output="text"):
    """
    Handle message crypting.
    If you need to encrypt or decrypt a message specify the quadrant and action.
    For messages that need to be larger than the modulus of the key use RSA_AES,
    This cipher wont work natively with Terraform so use a data external to have
    this tool decrypt your big strings at runtime.
    """
    p_log("Task: cryptic")
    if encrypt:
        response = SecretsManager.SecretsManager(
            {"key": quadrant, "cipher": cipher}
        ).rsa_encrypt(encrypt)
    elif decrypt:
        response = SecretsManager.SecretsManager(
            {"key": quadrant, "cipher": cipher}
        ).rsa_decrypt(decrypt)

    if output == "json":
        print(json.dumps(response))
    else:
        print(response)


@task(
    help={
        "bucket": "Name of an AWS bucket to store or keys",
        "quadrant": "Which quadrant to manage secrets for. (Available: [%s])"
        % (quadrants),
        "region": "Region the bucket exists in for upload",
    }
)
def key_gen(c, bucket, quadrant, region):
    """
    Create RSA keys for secret management.
    We will use these keys to encrypt and decrypt our secrets in terraform.
    """
    p_log("Task: key_gen")
    print(
        SecretsManager.SecretsManager(
            {"key": quadrant, "bucket": bucket, "region_name": region}
        ).generateKeyPair()
    )


@task(
    help={
        "quadrant": "Which quadrant to manage configs for. (Available: [%s])"
        % (quadrants),
        "attribute": "The dot notation path to the config you wish to change",
        "value": "The value you want to set the config to",
    }
)
def config_set(c, quadrant, attribute, value="", secure=False):
    """
    Set an attribute in our terraform configs.
    """
    p_log("Task: config_set")
    result = ConfigManager.ConfigManager(
        {"env": quadrant, "attribute": attribute, "value": value}
    ).upsert()

    if result:
        p_log("ok")
        return True
    return False


@task(
    help={
        "quadrant": "Which quadrant to get configs for. (Available: [%s])"
        % (quadrants),
        "attribute": "The dot notation path to the config you wish to get",
        "cipher": "Which cipher to use. Setting this assumes we're using a secret (Available: [%s])"
        % (ciphers),
        "output": "Specify your output method. (Available: [%s])" % (outputs),
    }
)
def config_get(c, quadrant, attribute, cipher=None, output="text"):
    """
    Get an attribute from our configs.  If you set the cipher then it assumes you want config from a secret.
    """
    p_log("Task: config_get")
    result = ConfigManager.ConfigManager(
        {"env": quadrant, "attribute": attribute, "cipher": cipher}
    ).read()

    if output == "json":
        ret = json.dumps(result)
        print(ret)
        return ret
    else:
        print(result)
        return result


@task(
    help={
        "quadrant": "Which quadrant to delete configs for. (Available: [%s])"
        % (quadrants),
        "attribute": "The dot notation path to the config you wish to delete",
    }
)
def config_delete(c, quadrant, attribute):
    """
    Delete an attribute in our terraform configs.
    """
    p_log("Task: config_delete")
    result = ConfigManager.ConfigManager(
        {"env": quadrant, "attribute": attribute}
    ).delete()

    if result:
        print("ok")
        return True
    return False


@task(
    help={
        "quadrant": "Which quadrant to delete configs for. (Available: [%s])"
        % (quadrants)
    }
)
def config_delete_file(c, quadrant):
    """
    Delete/Truncate the whole config file
    """
    p_log("Task: config_delete_file")
    result = ConfigManager.ConfigManager({"env": quadrant}).delete_config()

    if result:
        print("ok")
        return True
    return False


@task(
    help={
        "bucket": "Which bucket to check for key",
        "quadrant": "Which quadrant to manage secrets for. (Available: [%s])"
        % (quadrants),
    }
)
def key_exists(c, bucket, quadrant):
    """
    Check to see if a given key already exists
    """
    p_log("Task: key_exists")
    r = SecretsManager.SecretsManager({"bucket": bucket}).keyExists(quadrant)
    if r:
        print("Found")
        return True
    else:
        print("Not Found")
        return False


@task(
    help={
        "quadrant": "Which quadrant to manage secrets for. (Available: [%s])"
        % (quadrants),
        "cipher": "Change the default cipher to use.  (Available: [%s])" % (ciphers),
    }
)
def secrets(c, quadrant, cipher="PKCS1_v1_5"):
    """
    An interactive secret manager.
    Terraform doesn't handle secrets well, this fixes that for us.
    Using the keys we generated with the key-gen task we open an interactive
    editor with our secrets decrypted.  When we save and exit the editor our
    secrets are encrypted and stored in a our config.
    Terraform has a poorly documented function called rsadecrypt
    https://www.terraform.io/docs/configuration/interpolation.html#rsadecrypt-string-key-

    If you need to manage secrets that are larger than 245 characters
    (For a 2048bit key modulus - 11 = 245) then you should use the RSA_AES cipher
    This allows larger secrets but you can't use the built in terraform rsadecrypt

    Instead you will have to use data external like this
    Note: this will be a little slower than terraforms native rsadecrypt


    # config/${quadrant}/secrets.json
      {
        "foo": {
          "bar": {
            "API_KEY": "I got a secret, a super, super secret"
          }
        }
      }

    # projects/infrastructure/main.tf
      data "external" "secret_decrypt" {
        #Use dot notation for path to key
        program = [
          "reform",
          "config-get",
          "--quadrant",
          "${var.vpc_name}",
          "--attribute",
          "foo.bar.API_KEY",
          "--cipher",
          "RSA_AES",
          "--output",
          "json"
        ]
      }

      locals {
        API_KEY = "${data.external.secret_decrypt.result.usage}"
      }

    Now you can use local.API_KEY anywhere you need the decrypted secret and at run
    time terraform will call reform to decrypt your secret.

    """
    p_log("Task: Secrets")
    # TODO make this work with revised config format
    print(
        SecretsManager.SecretsManager(
            {"key": quadrant, "cipher": cipher}
        ).InteractiveEdit()
    )


@task(
    help={
        "quadrant": "Which quadrant to manage secrets for. (Available: [%s])"
        % (quadrants),
        "cipher": "Which cipher to use. (Available: [%s])" % (ciphers),
    }
)
def rotate_key(c, quadrant, cipher="PKCS1_v1_5"):
    """
    Rotate our RSA Keys.
    This will move our old keys to *\*.old* and generate a new key pair.
    It then walks through our configs and re-encrypts the secrets with the new
    keys
    """
    p_log("Task: rotate_key")
    print(SecretsManager.SecretsManager({"key": quadrant, "cipher": cipher}).rekey())


@task
def auto_generate_config(c):
    p_log("Task: auto_generate_config")
    reform_root = settings.GetReformRoot()

    config = ConfigManager.ConfigManager(
        {"env": "defaults"}
    ).auto_generate_default_config()
