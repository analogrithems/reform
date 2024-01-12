import base64
import boto3
import botocore
import configparser
import hashlib
import io
import json
import logging
import os
import pprint
import random
import subprocess
import tempfile
import time

from reform import ReformSettings
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


class SecretsManager:

    profile_settings_path = [
        "%s/.secretsManager" % (str(Path.home())),
        "%s/.secretsManager" % (os.path.dirname(os.path.realpath(__file__))),
    ]
    cache_keys = {}
    key_length = 2048
    secrets_file = ReformSettings.ReformSettings.reform_quadrant_secret_file

    def __init__(self, opts):
        a = {}
        if "profile" in opts and opts["profile"]:
            a["profile_name"] = opts["profile"]
        if "region" in opts and opts["region"]:
            a["region_name"] = opts["region"]
        self.session = boto3.Session(**a)
        self.args = opts
        self.pp = pprint.PrettyPrinter(indent=4)
        self.logger = logging.getLogger(__name__)
        self.logger.debug("ARGS: %s" % (self.pp.pformat(opts)))
        try:
            self.account_id = (
                self.session.client("sts").get_caller_identity().get("Account")
            )
        except botocore.exceptions.ClientError:
            self.logger.error("Failed to auth to AWS.")
            exit(-9)

        self.settings = ReformSettings.ReformSettings()
        self.UnSerializeSettings()

    def serializeSettings(self):
        """
        This stores the last used bucket and key in the users home dir
        under SecretsManager::profile_settings_path
        """
        change = False
        config = self.settings.get_config()

        section = {}

        if "key" in self.args:
            section["key"] = self.args["key"]
        if "region" in self.args:
            section["region"] = self.args["region"]
        if "bucket" in self.args:
            section["bucket"] = self.args["bucket"]

        if "key" in self.args:
            self.settings.set_config_section(self.args["key"], section)

    def UnSerializeSettings(self):
        """
        This unserializes the settings that were stored in the
        serializeSettings.  This is helpful to reduce the amount of
        args that must be passed all the time,
        """
        config = self.settings.get_config()

        if (
            "bucket" not in self.args
            and "key" in self.args
            and config.has_option(self.args["key"], "bucket")
        ):

            if config.has_option(self.args["key"], "bucket"):
                self.args["bucket"] = config.get(self.args["key"], "bucket")

            if config.has_option(self.args["key"], "region"):
                self.args["region"] = config.get(self.args["key"], "region")

    def getSecretPath(self, key=False):
        if key == False:
            key = self.args["key"]

        env_secret = "%s/configs/%s/%s" % (
            self.settings.GetReformRoot(),
            key,
            self.secrets_file,
        )
        return env_secret

    def InteractiveEdit(self):
        """
        In interactive editing mode we decrypt our MasterSecretsVolume and
        show all secrets in all environments.  You can then add, edit or remove
        secrets at will.  When you exit the editor each environments secrets
        are split up and placed in their corresponding environment config file.
        """

        # Read an decrypt all env secret volumes
        config = self.settings.get_config()
        oldVault = {}
        sections = config.sections()
        preChecksum = 0
        postChecksum = 0
        # If we set the key, we will only edit that environment
        if "key" in self.args:
            sections = [self.args["key"]]

        for key in sections:
            oldVault[key] = {}
            env_secret = self.getSecretPath(key)
            if os.path.exists(env_secret):
                # Load Key & bucket
                self.args["key"] = config[key]["key"]
                self.args["bucket"] = config[key]["bucket"]
                oldVault[key] = self.decryptSecretFile(env_secret)
            else:
                self.logger.warn(
                    "%s file doesn't exists. Must be starting fresh!" % (env_secret)
                )

        # Make Tempfile
        (fd, temp_path) = tempfile.mkstemp()
        fp = os.fdopen(fd, "w")

        # Write dict of all unencrypted strings
        fp.write(json.dumps(oldVault, sort_keys=True, indent=4, separators=(",", ": ")))
        fp.close()
        preChecksum = hashlib.md5(open(temp_path, "rb").read()).hexdigest()

        # Spawn editor to allow user to make changes
        editor = os.getenv("EDITOR", "vi")
        subprocess.call("%s %s" % (editor, temp_path), shell=True)

        # If file hasn't changed, don't bother trying to rencode it
        postChecksum = hashlib.md5(open(temp_path, "rb").read()).hexdigest()
        if preChecksum == postChecksum:
            self.logger.info("No changes to secrets, bailing")
            return True
        """
      When user exists, check the json is valid or allow them
      to fix it.

      If JSON is valid break it up by environment and start encrypting
      strings per env using the proper keys.
      """

        with open(temp_path, "r") as f:
            try:
                updated = json.loads(f.read())
            except json.decoder.JSONDecodeError:
                self.logger.error(
                    "Interactive edit contained invalid JSON. '%s'" % (f.read())
                )
                exit(-3)

            for key in updated:
                # Quick safety check to make sure we limit our scope to the env we selected
                if key not in sections:
                    continue
                env_secret = self.getSecretPath(key)

                # Set key & bucket
                self.args["key"] = config[key]["key"]
                self.args["bucket"] = config[key]["bucket"]

                self.encryptSecretFile(updated[key], env_secret)

        os.unlink(temp_path)
        return True

    def decryptSecretFile(self, env_secret):
        decrypted_vault = {}
        try:
            with open(env_secret, "r") as f:
                try:
                    cipheredSecrets = json.loads(f.read())
                    self.logger.debug(
                        "Read file: %s got %s" % (env_secret, cipheredSecrets)
                    )
                except json.decoder.JSONDecodeError:
                    self.logger.error("Error loading %s secrets json" % (env_secret))
                    exit(-5)

                self.logger.debug(cipheredSecrets)
                decrypted_vault = self.secretDecoderRing(cipheredSecrets)
            
        except FileNotFoundError as e:
            pass

        return decrypted_vault

    def encryptSecretFile(self, plaintext_config, secret_file):
        newVault = self.secretEnecoderRing(plaintext_config)
        with open(secret_file, "w+") as _secret_file:
            _secret_file.write(
                json.dumps(newVault, sort_keys=True, indent=4, separators=(",", ": "))
            )

    def secretEnecoderRing(self, secrets):
        """
        Steps thought our object and encrypts all the values
        """
        for key, value in secrets.items():
            if isinstance(value, dict):
                secrets[key] = self.secretEnecoderRing(value)
            elif isinstance(value, list):
                sec_list = []
                for i in value:
                    if isinstance(i, dict):
                        sec_list.append(self.secretEnecoderRing(i))
                    elif isinstance(i, list):
                        sec_list.append(self.secretEnecoderRing(i))
                    else:
                        sec_list.append(self.rsa_encrypt(i))
                secrets[key] = sec_list
            else:
                secrets[key] = self.rsa_encrypt(value)
        return secrets

    def secretDecoderRing(self, secrets):
        """
        Steps thought our object and decrypts all the values
        """
        for key, value in secrets.items():
            if isinstance(value, dict):
                secrets[key] = self.secretDecoderRing(value)
            elif isinstance(value, list):
                sec_list = []
                for i in value:
                    if isinstance(i, dict):
                        sec_list.append(self.secretDecoderRing(i))
                    elif isinstance(i, list):
                        sec_list.append(self.secretDecoderRing(i))
                    else:
                        sec_list.append(self.rsa_decrypt(i))
                secrets[key] = sec_list
            else:
                secrets[key] = self.rsa_decrypt(value)
        return secrets

    def inputValidate(self, v):
        """
        Check to make sure a give argument was pissed and valid
        """
        if v not in self.args:
            raise Exception("Missing argument --%s" % (v.replace("-", "_")))

    def secureUpload(self, b, bucket, path):
        """
        Securely upload files to s3 and mark them private so no one
        else can see them.
        """
        if "dry" not in self.args:
            s3 = self.session.resource("s3")
            self.logger.debug("Uploaded %s to %s/%s" % (b, bucket, path))
            _obj = s3.Object(bucket, path)
            response = _obj.put(
                ACL="private",
                Body=b,
                ContentType="text/plain",
                ServerSideEncryption="aws:kms",
            )
            return response
        else:
            self.logger.info("Uploaded %s to %s/%s" % (b, bucket, path))
            return True

    def keyExists(self, key):
        """
        Checks if a given key exists in the specified s3 region and env

        """
        path = "%s/SecretsMaster" % (key)
        s3 = self.session.resource("s3")
        try:
            _obj = s3.Object(self.args["bucket"], path).load()
            return True
        except botocore.exceptions.ClientError as e:
            return False

    def passwordGenerate(self, passlen):
        """
        This just makes a quick and dirty random password.
        """
        p = "".join(
            random.sample(
                "abcdefghijklmnopqrstuvwxyz01234567890ABCDEFGHIJKL"
                + "MNOPQRSTUVWXYZ.%?<>^)(,$",
                passlen,
            )
        )
        return p

    def rsa_encrypt(self, orig_message):
        """
        This Encrypts a string with the private key from the given
        environment. Uses RSA and/or AES depending on cipher arg given.
        If no arg given to init, defaults to PKCS1_v1_5

        Valid cipher options ['PKCS1_v1_5','RSA_AES','PKCS1_OAEP']

        """
        mem_key = self.getPublicKey()
        message = orig_message.encode("utf-8")
        self.logger.debug("Fetched key: %s" % (mem_key))
        key = RSA.importKey(mem_key)
        if "cipher" in self.args and self.args["cipher"] == "PKCS1_OAEP":
            cipher_rsa = PKCS1_OAEP.new(key)
            ciphertext = cipher_rsa.encrypt(message)
        elif "cipher" in self.args and self.args["cipher"] == "RSA_AES":
            session_key = get_random_bytes(16)
            cipher_rsa = PKCS1_OAEP.new(key)
            enc_session_key = cipher_rsa.encrypt(session_key)
            # Encrypt the data with the AES session key
            cipher_aes = AES.new(session_key, AES.MODE_EAX)
            aes_ciphertext, tag = cipher_aes.encrypt_and_digest(message)
            ciphertext = enc_session_key + cipher_aes.nonce + tag + aes_ciphertext
        else:
            cipher_rsa = PKCS1_v1_5.new(key)
            ciphertext = cipher_rsa.encrypt(message)
        c = base64.b64encode(ciphertext)
        self.logger.debug("ciphertxt: %s" % (c.decode("utf-8")))
        return c.decode("utf-8")

    def rsa_decrypt(self, message, key=False):
        """
        This Decrypts a string with the private key from the given
        environment. Uses RSA and/or AES depending on cipher arg given.
        If no arg.cipher given to init, defaults to PKCS1_v1_5

        Valid cipher options ['PKCS1_v1_5','RSA_AES','PKCS1_OAEP']

        If the default key doesn't work we try the previous key.old
        """
        old = False
        if not key:
            mem_key = self.getPrivateKey()
            key = RSA.importKey(mem_key)
        else:
            old = True

        try:
            b = base64.b64decode(message)
            if "cipher" in self.args and self.args["cipher"] == "PKCS1_OAEP":
                self.logger.debug("Decrypting with PKCS1_OAEP")
                cipher_rsa = PKCS1_OAEP.new(key)
                cleartext = cipher_rsa.decrypt(b)
            elif "cipher" in self.args and self.args["cipher"] == "RSA_AES":
                self.logger.debug("Decrypting with RSA_AES")
                file_in = io.BytesIO(b)
                file_in.seek(0)
                enc_session_key, nonce, tag, ciphertext = [
                    file_in.read(x) for x in (key.size_in_bytes(), 16, 16, -1)
                ]
                file_in.close()
                # Decrypt the session key with the private RSA key
                cipher_rsa = PKCS1_OAEP.new(key)
                session_key = cipher_rsa.decrypt(enc_session_key)

                # Decrypt the data with the AES session key
                cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
                cleartext = cipher_aes.decrypt_and_verify(ciphertext, tag)
            else:
                self.logger.debug("Decrypting with (default) PKCS1_v1_5")
                dsize = SHA.digest_size
                sentinel = Random.new().read(15 + dsize)
                cipher_rsa = PKCS1_v1_5.new(key)
                cleartext = cipher_rsa.decrypt(b, sentinel)
            return cleartext.decode("utf-8")
        except:
            if old == True:
                logging.exception("Failed to decrypt with our old key")
                return False
            self.logger.warn(
                "Current key could not decrypt, trying previous key.  This is normal during key rotation."
            )
            mem_key = self.getPrivateKey(".old")
            key = RSA.importKey(mem_key)
            return self.rsa_decrypt(message, key)

    def stringToBase64(s):
        return base64.b64encode(s.encode("utf-8"))

    def base64ToString(b):
        return base64.b64decode(b).decode("utf-8")

    def getPrivateKey(self, ext=""):
        path = "%s/SecretsMaster%s" % (self.args["key"], ext)
        return self.getKey(path)

    def getPublicKey(self, ext=""):
        path = "%s/SecretsMaster.pub%s" % (self.args["key"], ext)
        return self.getKey(path)

    def getKey(self, key_path):
        """
        Fetches a file from S3 and caches it so we do not keep getting it
        """
        cache_key_path = "%s/%s" % (self.args["bucket"], key_path)
        if cache_key_path in self.cache_keys:
            self.logger.debug(
                "Key: '%s' already fetched using cache" % (cache_key_path)
            )
            return self.cache_keys[cache_key_path]
        s3 = self.session.resource("s3")
        try:
            response = s3.Object(self.args["bucket"], key_path).get()
            self.cache_keys[cache_key_path] = response["Body"].read()
            return self.cache_keys[cache_key_path]
        except s3.meta.client.exceptions.NoSuchKey as e:
            # Invalid Path
            self.logger.warn(
                "Path: '%s/%s' doesn't exists." % (self.args["bucket"], key_path)
            )
            exit(2)
        except s3.meta.client.exceptions.NoSuchBucket as e:
            # Missing Bucket
            self.logger.warn("Bucket: '%s' doesn't exists." % (self.args["bucket"]))
            exit(2)
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "404":
                print(
                    "The object %s in %s does not exist." % (path, self.args["bucket"])
                )
                exit(2)
            else:
                raise

    def generateKeyPair(self):
        pri_key_path = "%s/SecretsMaster" % (self.args["key"])
        pub_key_path = "%s/SecretsMaster.pub" % (self.args["key"])
        # Lets make sure a key doesn't already exists
        if self.keyExists(pri_key_path):
            self.logger.error("Key already exists: '%s'!" % (pri_key_path))
            exit(3)

        key = RSA.generate(self.key_length)
        private_key = key.export_key()
        self.secureUpload(private_key, self.args["bucket"], pri_key_path)
        # Update local key cache
        self.cache_keys["%s/%s" % (self.args["bucket"], pri_key_path)] = private_key

        # Now Public Key
        public_key = key.publickey().export_key()
        self.secureUpload(public_key, self.args["bucket"], pub_key_path)
        # Update local key cache
        self.cache_keys["%s/%s" % (self.args["bucket"], pub_key_path)] = public_key
        self.logger.debug("Public Key: %s" % (public_key))
        self.serializeSettings()

    def rekey(self):
        """
        Rotate key and decrypt data with old key and encrypt with
        new key
        """
        pri_key_path = "%s/SecretsMaster" % (self.args["key"])
        pub_key_path = "%s/SecretsMaster.pub" % (self.args["key"])
        pri_key_path_old = "%s/SecretsMaster.old" % (self.args["key"])
        pub_key_path_old = "%s/SecretsMaster.pub.old" % (self.args["key"])
        pri_key_path_archive = "%s/SecretsMaster.old.%s" % (
            self.args["key"],
            time.strftime("%Y%m%d-%H%M%S"),
        )
        pub_key_path_archive = "%s/SecretsMaster.pub.old.%s" % (
            self.args["key"],
            time.strftime("%Y%m%d-%H%M%S"),
        )

        # Archive Old Key
        current_priv_key = self.getPrivateKey()
        current_pub_key = self.getPublicKey()
        # this is the rotate, will overwrite any other files at these locations
        self.secureUpload(current_priv_key, self.args["bucket"], pri_key_path_old)
        self.secureUpload(current_pub_key, self.args["bucket"], pub_key_path_old)
        # Lets also archive with timestamp
        self.secureUpload(current_priv_key, self.args["bucket"], pri_key_path_archive)
        self.secureUpload(current_pub_key, self.args["bucket"], pub_key_path_archive)

        # Make New Key pairs
        self.generateKeyPair()

        env_secret = self.getSecretPath(self.args["key"])
        cleartext_secrets = self.decryptSecretFile(env_secret)
        self.encryptSecretFile(cleartext_secrets, env_secret)

        return "Key's and secrets have been rotated for '%s'" % (self.args["key"])

    def isBase64(self, message):
        try:
            b = base64.b64decode(message.encode("utf-8"))
            return base64.b64encode(b) == message.encode("utf-8")
        except:
            pass
        return False

    def __del__(self):
        if "dry" not in self.args:
            pass
            # self.serializeSettings()
