import unittest
import uuid
import boto3
import botocore
import sys
import logging
import hashlib

from reform import tasks, SecretsManager, ReformSettings
from botocore.client import ClientError
from io import StringIO
from invoke import MockContext, Result

region = "us-west-1"
bucket_name = "reform-%s" % (uuid.uuid4())
quadrant = "unit_test"


class TestSecretManager(unittest.TestCase):
    @classmethod
    def setUpClass(self):
        c = MockContext()
        s3 = boto3.resource("s3", region)
        self.settings = ReformSettings.ReformSettings()

        # First make sure bucket does not exists.  As it's a name is reform-UUID()
        # it's not likely to exists yet
        found = s3.Bucket(bucket_name) in s3.buckets.all()
        self.assertFalse(self, found)
        # print("Create Bucket: %s"%(bucket_name))
        tasks.mkS3Bucket(c, bucket_name, region)
        found = s3.Bucket(bucket_name) in s3.buckets.all()
        self.assertTrue(self, found)
        result = tasks.create(
            c, self.settings.GetReformRoot(), quadrant, bucket_name, region
        )

    @classmethod
    def tearDownClass(self):
        # Remove Bucket as last step and verify it's gone
        self.nukeBucket(self, bucket_name)
        s3 = boto3.resource("s3", region)
        found = s3.Bucket(bucket_name) in s3.buckets.all()
        self.assertFalse(self, found)

    def createBucket(self, bucket_name):
        c = MockContext()
        s3 = boto3.resource("s3", region)

        # First make sure bucket does not exists.  As it's a name is reform-UUID()
        # it's not likely to exists yet
        found = s3.Bucket(bucket_name) in s3.buckets.all()
        self.assertFalse(found)
        # print("Create Bucket: %s"%(bucket_name))
        tasks.mkS3Bucket(c, bucket_name, region)
        found = s3.Bucket(bucket_name) in s3.buckets.all()
        self.assertTrue(found)

    def nukeBucket(self, bucket_name):
        """
    Empties and deletes the bucket
    :param bucket_name:
    :param region:
    :return:
    """
        # print("Delete Bucket: %s"%(bucket_name))
        logging.getLogger("TestSecretsManager").debug(
            "trying to delete the bucket {0}".format(bucket_name)
        )
        s3_client = boto3.client("s3", region_name=region)
        s3 = boto3.resource("s3", region_name=region)
        try:
            bucket = s3.Bucket(bucket_name).load()
        except ClientError:
            logging.getLogger("TestSecretsManager").debug(
                "bucket {0} does not exist".format(bucket_name)
            )
            return
        # Check if versioning is enabled
        response = s3_client.get_bucket_versioning(Bucket=bucket_name)
        status = response.get("Status", "")
        if status == "Enabled":
            response = s3_client.put_bucket_versioning(
                Bucket=bucket_name, VersioningConfiguration={"Status": "Suspended"}
            )
        paginator = s3_client.get_paginator("list_object_versions")
        page_iterator = paginator.paginate(Bucket=bucket_name)
        for page in page_iterator:
            logging.getLogger("TestSecretsManager").debug(page)
            if "DeleteMarkers" in page:
                delete_markers = page["DeleteMarkers"]
                if delete_markers is not None:
                    for delete_marker in delete_markers:
                        key = delete_marker["Key"]
                        versionId = delete_marker["VersionId"]
                        s3_client.delete_object(
                            Bucket=bucket_name, Key=key, VersionId=versionId
                        )
            if "Versions" in page and page["Versions"] is not None:
                versions = page["Versions"]
                for version in versions:
                    logging.getLogger("TestSecretsManager").debug(version)
                    key = version["Key"]
                    versionId = version["VersionId"]
                    s3_client.delete_object(
                        Bucket=bucket_name, Key=key, VersionId=versionId
                    )
        object_paginator = s3_client.get_paginator("list_objects_v2")
        page_iterator = object_paginator.paginate(Bucket=bucket_name)
        for page in page_iterator:
            if "Contents" in page:
                for content in page["Contents"]:
                    key = content["Key"]
                    s3_client.delete_object(Bucket=bucket_name, Key=content["Key"])
        s3_client.delete_bucket(Bucket=bucket_name)
        logging.getLogger("TestSecretsManager").debug(
            "Successfully deleted the bucket {0}".format(bucket_name)
        )

    def test_key_exists(self):
        """
    Test if a given key already exists
    """
        c = MockContext()
        s3 = boto3.resource("s3", region)

        tasks.key_gen(c, bucket_name, quadrant, region)

        result = tasks.key_exists(c, bucket_name, quadrant)
        self.assertTrue(result)

    def test_key_gen(self):
        """
    Test that we can generate our keys in our secure bucket
    """
        c = MockContext()
        s3 = boto3.resource("s3", region)

        tasks.key_gen(c, bucket_name, quadrant, region)

        # Verify the public and private key exists now
        pri_path = "%s/SecretsMaster" % (quadrant)
        found = False
        try:
            _obj = s3.Object(bucket_name, pri_path).load()
            found = True
        except botocore.exceptions.ClientError as e:
            found = False
        self.assertTrue(found)

        # Verify Public key exists
        # TODO check size
        pub_path = "%s/SecretsMaster.pub" % (quadrant)
        found = False
        try:
            _obj = s3.Object(bucket_name, pub_path).load()
            found = True
        except botocore.exceptions.ClientError as e:
            found = False
        self.assertTrue(found)

    def test_cryptic(self):
        """
    Test that we can encrypt and decrypt data with our RSA PKI
    """
        c = MockContext()
        tasks.key_gen(c, bucket_name, quadrant, region)

        # Test encrypt and decrypt
        plain_text = "hello world 1234567890!@#$%^&*()"
        capturedOutput = StringIO()
        sys.stdout = capturedOutput
        tasks.cryptic(c, quadrant, plain_text)
        cypher_text = capturedOutput.getvalue()
        sys.stdout = sys.__stdout__

        capturedOutput = StringIO()
        sys.stdout = capturedOutput
        tasks.cryptic(c, quadrant, False, cypher_text)
        decrypt_text = capturedOutput.getvalue().rstrip()
        sys.stdout = sys.__stdout__

        self.assertEqual(plain_text, decrypt_text)

    def test_cryptic_aes(self):
        """
    Test that we can encrypt and decrypt data with our RSA_AES PKI that allows for larger message sizes
    """
        c = MockContext()
        tasks.key_gen(c, bucket_name, quadrant, region)

        # Test encrypt and decrypt
        plain_text = (
            "Very long string to encrypt.0000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
        )
        capturedOutput = StringIO()
        sys.stdout = capturedOutput
        tasks.cryptic(c, quadrant, plain_text, False, "RSA_AES")
        cypher_text = capturedOutput.getvalue()
        sys.stdout = sys.__stdout__

        capturedOutput = StringIO()
        sys.stdout = capturedOutput
        tasks.cryptic(c, quadrant, False, cypher_text, "RSA_AES")
        decrypt_text = capturedOutput.getvalue().rstrip()
        sys.stdout = sys.__stdout__

        self.assertEqual(plain_text, decrypt_text)

    def test_rotate_key(self):
        """
    Test that we can rotate the keys in our bucket
    """
        c = MockContext()
        tasks.key_gen(c, bucket_name, quadrant, region)
        s3 = boto3.resource("s3", region)

        # Test if old key exists before
        pri_path = "%s/SecretsMaster.old" % (quadrant)
        found = False
        try:
            _obj = s3.Object(bucket_name, pri_path).load()
            found = True
        except botocore.exceptions.ClientError as e:
            found = False
        self.assertFalse(found)

        # Verify old Public key exists
        # TODO check size
        pub_path = "%s/SecretsMaster.pub.old" % (quadrant)
        found = False
        try:
            _obj = s3.Object(bucket_name, pub_path).load()
            found = True
        except botocore.exceptions.ClientError as e:
            found = False
        self.assertFalse(found)

        # Make secret before rotate
        sm = SecretsManager.SecretsManager({"key": quadrant})
        secret_file = sm.getSecretPath(quadrant)

        _secret_dict = {"test1": "hello world"}
        import copy

        copy_secret_dict = copy.deepcopy(_secret_dict)
        sm.encryptSecretFile(_secret_dict, secret_file)

        _secret_file_decrypt = sm.decryptSecretFile(secret_file)
        logging.getLogger("TestSecretsManager").debug(
            "Old: %s, New: %s" % (copy_secret_dict, _secret_file_decrypt)
        )

        self.assertEqual(copy_secret_dict, _secret_file_decrypt)

        # Lets get a file sum
        pre_checksum = hashlib.md5(open(secret_file, "rb").read()).hexdigest()

        # Rotate the keys now
        tasks.rotate_key(c, quadrant)

        # Test if old key exists after
        pri_path = "%s/SecretsMaster.old" % (quadrant)
        found = False
        try:
            _obj = s3.Object(bucket_name, pri_path).load()
            found = True
        except botocore.exceptions.ClientError as e:
            found = False
        self.assertTrue(found)

        # Verify old Public key exists
        # TODO check size
        pub_path = "%s/SecretsMaster.pub.old" % (quadrant)
        found = False
        try:
            _obj = s3.Object(bucket_name, pub_path).load()
            found = True
        except botocore.exceptions.ClientError as e:
            found = False
        self.assertTrue(found)

        # Test if crypted strings have been updated
        post_checksum = hashlib.md5(open(secret_file, "rb").read()).hexdigest()
        self.assertNotEqual(pre_checksum, post_checksum)
