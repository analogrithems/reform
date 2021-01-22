import unittest
import uuid
import boto3
import sys
import logging
import os
import json

from reform import tasks, ReformSettings
from botocore.client import ClientError
from io import StringIO
from invoke import MockContext, Result

attribute = "tester.domain"
value = "reform-%s" % (uuid.uuid4())
region = "us-west-1"
bucket_name = "reform-%s" % (uuid.uuid4())
quadrant = "unit_test_%s" % (uuid.uuid4())


class TestConfigManager(unittest.TestCase):
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
        """
    Lets Remove the config file we create so it works next time we test
    """

        c = MockContext()
        result = tasks.config_set(c, quadrant, attribute, value)
        last_result = tasks.config_delete_file(c, quadrant)
        # self.assertTrue(last_result)

    def test_upsert_config(self):
        """
    This test adding an attribute to our config
    """
        c = MockContext()
        result = tasks.config_set(c, quadrant, attribute, value)
        self.assertTrue(result)

    def test_read_config(self):
        """
    This test reading an attribute from our config
    """
        c = MockContext()
        result = tasks.config_set(c, quadrant, attribute, value)
        result_last = tasks.config_get(c, quadrant, attribute)
        self.assertEqual(result_last, value)

    def test_delete_config(self):
        """
    This test removing an attribute
    """
        c = MockContext()
        result = tasks.config_delete(c, quadrant, attribute)
        self.assertTrue(result)
