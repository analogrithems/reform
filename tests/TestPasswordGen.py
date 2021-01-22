import unittest
import sys
import logging

from reform import tasks
from botocore.client import ClientError
from io import StringIO
from invoke import MockContext, Result


class TestPasswordGen(unittest.TestCase):
    def test_pass_gen(self):
        """
    Test that our Random password generator works and creates a strong
    random password of 12 characters in length
    """
        c = MockContext()
        capturedOutput = StringIO()
        sys.stdout = capturedOutput
        tasks.pass_gen(c, 12)
        sys.stdout = sys.__stdout__
        password = capturedOutput.getvalue()
        logging.getLogger("TestTasks").debug("Random Password: %s" % (password))
        # Length should be 12 + 1 (newline)
        self.assertEqual(13, len(password))
