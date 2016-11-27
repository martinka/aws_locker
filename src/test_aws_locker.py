"""
unit tests for aws_locker

Copyright (c) 2016 Michael E. Martinka

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit
persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""
import unittest
import tempfile
import os
import aws_locker


class TestAWSLocker(unittest.TestCase):

    def setUp(self):
        # create the files to use in the tests
        self.in_file = tempfile.NamedTemporaryFile(prefix='aws_locker_in', delete=False)
        self.out_file = tempfile.NamedTemporaryFile(prefix='aws_locker_out', delete=False)

    def tearDown(self):
        # remove the temporary files
        self.in_file.close()
        if os.path.exists(self.in_file.name):
            os.unlink(self.in_file.name)
        self.out_file.close()
        if os.path.exists(self.out_file.name):
            os.unlink(self.out_file.name)

    def test_encryptfile(self):
        self.in_file.write('SOME DATA TO ENCRYPT')
        self.in_file.flush()
        aws_locker.encrypt_file('a passphrase', self.in_file.name, self.out_file.name)
        # verify input file is removed
        self.assertFalse(os.path.exists(self.in_file.name))
        # verify that the output file has data in it but not the plan text
        enc_data = self.out_file.read()
        self.assertIsNotNone(enc_data)
        self.assertGreater(len(enc_data), 0)
        self.assertFalse('ENCRYPT' in enc_data)
