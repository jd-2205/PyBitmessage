"""
Tests for openclpow module
"""
import hashlib
import unittest
from binascii import hexlify
from struct import pack, unpack

from pybitmessage import openclpow

from .samples import sample_pow_target, sample_pow_initial_hash


class TestOpenClPow(unittest.TestCase):
    """
    Main opencl test case
    """

    @classmethod
    def setUpClass(cls):
        openclpow.initCL()

    @unittest.skipUnless(openclpow.enabledGpus, "No GPUs found / enabled")
    def test_openclpow(self):
        """Check the working of openclpow module"""
        nonce = openclpow.do_opencl_pow(
            hexlify(sample_pow_initial_hash), sample_pow_target)
        trial_value, = unpack(
            '>Q', hashlib.sha512(hashlib.sha512(
                pack('>Q', nonce) + sample_pow_initial_hash).digest()
            ).digest()[0:8])
        self.assertLess((nonce - trial_value), sample_pow_target)
