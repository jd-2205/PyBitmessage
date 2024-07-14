"""Tests for RandomTrackingDict Class"""

import time
import unittest

from pybitmessage import highlevelcrypto
from pybitmessage.randomtrackingdict import RandomTrackingDict


class TestRandomTrackingDict(unittest.TestCase):
    """The test case for RandomTrackingDict"""
    _exp_time = 15

    def test_check_randomtrackingdict(self):
        """Check the logic (performance) of RandomTrackingDict class"""
        a = []
        k = RandomTrackingDict()

        a.append(time.time())
        for i in range(50000):
            k[highlevelcrypto.randomBytes(32)] = True
        a.append(time.time())

        while k:
            retval = k.randomKeys(1000)
            if not retval:
                self.fail('Error getting random keys')

            try:
                k.randomKeys(100)
                self.fail('bad')
            except KeyError:
                pass
            for i in retval:
                del k[i]
        a.append(time.time())

        for x in range(len(a) - 1):
            self.assertLess(a[x + 1] - a[x], self._exp_time)
