"""A test case for partial run class definition"""

import os
import sys
import time
import unittest

from pybitmessage import pathmagic

from .common import cleanup


class TestPartialRun(unittest.TestCase):
    """
    A base class for test cases running some parts of the app,
    e.g. separate threads or packages.
    """

    @classmethod
    def setUpClass(cls):
        # pylint: disable=import-outside-toplevel,unused-import
        if sys.hexversion < 0x3000000:
            cls.dirs = (os.path.abspath(os.curdir), pathmagic.setup())

        import bmconfigparser
        import state

        from debug import logger  # noqa:F401 pylint: disable=unused-variable
        if sys.hexversion >= 0x3000000:
            cls.dirs = None
            # pylint: disable=no-name-in-module,relative-import
            from mock import network as network_mock
            import network
            network.stats = network_mock.stats

        state.shutdown = 0
        cls.state = state
        bmconfigparser.config = cls.config = bmconfigparser.BMConfigParser()
        cls.config.read()

    @classmethod
    def tearDownClass(cls):
        cls.state.shutdown = 1
        cleanup()
        if cls.dirs:  # deactivate pathmagic
            os.chdir(cls.dirs[0])
            sys.path.remove(cls.dirs[1])
        time.sleep(5)
        cls.state.shutdown = 0
