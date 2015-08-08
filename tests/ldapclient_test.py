import configparser
import os.path
import unittest

from pyldap import LDAPClient

class LDAPClientTest(unittest.TestCase):
    """ Testing LDAPClient object. """
    def setUp(self):
        curdir = os.path.abspath(os.path.dirname(__file__))
        """ Set host url and connection. """
        cfg = configparser.ConfigParser()
        cfg.read(os.path.join(curdir, 'test.ini'))
        self.url = "ldap://%s:%s" % (cfg["SERVER"]["host"],
                                     cfg["SERVER"]["port"])
        self.client = LDAPClient(self.url)

    def test_connect(self):
        """ Test connect method. """
        self.assertIsNotNone(self.client.connect())

    def test_rootdse(self):
        """ Test receiving root DSE. """
        root_dse = self.client.get_rootDSE()
        self.assertEqual(root_dse['supportedLDAPVersion'][0], 3)

if __name__ == '__main__':
    unittest.main()
