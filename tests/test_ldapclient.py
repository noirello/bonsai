import configparser
import os.path
import unittest

import bonsai
from bonsai import LDAPClient

class LDAPClientTest(unittest.TestCase):
    """ Testing LDAPClient object. """
    @classmethod
    def setUpClass(cls):
        curdir = os.path.abspath(os.path.dirname(__file__))
        """ Set host url and connection. """
        cfg = configparser.ConfigParser()
        cfg.read(os.path.join(curdir, 'test.ini'))
        cls.url = "ldap://%s:%s" % (cfg["SERVER"]["hostip"],
                                     cfg["SERVER"]["port"])
        cls.client = LDAPClient(cls.url)

    def test_connect(self):
        """ Test connect method. """
        self.assertIsNotNone(self.client.connect())

    def test_rootdse(self):
        """ Test receiving root DSE. """
        root_dse = self.client.get_rootDSE()
        self.assertEqual(root_dse['supportedLDAPVersion'][0], 3)

    def test_raw_attributes(self):
        """ Test setting raw attributes to keep in bytearray format. """
        def value_err():
            self.client.set_raw_attributes([5])
        self.assertRaises(ValueError, value_err)
        self.client.set_raw_attributes(["namingContexts"])
        if type(self.client.get_rootDSE()["namingContexts"][0]) != bytes:
            self.fail("The type of the value is not bytes.")

    def test_set_credentials(self):
        """
        Test setcredentials method, mechanism and credentials properties.
        """
        self.assertRaises(ValueError,
                          lambda: self.client.set_credentials(2323, (None,)))
        self.assertRaises(ValueError,
                          lambda: self.client.set_credentials("Simple",
                                                              "pass"))
        self.assertRaises(ValueError, lambda: self.client
                          .set_credentials("Simple",("Name", 2, None, None)))
        self.assertRaises(ValueError, lambda: self.client
                         .set_credentials("EXTERNAL", (None, None)))
        self.assertRaises(ValueError, lambda: self.client
                         .set_credentials("SIMPLE", (None, None, None)))
        self.assertRaises(ValueError, lambda: self.client
                         .set_credentials("DIGEST-MD5", (None, None)))
        self.client.set_credentials("SIMPLE", ("cn=admin", "password"))
        self.assertEqual(self.client.mechanism, "SIMPLE")
        self.assertEqual(self.client.credentials, ("cn=admin", "password"))
        self.client.set_credentials("EXTERNAL", ("authzid",))
        self.assertEqual(self.client.credentials, (None, None, None, "authzid"))

    def test_vendor_info(self):
        """ Test vendor information. """
        info = bonsai.get_vendor_info()
        if len(info) != 2:
            self.fail()
        self.assertIsInstance(info[0], str)
        self.assertIsInstance(info[1], int)

    def test_tls_impl_name(self):
        """ Test TLS implementation name. """
        tls_impl = bonsai.get_tls_impl_name()
        self.assertIn(tls_impl, ("GnuTLS", "MozNSS", "OpenSSL", "SChannel"))

if __name__ == '__main__':
    unittest.main()
