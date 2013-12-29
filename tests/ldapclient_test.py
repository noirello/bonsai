import unittest

from pyLDAP import LDAPClient
from pyLDAP import LDAPEntry
import pyLDAP.errors

class LDAPClientTest(unittest.TestCase):
    def setUp(self):
        self.url = "ldap://192.168.1.83/dc=local?cn?sub"
        self.client = LDAPClient(self.url)
        self.client.connect("cn=admin,dc=local", "p@ssword")

    def tearDown(self):
        self.client.close()
        del self.client

    def test_bind_digest(self):
        client = LDAPClient(self.url)
        try:
            client.connect(mechanism="DIGEST-MD5",
                           username="root",
                           password="p@ssword")
        except (pyLDAP.errors.ConnectionError,
            pyLDAP.errors.AuthenticationError):
            self.fail()
        client.close()

    def test_search(self):
        obj = self.client.search("dc=local", 2)
        self.assertIsNotNone(obj)
        self.assertEqual(obj, self.client.search())

    def test_rootdse(self):
        self.assertEqual(self.client.get_rootDSE()['supportedLDAPVersion'],
                                ["3"])

    def test_getentry(self):
        obj = self.client.get_entry("cn=admin,dc=local")
        self.assertIsInstance(obj, LDAPEntry)

    def test_whoami(self):
        obj = self.client.whoami()
        self.assertEqual(obj, "dn:cn=admin,dc=local")

if __name__ == '__main__':
    unittest.main()
