import unittest

from pyldap import LDAPClient

class LDAPClientTest(unittest.TestCase):
    def setUp(self):
        self.url = "ldap://localhost/dc=local?cn?sub"
        self.client = LDAPClient(self.url)

    def test_connect(self):
        self.assertIsNotNone(self.client.connect())

    def test_rootdse(self):
        self.assertEqual(self.client.get_rootDSE()['supportedLDAPVersion'],
                                ["3"])

if __name__ == '__main__':
    unittest.main()
