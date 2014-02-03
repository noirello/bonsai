import unittest

from pyLDAP import LDAPClient
from pyLDAP import LDAPEntry
import pyLDAP.errors

class LDAPConnectionTest(unittest.TestCase):
    def setUp(self):
        self.url = "ldap://192.168.1.83/dc=local?cn?sub"
        client = LDAPClient(self.url)
        client.set_credentials("SIMPLE", {"binddn" : "cn=admin,dc=local",
                                          "password" : "p@ssword"})
        self.conn = client.connect()

    def tearDown(self):
        self.conn.close()
        del self.conn

    def test_bind_digest(self):
        client = LDAPClient(self.url)
        client.set_credentials("DIGEST-MD5", {"authcid" : "root",
                           "password" : "p@ssword"})
        try:
            conn = client.connect()
        except (pyLDAP.errors.ConnectionError,
            pyLDAP.errors.AuthenticationError):
            self.fail()
        conn.close()

    def test_search(self):
        obj = self.conn.search("dc=local", 2)
        self.assertIsNotNone(obj)
        self.assertEqual(obj, self.conn.search())
        
    def test_search_attr(self):
        obj = self.conn.search("dc=local", 2, "(objectclass=*)", ['cn'])[0]
        self.assertIsNotNone(obj)
        if 'cn' not in obj.keys():
            self.fail()

    """def test_rootdse(self):
        self.assertEqual(self.conn.get_rootDSE()['supportedLDAPVersion'],
                                ["3"])"""

    def test_whoami(self):
        obj = self.conn.whoami()
        self.assertEqual(obj, "dn:cn=admin,dc=local")

if __name__ == '__main__':
    unittest.main()
