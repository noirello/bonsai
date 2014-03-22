import unittest

from pyldap import LDAPClient
from pyldap import LDAPEntry
import pyldap.errors

class LDAPConnectionTest(unittest.TestCase):
    def setUp(self):
        self.url = "ldap://localhost/dc=local?cn?sub"
        client = LDAPClient(self.url)
        client.set_credentials("SIMPLE", ("cn=admin,dc=local", "p@ssword"))
        self.conn = client.connect()

    def tearDown(self):
        self.conn.close()
        del self.conn

    def test_bind_digest(self):
        client = LDAPClient(self.url)
        client.set_credentials("DIGEST-MD5", ("root", "p@ssword", None))
        try:
            conn = client.connect()
        except (pyldap.errors.ConnectionError,
            pyldap.errors.AuthenticationError):
            self.fail()
        conn.close()

    def test_search(self):
        obj = self.conn.search("dc=local", 2)
        self.assertIsNotNone(obj)
        self.assertEqual(obj, self.conn.search())
        
    def test_search_attr(self):
        obj = self.conn.search("dc=local", 2, "(objectclass=person)", ['cn'])[0]
        self.assertIsNotNone(obj)
        if 'cn' not in obj.keys():
            self.fail()

    def test_whoami(self):
        obj = self.conn.whoami()
        self.assertEqual(obj, "dn:cn=admin,dc=local")

if __name__ == '__main__':
    unittest.main()
