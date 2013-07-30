import unittest

from pyLDAP import LDAPClient
from pyLDAP import LDAPEntry
import pyLDAP.errors

class LDAPClientTest(unittest.TestCase):
    def setUp(self):
        self.url = "ldap://192.168.1.83"
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
        except (pyLDAP.errors.ConnectionError, pyLDAP.errors.AuthenticationError):
            self.fail()
        client.close()
        
    def test_search(self):
        o = self.client.search("dc=local", 1)
        self.assertIsNotNone(o)
        
    def test_rootdse(self):
        self.assertEqual(self.client.get_rootDSE()['supportedLDAPVersion'], ["3"])
 
    def test_getentry(self):
        o = self.client.get_entry("cn=admin,dc=local")
        self.assertIsInstance(o, LDAPEntry)
 
if __name__ == '__main__':
    unittest.main()   
    