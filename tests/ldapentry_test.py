import unittest

from pyLDAP import LDAPClient
from pyLDAP import LDAPEntry
import pyLDAP.errors

class LDAPEntryTest(unittest.TestCase):
    def setUp(self):
        self.client = LDAPClient("ldap://192.168.1.83")
        self.client.connect("cn=admin,dc=local", "p@ssword")
        self.entry = LDAPEntry("cn=test,dc=local", self.client)
        self.entry['objectclass'] = ['top', 'inetOrgPerson', 'person', 'organizationalPerson']
        self.entry['sn'] = "Test"
        
    def tearDown(self):
        self.client.close()
        del self.entry
        
    def test_operations(self):
        try:
            self.entry.add()
        except:
            self.fail("Add failed")
        self.entry.rename("cn=test2,dc=local")
        self.assertEqual(str(self.entry.dn), "cn=test2,dc=local")
        o = self.client.get_entry("cn=test,dc=local")
        self.assertIsNone(o)
        self.entry['sn'] = "Test_modify"
        try:
            self.entry.modify()
        except:
            self.fail("Modify failed.")
        o = self.client.get_entry("cn=test2,dc=local")
        self.assertEqual(self.entry['sn'], o['sn'])
        try:
            self.entry.delete()
        except:
            self.fail("Delete failed.")
            
    def test_ci(self):
        self.entry['givenName'] = "test"
        self.assertEqual(self.entry['GiVenName'], self.entry['givenname'])
        
if __name__ == '__main__':
    unittest.main()
            