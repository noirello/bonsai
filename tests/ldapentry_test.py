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
            
    def get_mail(self):
        return self.entry['mail']
    
    def set_same(self):
        self.entry['GivenName'].extend(['teSt', "test3"])
    
    def test_update(self):
        self.entry.update({"GivenName": "test2", "mail" : "test@mail"})
        self.entry.update([("sn", "test")])
        self.assertEqual(self.entry['mail'], ['test@mail'])
        self.assertEqual(self.entry['givenname'], ['test2'])
        self.assertEqual(self.entry['sn'][0], 'test')
            
    def test_ci(self):
        self.entry['givenName'] = "test"
        self.entry['mail'] = "test@mail"
        self.assertEqual(self.entry['GiVenName'], self.entry['givenname'])
        del self.entry['mAil']
        self.assertRaises(KeyError, self.get_mail)
        
    def test_append(self):
        self.entry['givenName'] =  "test"
        self.entry['givenname'].append("test2")
        self.assertEqual(self.entry['givenname'], ["test", "test2"])
        self.assertRaises(TypeError, self.set_same)
        
if __name__ == '__main__':
    unittest.main()
            