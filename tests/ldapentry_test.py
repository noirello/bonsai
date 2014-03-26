import unittest

from pyldap import LDAPClient
from pyldap import LDAPEntry
import pyldap.errors

class LDAPEntryTest(unittest.TestCase):
    def setUp(self):
        self.client = LDAPClient()
        self.client.set_credentials("SIMPLE", ("cn=admin,dc=local", "p@ssword"))
        self.conn = self.client.connect()
        self.entry = LDAPEntry("cn=test,dc=local")
        self.entry['objectclass'] = ['top', 'inetOrgPerson', 'person',
                                     'organizationalPerson']
        self.entry['sn'] = "Test"

    def tearDown(self):
        self.conn.close()
        del self.entry

    def test_operations(self):
        try:
            self.conn.add(self.entry)
        except:
            self.fail("Add failed")
        self.entry.rename("cn=test2,dc=local")
        self.assertEqual(str(self.entry.dn), "cn=test2,dc=local")
        obj = self.conn.search("cn=test,dc=local", 0)
        self.assertEqual(obj, [])
        self.entry['sn'] = "Test_modify"
        try:
            self.entry.modify()
        except:
            self.fail("Modify failed.")
        obj = self.conn.search("cn=test2,dc=local", 0)[0]
        self.assertEqual(self.entry['sn'], obj['sn'])
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
        
    def test_get(self):
        self.assertEqual(self.entry.get("Noneelem"), None)
        self.assertEqual(self.entry['sn'], self.entry.get('sN'))
        
    def test_pop(self):
        self.entry['test'] = "test"
        self.assertEqual(self.entry.pop("test"), ["test"])
        self.assertEqual(self.entry.pop("test", None), None)
        
    def test_popitem(self):
        item = self.entry.popitem()
        self.assertEqual(len(item), 2)
        self.assertNotIn(item[0], self.entry)
        self.entry[item[0]] = item[1]
        
    def test_clear(self):
        entry = self.entry
        entry.clear()
        self.assertDictEqual(entry, {})
        self.assertEqual(entry.dn, self.entry.dn)
        
    def test_special_char(self):
        conn = self.client.connect()
        entry = LDAPEntry("cn=test\, *\+withspec,dc=local")
        entry['objectclass'] = ['top', 'inetOrgPerson']
        entry['sn'] = "Test,*special"
        conn.add(entry)
        result = conn.search("dc=local", 1)
        entry.delete()
        self.assertIn(entry.dn, [res.dn for res in result])

if __name__ == '__main__':
    unittest.main()
