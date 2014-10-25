import configparser
import unittest

from pyldap import LDAPClient
from pyldap import LDAPEntry
import pyldap.errors

class LDAPEntryTest(unittest.TestCase):
    """ Testing LDAPEntry object. """
    def setUp(self):
        """ Set LDAP connection and test entry. """
        cfg = configparser.ConfigParser()
        cfg.read('test.ini')
        url = "ldap://%s:%s" % (cfg["SERVER"]["host"],
                                cfg["SERVER"]["port"])
        self.client = LDAPClient(url)
        self.client.set_credentials("SIMPLE", (cfg["SIMPLEAUTH"]["user"],
                                               cfg["SIMPLEAUTH"]["password"]))
        self.conn = self.client.connect()
        self.basedn = cfg["SERVER"]["basedn"]
        self.entry = LDAPEntry("cn=test,%s" % self.basedn)
        self.entry['objectclass'] = ['top', 'inetOrgPerson', 'person',
                                     'organizationalPerson']
        self.entry['sn'] = "Test"

    def tearDown(self):
        """ Close connection. """
        self.conn.close()
        del self.entry

    def test_operations(self):
        """ Test LDAPEntry's add, modify, rename and delete operations. """
        try:
            self.conn.add(self.entry)
        except pyldap.errors.AlreadyExists:
            self.entry.delete()
            self.conn.add(self.entry)
        except:
            self.fail("Add failed.")
        self.entry.rename("cn=test2,%s" % self.basedn)
        self.assertEqual(str(self.entry.dn), "cn=test2,%s" % self.basedn)
        obj = self.conn.search("cn=test,%s" % self.basedn, 0)
        self.assertEqual(obj, [])
        self.entry['sn'] = "Test_modify"
        try:
            self.entry.modify()
        except:
            self.fail("Modify failed.")
        obj = self.conn.search("cn=test2,%s" % self.basedn, 0)[0]
        self.assertEqual(self.entry['sn'], obj['sn'])
        try:
            self.entry.delete()
        except:
            self.fail("Delete failed.")

    def test_update(self):
        """ Test updating LDAPEntry object. """
        self.entry.update({"GivenName": "test2", "mail" : "test@mail"})
        self.entry.update([("sn", "test")])
        self.assertEqual(self.entry['mail'], ['test@mail'])
        self.assertEqual(self.entry['givenname'], ['test2'])
        self.assertEqual(self.entry['sn'][0], 'test')

    def test_ci(self):
        """ Test case-insensitivity of LDAPEntry object. """
        self.entry['givenName'] = "test"
        self.entry['mail'] = "test@mail"
        self.assertEqual(self.entry['GiVenName'], self.entry['givenname'])
        del self.entry['mAil']
        self.assertRaises(KeyError, lambda: self.entry['mail'])

    def test_append(self):
        """ Test LDAPEntry's append method. """
        self.entry['givenName'] = "test"
        self.entry['givenname'].append("test2")
        self.assertEqual(self.entry['givenname'], ["test", "test2"])
        self.assertRaises(TypeError,
                          lambda: self.entry['GivenName']
                          .extend(['teSt', "test3"]))

    def test_get(self):
        """ Test LDAPEntry's get method. """
        self.assertEqual(self.entry.get("Noneelem"), None)
        self.assertEqual(self.entry['sn'], self.entry.get('sN'))

    def test_pop(self):
        """ Test LDAPEntry's pop method. """
        self.entry['test'] = "test"
        self.assertEqual(self.entry.pop("test"), ["test"])
        self.assertEqual(self.entry.pop("test", None), None)

    def test_popitem(self):
        """ Test LDAPEntry's popitem method. """
        item = self.entry.popitem()
        self.assertEqual(len(item), 2)
        self.assertNotIn(item[0], self.entry)
        self.entry[item[0]] = item[1]

    def test_clear(self):
        """ Test LDAPEntry's clear method. """
        entry = self.entry
        entry.clear()
        self.assertDictEqual(entry, {})
        self.assertEqual(entry.dn, self.entry.dn)

    def test_special_char(self):
        """ Test adding entry with special character in its DN. """
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
