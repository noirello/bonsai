import configparser
import os.path
import unittest

from bonsai import LDAPClient
from bonsai import LDAPEntry
import bonsai.errors

class LDAPEntryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        curdir = os.path.abspath(os.path.dirname(__file__))
        """ Set LDAP client, get config parameters. """
        cfg = configparser.ConfigParser()
        cfg.read(os.path.join(curdir, 'test.ini'))
        url = "ldap://%s:%s" % (cfg["SERVER"]["hostip"],
                                cfg["SERVER"]["port"])
        cls.client = LDAPClient(url)
        cls.creds = ("SIMPLE", (cfg["SIMPLEAUTH"]["user"],
                                 cfg["SIMPLEAUTH"]["password"]))
        cls.basedn = cfg["SERVER"]["basedn"]

    def test_set_get(self):
        """ Test LDAPEntry's SetItem, GetItem and get methods. """  
        entry = LDAPEntry("cn=test");
        entry['sn'] = 'Test'
        self.assertDictEqual(entry, {'sn' : ['Test']},
                             "LDAPEntry set is failed.")
        entry['givenname'] = 'Test'
        self.assertEqual(entry.get("None"), None,
                         "LDAPEntry get is failed.")
        self.assertListEqual(entry.get("GivenName"), entry['givenNAME'],
                         "LDAPEntry get is failed.")
        del entry['sn']
        self.assertRaises(KeyError, lambda: entry['sn'])

    def test_append_extend(self):
        """ Test append and extend methods of LDAPEntry's attribute. """
        entry = LDAPEntry("cn=test");
        entry['givenName'] = "test"
        entry['givenname'].append("test2")
        self.assertListEqual(entry['givenname'], ["test", "test2"])
        self.assertEqual(entry['givenname'][0], "test")
        self.assertRaises(ValueError,
                          lambda: entry['GivenName']
                          .extend(['teSt', "test3"]))

    def test_pop(self):
        """ Test LDAPEntry's pop method. """
        entry = LDAPEntry("cn=test")
        entry['test'] = "test"
        self.assertEqual(entry.pop("test"), ["test"])
        self.assertEqual(entry.pop("test", None), None)

    def test_popitem(self):
        """ Test LDAPEntry's popitem method. """
        entry = LDAPEntry("cn=test")
        entry['test'] = "test"
        entry['test2'] = 'test'
        item = entry.popitem()
        self.assertEqual(len(item), 2)
        self.assertNotIn(item[0], entry)
        entry[item[0]] = item[1]
        self.assertEqual(entry[item[0]], item[1])

    def test_popitem_empty(self):
        """ Test LDAPEntry's popitem raises KeyError if it is empty. """
        entry = LDAPEntry("cn=test")
        self.assertRaises(KeyError, entry.popitem)

    def test_clear(self):
        """ Test LDAPEntry's clear method. """
        entry = LDAPEntry("cn=test")
        entry['sn'] = ['test1', 'test2']
        entry['gn'] = ['test3']
        entry.clear()
        self.assertDictEqual(entry, {})
        self.assertEqual(entry.dn, "cn=test")

    def test_update(self):
        """ Test updating LDAPEntry object. """
        entry = LDAPEntry("cn=test")
        entry.update({"GivenName": "test2", "mail" : "test@mail"})
        entry.update([("sn", "test")])
        entry.update(uidnumber=1, gidnumber=1)
        self.assertEqual(entry['mail'], ['test@mail'])
        self.assertEqual(entry['givenname'], ['test2'])
        self.assertEqual(entry['sn'][0], 'test')
        self.assertEqual(entry['uidnumber'], [1])
        self.assertEqual(entry['gidnumber'], [1])

    def test_special_char(self):
        """ Test adding entry with special character in its DN. """
        self.client.set_credentials(*self.creds)
        conn = self.client.connect()
        entry = LDAPEntry("cn=test\, *\+withspec,%s" % self.basedn)
        entry['objectclass'] = ['top', 'inetOrgPerson']
        entry['sn'] = "Test,*special"
        conn.add(entry)
        result = conn.search(self.basedn, 1)
        entry.delete()
        conn.close()
        self.assertIn(entry.dn, [res.dn for res in result])

    def test_unicode(self):
        """ Test adding entry with special character in its DN. """
        self.client.set_credentials(*self.creds)
        conn = self.client.connect()
        dname = "cn=test_µčབྷñ,%s" % self.basedn
        entry = LDAPEntry(dname)
        entry['objectclass'] = ['top', 'inetOrgPerson']
        entry['sn'] = "unicode_µčབྷñ"
        conn.add(entry)
        result = conn.search(dname, 0)
        entry.delete()
        conn.close()
        self.assertIn(dname, [res.dn for res in result])

    def test_binary(self):
        """ Test adding binary data. """
        curdir = os.path.abspath(os.path.dirname(__file__))
        self.client.set_credentials(*self.creds)
        conn = self.client.connect()
        dname = "cn=binary,%s" % self.basedn
        entry = LDAPEntry(dname)
        entry['objectclass'] = ['top', 'inetOrgPerson']
        entry['sn'] = "binary_test"
        with open('%s/testenv/test.jpeg' % curdir, 'rb') as image:
            entry['jpegPhoto'] = image.read()
        conn.add(entry)
        result = conn.search(dname, 0)
        entry.delete()
        conn.close()
        self.assertIn("jpegPhoto", result[0].keys())
        self.assertEqual(result[0]['jpegphoto'][0], entry['jpegphoto'][0])

    def test_connection(self):
        """ Test set and get connection object form LDAPEntry. """
        entry = LDAPEntry("cn=test,%s" % self.basedn)
        conn = self.client.connect()
        entry.connection = conn
        self.assertEqual(entry.connection, conn)
        def invalid_assign():
             entry.connection = "string"
        self.assertRaises(TypeError, invalid_assign)

    def _add_for_renaming(self, conn, entry):
        entry['objectclass'] = ['top', 'inetOrgPerson', 'person',
                                'organizationalPerson']
        entry['sn'] = 'test'
        try:
            conn.add(entry)
        except bonsai.AlreadyExists:
            conn.delete(entry.dn)
            conn.add(entry)
        except:
            self.fail("Adding LDAPEntry to the server is failed.")

    def test_rename(self):
        """ Test LDAPEntry's rename LDAP operation. """
        entry = LDAPEntry("cn=test,%s" % self.basedn)
        self.client.set_credentials(*self.creds)
        with self.client.connect() as conn:
            self._add_for_renaming(conn, entry)
            entry.rename("cn=test2,%s" % self.basedn)
            self.assertEqual(str(entry.dn), "cn=test2,%s" % self.basedn)
            obj = conn.search("cn=test,%s" % self.basedn, 0)
            self.assertEqual(obj, [])
            obj = conn.search("cn=test2,%s" % self.basedn, 0)[0]
            self.assertEqual(entry.dn, obj.dn)
            entry.delete()

    def test_rename_error(self):
        """ Test LDAPEntry's rename error handling. """
        dname = bonsai.LDAPDN("cn=test,%s" % self.basedn)
        entry = LDAPEntry(dname)
        self.client.set_credentials(*self.creds)
        with self.client.connect() as conn:
            self._add_for_renaming(conn, entry)
            try:
                newdn = bonsai.LDAPDN("cn=test2,ou=invalid,%s" % self.basedn)
                entry.rename(newdn)
            except bonsai.LDAPError:
                self.assertEqual(entry.dn, dname)
            finally:
                conn.delete(dname)

    def test_sync_operations(self):
        """
        Test LDAPEntry's add, modify and delete synchronous operations.
        """
        entry = LDAPEntry("cn=test,%s" % self.basedn)
        self.client.set_credentials(*self.creds)
        with self.client.connect() as conn:
            entry['objectclass'] = ['top', 'inetOrgPerson', 'person',
                                    'organizationalPerson']
            self.assertRaises(bonsai.ObjectClassViolation,
                              lambda: conn.add(entry))
            entry['sn'] = 'test'
            try:
                conn.add(entry)
            except bonsai.AlreadyExists:
                conn.delete(entry.dn)
                conn.add(entry)
            except:
                self.fail("Adding LDAPEntry to the server is failed.")
            entry['sn'] = "Test_modify"
            try:
                entry.modify()
            except:
                self.fail("Modify failed.")
            obj = conn.search("cn=test,%s" % self.basedn, 0)[0]
            self.assertEqual(entry['sn'], obj['sn'])
            try:
                entry.delete()
            except:
                self.fail("Delete failed.")

if __name__ == '__main__':
    unittest.main()
