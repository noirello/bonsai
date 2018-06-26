import configparser
import os
import unittest

from bonsai import LDAPClient
from bonsai import LDAPEntry
import bonsai.errors

try:
    from bonsai.gevent import GeventLDAPConnection
    MOD_INSTALLED = True
except ImportError:
    MOD_INSTALLED = False

@unittest.skipIf(not MOD_INSTALLED, "Gevent is not installed.")
class GeventLDAPConnectionTest(unittest.TestCase):
    """ Test GeventLDAPConnection object. """
    @classmethod
    def setUpClass(cls):
        """ Set LDAP URL and open connection. """
        curdir = os.path.abspath(os.path.dirname(__file__))
        cls.cfg = configparser.ConfigParser()
        cls.cfg.read(os.path.join(curdir, 'test.ini'))
        cls.url = "ldap://%s:%s/%s?%s?%s" % (cls.cfg["SERVER"]["hostip"],
                                             cls.cfg["SERVER"]["port"],
                                             cls.cfg["SERVER"]["basedn"],
                                             cls.cfg["SERVER"]["search_attr"],
                                             cls.cfg["SERVER"]["search_scope"])
        cls.basedn = cls.cfg["SERVER"]["basedn"]
        cls.ipaddr = cls.cfg["SERVER"]["hostip"]
        cls.client = LDAPClient(cls.url)
        cls.client.set_credentials("SIMPLE",
                                   user=cls.cfg["SIMPLEAUTH"]["user"],
                                   password=cls.cfg["SIMPLEAUTH"]["password"])
        cls.client.set_async_connection_class(GeventLDAPConnection)

    def test_connection(self):
        """ Test opening a connection. """
        conn = self.client.connect(True)
        self.assertIsNotNone(conn)
        self.assertFalse(conn.closed)

    def test_search(self):
        """ Test search. """
        with self.client.connect(True) as conn:
            res = conn.search()
            self.assertIsNotNone(res)

    def test_add_and_delete(self):
        """ Test adding and deleting an LDAP entry. """
        with self.client.connect(True) as conn:
            entry = LDAPEntry("cn=async_test,%s" % self.basedn)
            entry['objectclass'] = ['top', 'inetOrgPerson', 'person',
                                    'organizationalPerson']
            entry['sn'] = "async_test"
            try:
                conn.add(entry)
            except bonsai.errors.AlreadyExists:
                conn.delete(entry.dn)
                conn.add(entry)
            except:
                self.fail("Unexpected error.")
            res = conn.search()
            self.assertIn(entry, res)
            entry.delete()
            res = conn.search()
            self.assertNotIn(entry, res)

    def test_recursive_delete(self):
        """ Test removing a subtree recursively. """
        org1 = bonsai.LDAPEntry("ou=testusers,%s" % self.basedn)
        org1.update({"objectclass" : ['organizationalUnit', 'top'], "ou" : "testusers"})
        org2 = bonsai.LDAPEntry("ou=tops,ou=testusers,%s" % self.basedn)
        org2.update({"objectclass" : ['organizationalUnit', 'top'], "ou" : "tops"})
        entry = bonsai.LDAPEntry("cn=tester,ou=tops,ou=testusers,%s" % self.basedn)
        entry.update({"objectclass" : ["top", "inetorgperson"], "cn" : "tester", "sn" : "example"})
        try:
            with self.client.connect(True) as conn:
                conn.add(org1)
                conn.add(org2)
                conn.add(entry)
                try:
                    conn.delete(org1.dn)
                except bonsai.LDAPError as exc:
                    self.assertIsInstance(exc, bonsai.errors.NotAllowedOnNonleaf)
                conn.delete(org1.dn, recursive=True)
                res = conn.search(org1.dn, 2)
                self.assertListEqual(res, [])
        except bonsai.LDAPError as err:
            self.fail("Recursive delete is failed: %s" % err)

    def test_modify_and_rename(self):
        """ Test modifying and renaming LDAP entry. """
        with self.client.connect(True) as conn:
            entry = LDAPEntry("cn=async_test,%s" % self.basedn)
            entry['objectclass'] = ['top', 'inetOrgPerson', 'person',
                                    'organizationalPerson']
            entry['sn'] = "async_test"
            oldname = "cn=async_test,%s" % self.basedn
            newname = "cn=async_test2,%s" % self.basedn
            res = conn.search(newname, 0)
            if res:
                res[0].delete()
            try:
                conn.add(entry)
            except bonsai.errors.AlreadyExists:
                conn.delete(entry.dn)
                conn.add(entry)
            except:
                self.fail("Unexpected error.")
            entry['sn'] = "async_test2"
            entry.modify()
            entry.rename(newname)
            res = conn.search(entry.dn, 0, attrlist=['sn'])
            self.assertEqual(entry['sn'], res[0]['sn'])
            res = conn.search(oldname, 0)
            self.assertEqual(res, [])
            conn.delete(entry.dn)

    def test_obj_err(self):
        """ Test object class violation error. """
        entry = LDAPEntry("cn=async_test,%s" % self.basedn)
        entry['cn'] = ['async_test']
        def err():
            with self.client.connect(True) as conn:
                conn.add(entry)
        self.assertRaises(bonsai.errors.ObjectClassViolation, err)

    def test_whoami(self):
        """ Test whoami. """
        with self.client.connect(True) as conn:
            obj = conn.whoami()
            expected_res = ["dn:%s" % self.cfg["SIMPLEAUTH"]["user"],
                            self.cfg["SIMPLEAUTH"]["adusername"]]
            self.assertIn(obj, expected_res)

if __name__ == '__main__':
    unittest.main()
