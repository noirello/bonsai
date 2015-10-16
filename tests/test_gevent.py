import configparser
import os
import unittest

from bonsai import LDAPClient
from bonsai import LDAPEntry
import bonsai.errors

try:
    import gevent
    from bonsai.gevent import GeventLDAPConnection 
    modinstalled = True
except ImportError:
    modinstalled = False
    pass

@unittest.skipIf(not modinstalled, "Gevent is not installed.")
class GeventLDAPConnectionTest(unittest.TestCase):
    """ Test AIOLDAPConnection object. """
    def setUp(self):
        """ Set LDAP URL and open connection. """
        curdir = os.path.abspath(os.path.dirname(__file__))
        self.cfg = configparser.ConfigParser()
        self.cfg.read(os.path.join(curdir, 'test.ini'))
        self.url = "ldap://%s:%s/%s?%s?%s" % (self.cfg["SERVER"]["host"], \
                                        self.cfg["SERVER"]["port"], \
                                        self.cfg["SERVER"]["basedn"], \
                                        self.cfg["SERVER"]["search_attr"], \
                                        self.cfg["SERVER"]["search_scope"])
        self.basedn = self.cfg["SERVER"]["basedn"]
        self.client = LDAPClient(self.url)
        self.client.set_credentials("SIMPLE", (self.cfg["SIMPLEAUTH"]["user"],
                                          self.cfg["SIMPLEAUTH"]["password"]))
        self.client.set_async_connection_class(GeventLDAPConnection)
        gevent.sleep(1.0)
        
    def test_connection(self):
        conn = self.client.connect(True)
        self.assertIsNotNone(conn)
        self.assertFalse(conn.closed)
    
    def test_search(self):
        with self.client.connect(True) as conn:
            res = conn.search()
            self.assertIsNotNone(res)
   
    def test_add_and_delete(self):
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
                self.fail("Unexcepected error.")
            res = conn.search()
            self.assertIn(entry, res)
            entry.delete()
            res = conn.search()
            self.assertNotIn(entry, res)

    def test_modify_and_rename(self):
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
                self.fail("Unexcepected error.")
            entry['sn'] = "async_test2"
            entry.modify()
            entry.rename("cn=async_test2,%s" % self.basedn)
            res = conn.search(entry.dn, 0, attrlist=['sn'])
            self.assertEqual(entry['sn'], res[0]['sn'])
            res = conn.search("cn=async_test,%s" % self.basedn, 0)
            self.assertEqual(res, [])
            conn.delete(entry.dn)

    def test_obj_err(self):
        entry = LDAPEntry("cn=async_test,%s" % self.basedn)
        entry['objectclass'] = ['top', 'inetOrgPerson', 'person',
                                'organizationalPerson']
        def err():
            with self.client.connect(True) as conn:
                conn.add(entry)
        self.assertRaises(bonsai.errors.ObjectClassViolation, err)

    def test_whoami(self):
        """ Test whoami. """
        with self.client.connect(True) as conn:
            obj = conn.whoami()
            expected_res = "dn:%s" % self.cfg["SIMPLEAUTH"]["user"]
            self.assertEqual(obj, expected_res)
            
if __name__ == '__main__':
    unittest.main()
