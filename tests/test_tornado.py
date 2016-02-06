import configparser
import os
import unittest
from functools import wraps

from bonsai import LDAPClient
from bonsai import LDAPEntry
import bonsai.errors

def dummy(f):
    return f

try:
    from tornado.testing import gen_test
    from tornado.testing import AsyncTestCase
    from bonsai.tornado import TornadoLDAPConnection
    TestCaseClass = AsyncTestCase
    modinstalled = True
except ImportError:
    TestCaseClass = unittest.TestCase
    gen_test = dummy
    modinstalled = False
    pass

@unittest.skipIf(not modinstalled, "Tornado is not installed.")
class TornadoLDAPConnectionTest(TestCaseClass):
    """ Test TornadoLDAPConnection object. """
    def setUp(self):
        """ Set LDAP URL and open connection. """
        curdir = os.path.abspath(os.path.dirname(__file__))
        self.cfg = configparser.ConfigParser()
        self.cfg.read(os.path.join(curdir, 'test.ini'))
        self.url = "ldap://%s:%s/%s?%s?%s" % (self.cfg["SERVER"]["hostip"], \
                                        self.cfg["SERVER"]["port"], \
                                        self.cfg["SERVER"]["basedn"], \
                                        self.cfg["SERVER"]["search_attr"], \
                                        self.cfg["SERVER"]["search_scope"])
        self.basedn = self.cfg["SERVER"]["basedn"]
        self.client = LDAPClient(self.url)
        self.client.set_credentials("SIMPLE", (self.cfg["SIMPLEAUTH"]["user"],
                                          self.cfg["SIMPLEAUTH"]["password"]))
        self.client.set_async_connection_class(TornadoLDAPConnection)
        self.io_loop = self.get_new_ioloop()
        
    @gen_test
    def test_connection(self):
        conn = yield self.client.connect(True, ioloop=self.io_loop)
        self.assertIsNotNone(conn)
        self.assertFalse(conn.closed)
        conn.close()
    
    @gen_test
    def test_search(self):
        with (yield self.client.connect(True, ioloop=self.io_loop)) as conn:
            res = yield conn.search()
            self.assertIsNotNone(res)
   
    @gen_test
    def test_add_and_delete(self):
        with (yield self.client.connect(True, ioloop=self.io_loop)) as conn:
            entry = LDAPEntry("cn=async_test,%s" % self.basedn)
            entry['objectclass'] = ['top', 'inetOrgPerson', 'person',
                                    'organizationalPerson']
            entry['sn'] = "async_test"
            try:
                yield conn.add(entry)
            except bonsai.errors.AlreadyExists:
                yield conn.delete(entry.dn)
                yield conn.add(entry)
            except:
                self.fail("Unexcepected error.")
            res = yield conn.search()
            self.assertIn(entry, res)
            yield entry.delete()
            res = yield conn.search()
            self.assertNotIn(entry, res)

    @gen_test
    def test_modify_and_rename(self):
        with (yield self.client.connect(True, ioloop=self.io_loop)) as conn:
            entry = LDAPEntry("cn=async_test,%s" % self.basedn)
            entry['objectclass'] = ['top', 'inetOrgPerson', 'person',
                                    'organizationalPerson']
            entry['sn'] = "async_test"
            oldname = "cn=async_test,%s" % self.basedn
            newname = "cn=async_test2,%s" % self.basedn
            res = yield conn.search(newname, 0)
            if res:
                yield res[0].delete()
            try:
                yield conn.add(entry)
            except bonsai.errors.AlreadyExists:
                yield conn.delete(entry.dn)
                yield conn.add(entry)
            except:
                self.fail("Unexcepected error.")
            entry['sn'] = "async_test2"
            yield entry.modify()
            yield entry.rename(newname)
            res = yield conn.search(entry.dn, 0, attrlist=['sn'])
            self.assertEqual(entry['sn'], res[0]['sn'])
            res = yield conn.search(oldname, 0)
            self.assertEqual(res, [])
            yield conn.delete(entry.dn)
    
    @gen_test
    def test_obj_err(self):
        entry = LDAPEntry("cn=async_test,%s" % self.basedn)
        entry['objectclass'] = ['top', 'inetOrgPerson', 'person',
                                'organizationalPerson']
        try:
            with (yield self.client.connect(True, ioloop=self.io_loop)) as conn:
                yield conn.add(entry)
        except bonsai.errors.ObjectClassViolation:
            return
        except Exception as exc:
            self.fail("test_obj_err failed with %s" % exc)
        self.fail("test_obj_err failed without the right exception.")

    @gen_test
    def test_whoami(self):
        """ Test whoami. """
        with (yield self.client.connect(True, ioloop=self.io_loop)) as conn:
            obj = yield conn.whoami()
            expected_res = "dn:%s" % self.cfg["SIMPLEAUTH"]["user"]
            self.assertEqual(obj, expected_res)
            
if __name__ == '__main__':
    unittest.main()
