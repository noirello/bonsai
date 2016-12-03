import asyncio
import configparser
import os
import time
import unittest
from functools import wraps

from bonsai import LDAPClient
from bonsai import LDAPEntry
import bonsai.errors

def asyncio_test(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        coro = asyncio.coroutine(func)
        future = coro(*args, **kwargs)
        loop = asyncio.get_event_loop()
        loop.run_until_complete(future)
    return wrapper


class AIOLDAPConnectionTest(unittest.TestCase):
    """ Test AIOLDAPConnection object. """
    @classmethod
    def setUpClass(cls):
        """ Set LDAP URL and open connection. """
        curdir = os.path.abspath(os.path.dirname(__file__))
        cls.cfg = configparser.ConfigParser()
        cls.cfg.read(os.path.join(curdir, 'test.ini'))
        cls.url = "ldap://%s:%s/%s?%s?%s" % (cls.cfg["SERVER"]["hostip"], \
                                             cls.cfg["SERVER"]["port"], \
                                             cls.cfg["SERVER"]["basedn"], \
                                             cls.cfg["SERVER"]["search_attr"], \
                                             cls.cfg["SERVER"]["search_scope"])
        cls.basedn = cls.cfg["SERVER"]["basedn"]
        cls.ipaddr = cls.cfg["SERVER"]["hostip"]
        cls.client = LDAPClient(cls.url)
        cls.client.set_credentials("SIMPLE", (cls.cfg["SIMPLEAUTH"]["user"],
                                              cls.cfg["SIMPLEAUTH"]["password"]))

    @asyncio_test
    def test_connection(self):
        """ Test opening a connection. """
        conn = yield from self.client.connect(True)
        self.assertIsNotNone(conn)
        self.assertFalse(conn.closed)

    @asyncio_test
    def test_search(self):
        """ Test search. """
        with (yield from self.client.connect(True)) as conn:
            res = yield from conn.search()
            self.assertIsNotNone(res)

    @asyncio_test
    def test_add_and_delete(self):
        """ Test adding and deleting an LDAP entry. """
        with (yield from self.client.connect(True)) as conn:
            entry = LDAPEntry("cn=async_test,%s" % self.basedn)
            entry['objectclass'] = ['top', 'inetOrgPerson', 'person',
                                    'organizationalPerson']
            entry['sn'] = "async_test"
            try:
                yield from conn.add(entry)
            except bonsai.errors.AlreadyExists:
                yield from conn.delete(entry.dn)
                yield from conn.add(entry)
            except:
                self.fail("Unexcepected error.")
            res = yield from conn.search()
            self.assertIn(entry, res)
            yield from entry.delete()
            res = yield from conn.search()
            self.assertNotIn(entry, res)

    @asyncio_test
    def test_recursive_delete(self):
        """ Test removing a subtree recursively. """
        org1 = bonsai.LDAPEntry("ou=testusers,%s" % self.basedn)
        org1.update({"objectclass" : ['organizationalUnit', 'top'], "ou" : "testusers"})
        org2 = bonsai.LDAPEntry("ou=tops,ou=testusers,%s" % self.basedn)
        org2.update({"objectclass" : ['organizationalUnit', 'top'], "ou" : "tops"})
        entry = bonsai.LDAPEntry("cn=tester,ou=tops,ou=testusers,%s" % self.basedn)
        entry.update({"objectclass" : ["top", "inetorgperson"], "cn" : "tester", "sn" : "example"})
        try:
            with (yield from self.client.connect(True)) as conn:
                yield from conn.add(org1)
                yield from conn.add(org2)
                yield from conn.add(entry)
                try:
                    yield from conn.delete(org1.dn)
                except bonsai.LDAPError as exc:
                    self.assertIsInstance(exc, bonsai.errors.NotAllowedOnNonleaf)
                yield from conn.delete(org1.dn, recursive=True)
                res = yield from conn.search(org1.dn, 2)
                self.assertListEqual(res, [])
        except bonsai.LDAPError as err:
            self.fail("Recursive delete is failed: %s" % err)

    @asyncio_test
    def test_modify_and_rename(self):
        """ Test modifying and renaming LDAP entry. """
        with (yield from self.client.connect(True)) as conn:
            entry = LDAPEntry("cn=async_test,%s" % self.basedn)
            entry['objectclass'] = ['top', 'inetOrgPerson', 'person',
                                    'organizationalPerson']
            entry['sn'] = "async_test"
            oldname = "cn=async_test,%s" % self.basedn
            newname = "cn=async_test2,%s" % self.basedn
            res = yield from conn.search(newname, 0)
            if res:
                yield from res[0].delete()
            try:
                yield from conn.add(entry)
            except bonsai.errors.AlreadyExists:
                yield from conn.delete(entry.dn)
                yield from conn.add(entry)
            except:
                self.fail("Unexcepected error.")
            entry['sn'] = "async_test2"
            yield from entry.modify()
            yield from entry.rename(newname)
            res = yield from conn.search(entry.dn, 0, attrlist=['sn'])
            self.assertEqual(entry['sn'], res[0]['sn'])
            res = yield from conn.search(oldname, 0)
            self.assertEqual(res, [])
            yield from conn.delete(entry.dn)

    def test_obj_err(self):
        """ Test object class violation error. """
        entry = LDAPEntry("cn=async_test,%s" % self.basedn)
        entry['cn'] = ['async_test']
        @asyncio_test
        def err():
            with (yield from self.client.connect(True)) as conn:
                yield from conn.add(entry)
        self.assertRaises(bonsai.errors.ObjectClassViolation, err)

    @asyncio_test
    def test_whoami(self):
        """ Test whoami. """
        with (yield from self.client.connect(True)) as conn:
            obj = yield from conn.whoami()
            expected_res = ["dn:%s" % self.cfg["SIMPLEAUTH"]["user"],
                            self.cfg["SIMPLEAUTH"]["adusername"]]
            self.assertIn(obj, expected_res)

    @asyncio_test
    def test_connection_timeout(self):
        """ Test connection timeout. """
        import xmlrpc.client as rpc
        proxy = rpc.ServerProxy("http://%s:%d/" % (self.ipaddr, 8000))
        proxy.set_delay(6.0)
        time.sleep(3.0)
        try:
            yield from self.client.connect(True, timeout=8.0)
        except Exception as exc:
            self.assertIsInstance(exc, asyncio.TimeoutError)
        else:
            self.fail("Failed to receive TimeoutError.")
        finally:
            proxy.remove_delay()

    @asyncio_test
    def test_search_timeout(self):
        """ Test search timeout. """
        import xmlrpc.client as rpc
        with (yield from self.client.connect(True)) as conn:
            proxy = rpc.ServerProxy("http://%s:%d/" % (self.ipaddr, 8000))
            proxy.set_delay(5.1, 7)
            time.sleep(3.0)
            try:
                yield from conn.search(timeout=4.0)
            except Exception as exc:
                self.assertIsInstance(exc, asyncio.TimeoutError)
            else:
                self.fail("Failed to receive TimeoutError.")
            finally:
                proxy.remove_delay()

if __name__ == '__main__':
    unittest.main()
