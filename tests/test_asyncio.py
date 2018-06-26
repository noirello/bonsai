import asyncio
import configparser
import os
import time
import unittest
import sys
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
        cls.client.set_credentials("SIMPLE", user=cls.cfg["SIMPLEAUTH"]["user"],
                                   password=cls.cfg["SIMPLEAUTH"]["password"])

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
                self.fail("Unexpected error.")
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
                self.fail("Unexpected error.")
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

    @asyncio_test
    def test_paged_search(self):
        """ Test paged search. """
        if sys.version_info.minor < 5:
            self.skipTest("No __aiter__ and __anext__ methods under 3.5.")
        search_dn = "ou=nerdherd,%s" % self.basedn
        with (yield from self.client.connect(True)) as conn:
            # To keep compatibility with 3.4 it does not uses async for,
            # but its while loop equvivalent.
            res_iter = yield from conn.paged_search(search_dn, 1, page_size=3)
            res_iter = type(res_iter).__aiter__(res_iter)
            cnt = 0
            while True:
                try:
                    res = yield from type(res_iter).__anext__(res_iter)
                    self.assertIsInstance(res, LDAPEntry)
                    cnt += 1
                except StopAsyncIteration:
                    break
            self.assertEqual(cnt, 6)

    @asyncio_test
    def test_async_with(self):
        """
        Test async with context manager
        (with backward compatibility)
        """
        mgr = self.client.connect(True)
        aexit = type(mgr).__aexit__
        aenter = type(mgr).__aenter__(mgr)

        conn = yield from aenter
        try:
            self.assertFalse(conn.closed)
            _ = yield from conn.whoami()
        except:
            if not (yield from aexit(mgr, *sys.exc_info())):
                raise
        else:
            yield from aexit(mgr, None, None, None)
        self.assertTrue(conn.closed)

if __name__ == '__main__':
    unittest.main()
