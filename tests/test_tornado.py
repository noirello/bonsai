import time
import unittest
import sys

import pytest
from conftest import (
    get_config,
    network_delay,
    new_client_with_simple_auth,
    pausable_proxy,
    MAX_IDLE_CPU,
)

from bonsai import LDAPEntry
import bonsai.errors


def dummy(timeout=None):
    def dummy_f(f):
        return f

    return dummy_f


if sys.platform == "win32" and sys.version_info.minor >= 8:
    # Enforce SelectorEventLoop as it's no longer default on Windows since Python 3.8.
    import asyncio

    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

try:
    from tornado import gen
    from tornado.testing import gen_test
    from tornado.testing import AsyncTestCase
    from bonsai.tornado import TornadoLDAPConnection

    TestCaseClass = AsyncTestCase
    gen_coroutine = gen.coroutine
    MOD_INSTALLED = True
except ImportError:
    TestCaseClass = unittest.TestCase
    gen_test = dummy
    gen_coroutine = dummy
    MOD_INSTALLED = False


@pytest.mark.skipif(not MOD_INSTALLED, reason="Tornado is not installed.")
class TornadoLDAPConnectionTest(TestCaseClass):
    """Test TornadoLDAPConnection object."""

    def setUp(self):
        """Set LDAP URL and open connection."""
        super().setUp()
        self.cfg = get_config()
        self.basedn = self.cfg["SERVER"]["basedn"]
        self.client = new_client_with_simple_auth(conn_class=TornadoLDAPConnection)
        self.io_loop = self.get_new_ioloop()

    @gen_test(timeout=20.0)
    def test_connection(self):
        """Test opening a connection."""
        conn = yield self.client.connect(True, ioloop=self.io_loop)
        assert conn is not None
        assert not conn.closed
        conn.close()

    @gen_test(timeout=20.0)
    def test_search(self):
        """Test search."""
        with (yield self.client.connect(True, ioloop=self.io_loop)) as conn:
            res = yield conn.search()
            assert res is not None

    @gen_test(timeout=20.0)
    def test_add_and_delete(self):
        """Test addding and deleting an LDAP entry."""
        with (yield self.client.connect(True, ioloop=self.io_loop)) as conn:
            entry = LDAPEntry("cn=async_test,%s" % self.basedn)
            entry["objectclass"] = [
                "top",
                "inetOrgPerson",
                "person",
                "organizationalPerson",
            ]
            entry["sn"] = "async_test"
            try:
                yield conn.add(entry)
            except bonsai.errors.AlreadyExists:
                yield conn.delete(entry.dn)
                yield conn.add(entry)
            except:
                self.fail("Unexpected error.")
            res = yield conn.search()
            assert entry in res
            yield entry.delete()
            res = yield conn.search()
            assert entry not in res

    @gen_test(timeout=20.0)
    def test_recursive_delete(self):
        """Test removing a subtree recursively."""
        org1 = bonsai.LDAPEntry("ou=testusers,%s" % self.basedn)
        org1.update({"objectclass": ["organizationalUnit", "top"], "ou": "testusers"})
        org2 = bonsai.LDAPEntry("ou=tops,ou=testusers,%s" % self.basedn)
        org2.update({"objectclass": ["organizationalUnit", "top"], "ou": "tops"})
        entry = bonsai.LDAPEntry("cn=tester,ou=tops,ou=testusers,%s" % self.basedn)
        entry.update(
            {"objectclass": ["top", "inetorgperson"], "cn": "tester", "sn": "example"}
        )
        try:
            with (
                yield self.client.connect(True, timeout=10.0, ioloop=self.io_loop)
            ) as conn:
                yield conn.add(org1)
                yield conn.add(org2)
                yield conn.add(entry)
                with pytest.raises(bonsai.errors.NotAllowedOnNonleaf):
                    yield conn.delete(org1.dn)
                yield conn.delete(org1.dn, recursive=True)
                res = yield conn.search(org1.dn, 2)
                assert res == []
        except bonsai.LDAPError as err:
            self.fail("Recursive delete is failed: %s" % err)

    @gen_test(timeout=20.0)
    def test_modify_and_rename(self):
        """Test modifying and renaming an LDAP entry."""
        with (yield self.client.connect(True, ioloop=self.io_loop)) as conn:
            entry = LDAPEntry("cn=async_test,%s" % self.basedn)
            entry["objectclass"] = [
                "top",
                "inetOrgPerson",
                "person",
                "organizationalPerson",
            ]
            entry["sn"] = "async_test"
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
                self.fail("Unexpected error.")
            entry["sn"] = "async_test2"
            yield entry.modify()
            yield entry.rename(newname)
            res = yield conn.search(entry.dn, 0, attrlist=["sn"])
            assert entry["sn"] == res[0]["sn"]
            res = yield conn.search(oldname, 0)
            assert res == []
            yield conn.delete(entry.dn)

    @gen_test(timeout=20.0)
    def test_obj_err(self):
        """Test object class violation error."""
        entry = LDAPEntry("cn=async_test,%s" % self.basedn)
        entry["cn"] = ["async_test"]
        with (yield self.client.connect(True, ioloop=self.io_loop)) as conn:
            with pytest.raises(bonsai.errors.ObjectClassViolation):
                yield conn.add(entry)

    @gen_test(timeout=20.0)
    def test_whoami(self):
        """Test whoami."""
        with (yield self.client.connect(True, ioloop=self.io_loop)) as conn:
            obj = yield conn.whoami()
            expected_res = [
                "dn:%s" % self.cfg["SIMPLEAUTH"]["user"],
                self.cfg["SIMPLEAUTH"]["adusername"],
            ]
            assert obj in expected_res

    @gen_test(timeout=12.0)
    def test_connection_timeout(self):
        """Test connection timeout."""
        with network_delay(7.0):
            with pytest.raises(gen.TimeoutError):
                yield self.client.connect(True, ioloop=self.io_loop, timeout=8.0)

    @gen_test(timeout=18.0)
    def test_search_timeout(self):
        """Test search timeout."""
        with (yield self.client.connect(True, ioloop=self.io_loop)) as conn:
            with network_delay(7.0):
                with pytest.raises(gen.TimeoutError):
                    yield conn.search(timeout=3.0)

    @gen_test(timeout=20.0)
    def test_paged_search(self):
        """Test paged results control."""
        self.client.auto_page_acquire = False
        search_dn = "ou=nerdherd,%s" % self.basedn
        with (yield self.client.connect(True, ioloop=self.io_loop)) as conn:
            res = yield conn.paged_search(search_dn, 1, page_size=2)
            for ent in res:
                assert isinstance(ent, bonsai.LDAPEntry)
            page = 1  # First page is already acquired.
            while True:
                if len(res) > 2:
                    pytest.fail("The size of the page is greater than expected.")
                msgid = res.acquire_next_page()
                if msgid is None:
                    break
                res = yield conn.get_result(msgid)
                page += 1
            assert page == 3

    @gen_test(timeout=20.0)
    def test_paged_search_with_auto_acq(self):
        """Test paged search with auto page acquiring."""
        self.client.auto_page_acquire = True
        search_dn = "ou=nerdherd,%s" % self.basedn
        with (yield self.client.connect(True, ioloop=self.io_loop)) as conn:
            res_iter = yield conn.paged_search(search_dn, 1, page_size=3)
            res_iter = type(res_iter).__aiter__(res_iter)
            cnt = 0
            while True:
                try:
                    res = yield type(res_iter).__anext__(res_iter)
                    assert isinstance(res, LDAPEntry)
                    cnt += 1
                except StopAsyncIteration:
                    break
            assert cnt == 6

    @gen_test(timeout=20.0)
    def test_paged_search_async_for_no_auto_acquire(self):
        """Test that with auto acquire off, async for stops at the end of the first page."""
        self.client.auto_page_acquire = False
        search_dn = "ou=nerdherd,%s" % self.basedn
        with (yield self.client.connect(True, ioloop=self.io_loop)) as conn:
            res_iter = yield conn.paged_search(search_dn, 1, page_size=2)
            res_iter = type(res_iter).__aiter__(res_iter)
            found = []
            while True:
                try:
                    found.append((yield type(res_iter).__anext__(res_iter)))
                except StopAsyncIteration:
                    break
        assert len(found) == 2

    @gen_test(timeout=15.0)
    def test_connect_with_async_connect_option(self):
        """Open must complete when LDAP_OPT_CONNECT_ASYNC is enabled.

        Regression: with set_connect_async(True), _ldap_bind returns
        LDAP_X_CONNECTING and the bind PDU is not queued, so polling
        ldap_result on the (undefined) bind msgid returned 0 forever and
        open() hung indefinitely.
        """
        bonsai.set_connect_async(True)
        try:
            conn = yield self.client.connect(True, ioloop=self.io_loop, timeout=10.0)
            assert not conn.closed
            conn.close()
        finally:
            bonsai.set_connect_async(False)

    @gen_test(timeout=25.0)
    def test_connect_with_async_connect_option_under_delay(self):
        """The async-connect retry path drives the connect to completion.

        With network_delay slowing the TCP handshake, the open should still
        complete by retrying _ldap_bind on socket write-readiness.
        """
        bonsai.set_connect_async(True)
        try:
            with network_delay(2.0):
                conn = yield self.client.connect(
                    True, ioloop=self.io_loop, timeout=20.0
                )
                assert not conn.closed
                conn.close()
        finally:
            bonsai.set_connect_async(False)

    @gen_coroutine
    def first_page(self, conn, **kwargs):
        res = yield conn.paged_search(
            "ou=nerdherd,dc=bonsai,dc=test", 1, page_size=3, **kwargs
        )
        for _ in range(3):
            next(res)
        return type(res).__aiter__(res)

    @gen_test(timeout=30)
    def test_paged_search_waiting_does_not_spin_cpu(self):
        """Test that waiting for a page lets the event loop sleep."""
        with pausable_proxy() as proxy:
            cli = new_client_with_simple_auth(
                "127.0.0.1", proxy.port, TornadoLDAPConnection
            )
            conn = yield cli.connect(True)
            res = yield self.first_page(conn)
            proxy.pause()
            fut = type(res).__anext__(res)
            yield gen.sleep(0.2)
            start = time.process_time()
            yield gen.sleep(1.0)
            used = time.process_time() - start
            proxy.resume()
            entry = yield fut
            conn.close()
        assert isinstance(entry, LDAPEntry)
        assert used < MAX_IDLE_CPU

    @gen_test(timeout=30)
    def test_paged_search_timeout_on_next_page(self):
        """Test that the timeout applies to the pages after the first one."""
        with pausable_proxy() as proxy:
            cli = new_client_with_simple_auth(
                "127.0.0.1", proxy.port, TornadoLDAPConnection
            )
            conn = yield cli.connect(True)
            res = yield self.first_page(conn, timeout=1.0)
            proxy.pause()
            start = time.monotonic()
            with pytest.raises(gen.TimeoutError):
                yield type(res).__anext__(res)
            assert 0.8 < time.monotonic() - start < 4.0
            proxy.resume()
            conn.close()
