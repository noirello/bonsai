import sys
import time
import bonsai.errors
from bonsai import get_vendor_info
from bonsai import LDAPEntry

import pytest
from conftest import (
    get_config,
    network_delay,
    new_client_with_simple_auth,
    pausable_proxy,
    MAX_IDLE_CPU,
)

try:
    from gevent import socket
    from bonsai.gevent import GeventLDAPConnection
except ImportError:
    pass
gevent = pytest.importorskip("gevent")


@pytest.fixture(scope="module")
def gclient():
    """Get an LDAPClient with GeventLDAPConnection async class."""
    return new_client_with_simple_auth(conn_class=GeventLDAPConnection)


def test_connection(gclient):
    """Test opening a connection."""
    conn = gclient.connect(True)
    assert conn is not None
    assert not conn.closed


def test_search(gclient):
    """Test search."""
    with gclient.connect(True) as conn:
        res = conn.search()
        assert res is not None


def test_paged_search_with_auto_acq(gclient, basedn, set_auto_page_acquire):
    """Test paged search with auto page acquiring."""
    set_auto_page_acquire(gclient, True)
    search_dn = "ou=nerdherd,%s" % basedn
    with gclient.connect(True) as conn:
        res = conn.paged_search(search_dn, 1, page_size=3)
        cnt = 0
        for item in res:
            assert isinstance(item, LDAPEntry)
            cnt += 1
        assert cnt == 6


def test_add_and_delete(gclient, basedn):
    """Test adding and deleting an LDAP entry."""
    with gclient.connect(True) as conn:
        entry = LDAPEntry("cn=async_test,%s" % basedn)
        entry["objectclass"] = [
            "top",
            "inetOrgPerson",
            "person",
            "organizationalPerson",
        ]
        entry["sn"] = "async_test"
        try:
            conn.add(entry)
        except bonsai.errors.AlreadyExists:
            conn.delete(entry.dn)
            conn.add(entry)
        except:
            pytest.fail("Unexpected error.")
        res = conn.search()
        assert entry in res
        entry.delete()
        res = conn.search()
        assert entry not in res


def test_recursive_delete(gclient, basedn):
    """Test removing a subtree recursively."""
    org1 = bonsai.LDAPEntry("ou=testusers,%s" % basedn)
    org1.update({"objectclass": ["organizationalUnit", "top"], "ou": "testusers"})
    org2 = bonsai.LDAPEntry("ou=tops,ou=testusers,%s" % basedn)
    org2.update({"objectclass": ["organizationalUnit", "top"], "ou": "tops"})
    entry = bonsai.LDAPEntry("cn=tester,ou=tops,ou=testusers,%s" % basedn)
    entry.update(
        {"objectclass": ["top", "inetorgperson"], "cn": "tester", "sn": "example"}
    )
    try:
        with gclient.connect(True) as conn:
            conn.add(org1)
            conn.add(org2)
            conn.add(entry)
            with pytest.raises(bonsai.errors.NotAllowedOnNonleaf):
                conn.delete(org1.dn)
            conn.delete(org1.dn, recursive=True)
            res = conn.search(org1.dn, 2)
            assert res == []
    except bonsai.LDAPError as err:
        pytest.fail("Recursive delete is failed: %s" % err)


def test_modify_and_rename(gclient, basedn):
    """Test modifying and renaming LDAP entry."""
    with gclient.connect(True) as conn:
        entry = LDAPEntry("cn=async_test,%s" % basedn)
        entry["objectclass"] = [
            "top",
            "inetOrgPerson",
            "person",
            "organizationalPerson",
        ]
        entry["sn"] = "async_test"
        oldname = "cn=async_test,%s" % basedn
        newname = "cn=async_test2,%s" % basedn
        res = conn.search(newname, 0)
        if res:
            res[0].delete()
        try:
            conn.add(entry)
        except bonsai.errors.AlreadyExists:
            conn.delete(entry.dn)
            conn.add(entry)
        except:
            pytest.fail("Unexpected error.")
        entry["sn"] = "async_test2"
        entry.modify()
        entry.rename(newname)
        res = conn.search(entry.dn, 0, attrlist=["sn"])
        assert entry["sn"] == res[0]["sn"]
        res = conn.search(oldname, 0)
        assert res == []
        conn.delete(entry.dn)


def test_obj_err(gclient, basedn):
    """Test object class violation error."""
    entry = LDAPEntry("cn=async_test,%s" % basedn)
    entry["cn"] = ["async_test"]
    with pytest.raises(bonsai.errors.ObjectClassViolation):
        with gclient.connect(True) as conn:
            conn.add(entry)


def test_whoami(gclient):
    """Test whoami."""
    with gclient.connect(True) as conn:
        cfg = get_config()
        obj = conn.whoami()
        expected_res = [
            "dn:%s" % cfg["SIMPLEAUTH"]["user"],
            cfg["SIMPLEAUTH"]["adusername"],
        ]
        assert obj in expected_res


@pytest.mark.skipif(
    get_vendor_info()[1] < 20445 or sys.platform != "linux",
    reason="No async timeout support",
)
@pytest.mark.timeout(18)
def test_connection_timeout(gclient, turn_async_conn):
    """Test connection timeout."""
    with network_delay(6.0):
        with pytest.raises(socket.timeout):
            gclient.connect(True, timeout=5.0)


@pytest.mark.timeout(15)
def test_connect_with_async_connect_option(gclient, turn_async_conn):
    """Open must complete when LDAP_OPT_CONNECT_ASYNC is enabled.

    Regression: with set_connect_async(True), _ldap_bind returns
    LDAP_X_CONNECTING and the bind PDU is not queued, so polling
    ldap_result on the (undefined) bind msgid returned 0 forever and
    open() hung indefinitely.
    """
    conn = gclient.connect(True, timeout=10)
    assert not conn.closed
    conn.close()


@pytest.mark.timeout(25)
def test_connect_with_async_connect_option_under_delay(gclient, turn_async_conn):
    """The async-connect retry path drives the connect to completion.

    With network_delay slowing the TCP handshake, the open should still
    complete by retrying _ldap_bind on socket write-readiness.
    """
    with network_delay(2.0):
        conn = gclient.connect(True, timeout=20)
        assert not conn.closed
        conn.close()


def _first_page(conn, **kwargs):
    res = conn.paged_search("ou=nerdherd,dc=bonsai,dc=test", 1, page_size=3, **kwargs)
    for _ in range(3):
        next(res)
    return res


def test_paged_search_iter_all_pages():
    """Test that a plain for loop goes through every page."""
    with new_client_with_simple_auth(conn_class=GeventLDAPConnection).connect(
        True
    ) as conn:
        res = conn.paged_search("ou=nerdherd,dc=bonsai,dc=test", 1, page_size=4)
        assert len(list(res)) == 6


def test_paged_search_waiting_does_not_spin_cpu():
    """Test that waiting for a page lets the other greenlets (and the CPU) sleep."""
    with pausable_proxy() as proxy:
        cli = new_client_with_simple_auth("127.0.0.1", proxy.port, GeventLDAPConnection)
        with cli.connect(True) as conn:
            res = _first_page(conn)
            proxy.pause()
            greenlet = gevent.spawn(list, res)
            gevent.sleep(0.2)
            start = time.process_time()
            gevent.sleep(1.0)
            used = time.process_time() - start
            proxy.resume()
            assert len(greenlet.get(timeout=5)) == 3
    assert used < MAX_IDLE_CPU


def test_paged_search_timeout_on_next_page():
    """Test that the timeout applies to the pages after the first one, and that
    it's a real deadline, not restarted at every wake up."""
    with pausable_proxy() as proxy:
        cli = new_client_with_simple_auth("127.0.0.1", proxy.port, GeventLDAPConnection)
        with cli.connect(True) as conn:
            res = _first_page(conn, timeout=1.0)
            proxy.pause()
            start = time.monotonic()
            with pytest.raises(socket.timeout):
                next(res)
            assert 0.8 < time.monotonic() - start < 4.0
            proxy.resume()
