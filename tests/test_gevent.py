import sys
import bonsai.errors
from bonsai import get_vendor_info
from bonsai import LDAPClient
from bonsai import LDAPEntry

import pytest
from conftest import get_config, network_delay

try:
    from gevent import socket
    from bonsai.gevent import GeventLDAPConnection
except ImportError:
    pass
gevent = pytest.importorskip("gevent")


@pytest.fixture(scope="module")
def gclient():
    """ Get an LDAPClient with GeventLDAPConnection async class. """
    cfg = get_config()
    url = "ldap://%s:%s/%s?%s?%s" % (
        cfg["SERVER"]["hostip"],
        cfg["SERVER"]["port"],
        cfg["SERVER"]["basedn"],
        cfg["SERVER"]["search_attr"],
        cfg["SERVER"]["search_scope"],
    )
    cli = LDAPClient(url)
    cli.set_credentials(
        "SIMPLE", user=cfg["SIMPLEAUTH"]["user"], password=cfg["SIMPLEAUTH"]["password"]
    )
    cli.set_async_connection_class(GeventLDAPConnection)
    return cli


@pytest.fixture
def turn_async_conn():
    bonsai.set_connect_async(True)
    yield None
    bonsai.set_connect_async(False)


def test_connection(gclient):
    """ Test opening a connection. """
    conn = gclient.connect(True)
    assert conn is not None
    assert not conn.closed


def test_search(gclient):
    """ Test search. """
    with gclient.connect(True) as conn:
        res = conn.search()
        assert res is not None


def test_add_and_delete(gclient, basedn):
    """ Test adding and deleting an LDAP entry. """
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
    """ Test removing a subtree recursively. """
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
    """ Test modifying and renaming LDAP entry. """
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
    """ Test object class violation error. """
    entry = LDAPEntry("cn=async_test,%s" % basedn)
    entry["cn"] = ["async_test"]
    with pytest.raises(bonsai.errors.ObjectClassViolation):
        with gclient.connect(True) as conn:
            conn.add(entry)


def test_whoami(gclient):
    """ Test whoami. """
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
    """ Test connection timeout. """
    turn_async_conn
    with network_delay(6.0):
        with pytest.raises(socket.timeout):
            gclient.connect(True, timeout=5.0)
