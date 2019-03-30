import asyncio
import sys
import time
from functools import wraps

import pytest
from conftest import get_config, network_delay

from bonsai import LDAPClient
from bonsai import LDAPEntry
from bonsai.asyncio import AIOConnectionPool
from bonsai.pool import ClosedPool
import bonsai.errors


def asyncio_test(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        coro = asyncio.coroutine(func)
        future = coro(*args, **kwargs)
        loop = asyncio.get_event_loop()
        loop.run_until_complete(future)

    return wrapper


@asyncio_test
def test_connection(client):
    """ Test opening a connection. """
    conn = yield from client.connect(True)
    assert conn is not None
    assert conn.closed == False


@asyncio_test
def test_search(client):
    """ Test search. """
    with (yield from client.connect(True)) as conn:
        res = yield from conn.search()
        assert res is not None


@asyncio_test
def test_add_and_delete(client, basedn):
    """ Test adding and deleting an LDAP entry. """
    with (yield from client.connect(True)) as conn:
        entry = LDAPEntry("cn=async_test,%s" % basedn)
        entry["objectclass"] = [
            "top",
            "inetOrgPerson",
            "person",
            "organizationalPerson",
        ]
        entry["sn"] = "async_test"
        try:
            yield from conn.add(entry)
        except bonsai.errors.AlreadyExists:
            yield from conn.delete(entry.dn)
            yield from conn.add(entry)
        except:
            pytest.fail("Unexpected error.")
        res = yield from conn.search()
        assert entry in res
        yield from entry.delete()
        res = yield from conn.search()
        assert entry not in res


@asyncio_test
def test_recursive_delete(client, basedn):
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
        with (yield from client.connect(True)) as conn:
            yield from conn.add(org1)
            yield from conn.add(org2)
            yield from conn.add(entry)
            with pytest.raises(bonsai.errors.NotAllowedOnNonleaf):
                yield from conn.delete(org1.dn)
            yield from conn.delete(org1.dn, recursive=True)
            res = yield from conn.search(org1.dn, 2)
            assert res == []
    except bonsai.LDAPError as err:
        pytest.fail("Recursive delete is failed: %s" % err)


@asyncio_test
def test_modify_and_rename(client, basedn):
    """ Test modifying and renaming LDAP entry. """
    with (yield from client.connect(True)) as conn:
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
        res = yield from conn.search(newname, 0)
        if res:
            yield from res[0].delete()
        try:
            yield from conn.add(entry)
        except bonsai.errors.AlreadyExists:
            yield from conn.delete(entry.dn)
            yield from conn.add(entry)
        except:
            pytest.fail("Unexpected error.")
        entry["sn"] = "async_test2"
        yield from entry.modify()
        yield from entry.rename(newname)
        res = yield from conn.search(entry.dn, 0, attrlist=["sn"])
        assert entry["sn"] == res[0]["sn"]
        res = yield from conn.search(oldname, 0)
        assert res == []
        yield from conn.delete(entry.dn)


@asyncio_test
def test_obj_err(client, basedn):
    """ Test object class violation error. """
    entry = LDAPEntry("cn=async_test,%s" % basedn)
    entry["cn"] = ["async_test"]
    with pytest.raises(bonsai.errors.ObjectClassViolation):
        with (yield from client.connect(True)) as conn:
            yield from conn.add(entry)


@asyncio_test
def test_whoami(client):
    """ Test whoami. """
    with (yield from client.connect(True)) as conn:
        cfg = get_config()
        obj = yield from conn.whoami()
        expected_res = [
            "dn:%s" % cfg["SIMPLEAUTH"]["user"],
            cfg["SIMPLEAUTH"]["adusername"],
        ]
        assert obj in expected_res


@pytest.mark.timeout(18)
@asyncio_test
def test_connection_timeout(client):
    """ Test connection timeout. """
    with network_delay(6.0):
        with pytest.raises(asyncio.TimeoutError):
            yield from client.connect(True, timeout=8.0)


@pytest.mark.timeout(18)
@asyncio_test
def test_search_timeout(client):
    """ Test search timeout. """
    with (yield from client.connect(True)) as conn:
        with network_delay(5.1):
            with pytest.raises(asyncio.TimeoutError):
                yield from conn.search(timeout=4.0)


@pytest.mark.skipif(
    sys.version_info.minor < 5, reason="No __aiter__ and __anext__ methods under 3.5."
)
@asyncio_test
def test_paged_search(client, basedn):
    """ Test paged search. """
    search_dn = "ou=nerdherd,%s" % basedn
    with (yield from client.connect(True)) as conn:
        # To keep compatibility with 3.4 it does not uses async for,
        # but its while loop equivalent.
        res_iter = yield from conn.paged_search(search_dn, 1, page_size=3)
        res_iter = type(res_iter).__aiter__(res_iter)
        cnt = 0
        while True:
            try:
                res = yield from type(res_iter).__anext__(res_iter)
                assert isinstance(res, LDAPEntry)
                cnt += 1
            except StopAsyncIteration:
                break
        assert cnt == 6


@asyncio_test
def test_async_with(client):
    """ Test async with context manager (with backward compatibility). """
    mgr = client.connect(True)
    aexit = type(mgr).__aexit__
    aenter = type(mgr).__aenter__(mgr)

    conn = yield from aenter
    try:
        assert conn.closed == False
        _ = yield from conn.whoami()
    except:
        if not (yield from aexit(mgr, *sys.exc_info())):
            raise
    else:
        yield from aexit(mgr, None, None, None)
    assert conn.closed


@asyncio.coroutine
def keep(pool, delay):
    conn = yield from pool.get()
    yield from asyncio.sleep(delay)
    yield from pool.put(conn)


@asyncio_test
def test_pool_get_put(client):
    """ Test getting and putting back connection from pool. """
    delay = 2
    pool = AIOConnectionPool(client, minconn=1, maxconn=1)
    with pytest.raises(ClosedPool):
        _ = yield from pool.get()
    yield from pool.open()
    assert pool.closed == False
    assert pool.idle_connection == 1
    task1 = asyncio.ensure_future(keep(pool, delay))
    task2 = asyncio.ensure_future(keep(pool, delay))
    start = time.time()
    yield from task1
    yield from task2
    assert time.time() - start >= delay * 2
    # With enough connection in the pool for both tasks.
    pool.max_connection = 2
    task1 = asyncio.ensure_future(keep(pool, delay))
    task2 = asyncio.ensure_future(keep(pool, delay))
    start = time.time()
    yield from task1
    yield from task2
    assert time.time() - start >= delay


@asyncio_test
def test_pool_close(client):
    """ Test closing the pool. """
    pool = AIOConnectionPool(client, minconn=1, maxconn=1)
    yield from pool.open()
    assert pool.closed == False
    assert pool.idle_connection == 1
    yield from pool.close()
    assert pool.closed == True
    assert pool.idle_connection == 0
