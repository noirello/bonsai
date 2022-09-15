import asyncio
import sys
import time
from functools import wraps

import pytest
from conftest import get_config, network_delay

from bonsai import LDAPEntry
from bonsai.asyncio import AIOConnectionPool
from bonsai.pool import ClosedPool
import bonsai.errors

if sys.platform == "win32" and sys.version_info.minor >= 8:
    # Enforce SelectorEventLoop as it's no longer default on Windows since Python 3.8.
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


def asyncio_test(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        future = func(*args, **kwargs)
        asyncio.run(future)

    return wrapper


@asyncio_test
async def test_connection(client):
    """Test opening a connection."""
    conn = await client.connect(True)
    assert conn is not None
    assert conn.closed == False


@asyncio_test
async def test_search(client):
    """Test search."""
    async with client.connect(True) as conn:
        res = await conn.search()
        assert res is not None


@asyncio_test
async def test_add_and_delete(client, basedn):
    """Test adding and deleting an LDAP entry."""
    async with client.connect(True) as conn:
        entry = LDAPEntry("cn=async_test,%s" % basedn)
        entry["objectclass"] = [
            "top",
            "inetOrgPerson",
            "person",
            "organizationalPerson",
        ]
        entry["sn"] = "async_test"
        try:
            await conn.add(entry)
        except bonsai.errors.AlreadyExists:
            await conn.delete(entry.dn)
            await conn.add(entry)
        except:
            pytest.fail("Unexpected error.")
        res = await conn.search()
        assert entry in res
        await entry.delete()
        res = await conn.search()
        assert entry not in res


@asyncio_test
async def test_recursive_delete(client, basedn):
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
        with (await client.connect(True)) as conn:
            await conn.add(org1)
            await conn.add(org2)
            await conn.add(entry)
            with pytest.raises(bonsai.errors.NotAllowedOnNonleaf):
                await conn.delete(org1.dn)
            await conn.delete(org1.dn, recursive=True)
            res = await conn.search(org1.dn, 2)
            assert res == []
    except bonsai.LDAPError as err:
        pytest.fail("Recursive delete is failed: %s" % err)


@asyncio_test
async def test_modify_and_rename(client, basedn):
    """Test modifying and renaming LDAP entry."""
    async with client.connect(True) as conn:
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
        res = await conn.search(newname, 0)
        if res:
            await res[0].delete()
        try:
            await conn.add(entry)
        except bonsai.errors.AlreadyExists:
            await conn.delete(entry.dn)
            await conn.add(entry)
        except:
            pytest.fail("Unexpected error.")
        entry["sn"] = "async_test2"
        await entry.modify()
        await entry.rename(newname)
        res = await conn.search(entry.dn, 0, attrlist=["sn"])
        assert entry["sn"] == res[0]["sn"]
        res = await conn.search(oldname, 0)
        assert res == []
        await conn.delete(entry.dn)


@asyncio_test
async def test_obj_err(client, basedn):
    """Test object class violation error."""
    entry = LDAPEntry("cn=async_test,%s" % basedn)
    entry["cn"] = ["async_test"]
    with pytest.raises(bonsai.errors.ObjectClassViolation):
        async with client.connect(True) as conn:
            await conn.add(entry)


@asyncio_test
async def test_whoami(client):
    """Test whoami."""
    async with client.connect(True) as conn:
        cfg = get_config()
        obj = await conn.whoami()
        expected_res = [
            "dn:%s" % cfg["SIMPLEAUTH"]["user"],
            cfg["SIMPLEAUTH"]["adusername"],
        ]
        assert obj in expected_res


@pytest.mark.timeout(18)
@asyncio_test
async def test_connection_timeout(client):
    """Test connection timeout."""
    with network_delay(6.0):
        with pytest.raises(asyncio.TimeoutError):
            await client.connect(True, timeout=8.0)


@pytest.mark.timeout(18)
@asyncio_test
async def test_search_timeout(client):
    """Test search timeout."""
    async with client.connect(True) as conn:
        with network_delay(5.1):
            with pytest.raises(asyncio.TimeoutError):
                await conn.search(timeout=4.0)


@asyncio_test
async def test_paged_search(client, basedn):
    """Test paged results control."""
    client.auto_page_acquire = False
    search_dn = "ou=nerdherd,%s" % basedn
    async with client.connect(True) as conn:
        res = await conn.paged_search(search_dn, 1, page_size=2)
        for ent in res:
            assert isinstance(ent, bonsai.LDAPEntry)
        page = 1  # First page is already acquired.
        while True:
            if len(res) > 2:
                pytest.fail("The size of the page is greater than expected.")
            msgid = res.acquire_next_page()
            if msgid is None:
                break
            res = await conn.get_result(msgid)
            page += 1
        assert page == 3


@asyncio_test
async def test_paged_search_with_auto_acq(client, basedn):
    """Test paged search with auto page acquiring."""
    search_dn = "ou=nerdherd,%s" % basedn
    async with client.connect(True) as conn:
        cnt = 0
        result = await conn.paged_search(search_dn, 1, page_size=3)
        async for item in result:
            assert isinstance(item, LDAPEntry)
            cnt += 1
        assert cnt == 6


@asyncio_test
async def test_async_with(client):
    """Test async with context manager (with backward compatibility)."""
    mgr = client.connect(True)
    aexit = type(mgr).__aexit__
    aenter = type(mgr).__aenter__(mgr)

    conn = await aenter
    try:
        assert conn.closed == False
        _ = await conn.whoami()
    except:
        if not (await aexit(mgr, *sys.exc_info())):
            raise
    else:
        await aexit(mgr, None, None, None)
    assert conn.closed


async def keep(pool, delay):
    conn = await pool.get()
    await asyncio.sleep(delay)
    await pool.put(conn)


@asyncio_test
async def test_pool_get_put(client):
    """Test getting and putting back connection from pool."""
    delay = 2
    pool = AIOConnectionPool(client, minconn=1, maxconn=1)
    with pytest.raises(ClosedPool):
        _ = await pool.get()
    await pool.open()
    assert pool.closed == False
    assert pool.idle_connection == 1
    task1 = asyncio.ensure_future(keep(pool, delay))
    task2 = asyncio.ensure_future(keep(pool, delay))
    start = time.time()
    await task1
    await task2
    assert time.time() - start >= delay * 2
    # With enough connection in the pool for both tasks.
    pool.max_connection = 2
    task1 = asyncio.ensure_future(keep(pool, delay))
    task2 = asyncio.ensure_future(keep(pool, delay))
    start = time.time()
    await task1
    await task2
    assert time.time() - start >= delay


@asyncio_test
async def test_pool_close(client):
    """Test closing the pool."""
    pool = AIOConnectionPool(client, minconn=1, maxconn=1)
    await pool.open()
    assert pool.closed == False
    assert pool.idle_connection == 1
    await pool.close()
    assert pool.closed == True
    assert pool.idle_connection == 0


@asyncio_test
async def test_pool_pass_param(client):
    """Test passing parameter to connect."""
    pool = AIOConnectionPool(client, minconn=1, maxconn=1, timeout=0)
    with pytest.raises(asyncio.TimeoutError):
        await pool.open()
        _ = await pool.get()


@asyncio_test
async def test_pool_spawn(client):
    """Test context manager."""
    pool = AIOConnectionPool(client, minconn=1, maxconn=1)
    assert pool.idle_connection == 0
    async with pool.spawn() as conn:
        assert pool.shared_connection == 1
        _ = await conn.whoami()
    assert pool.idle_connection == 1
    assert pool.shared_connection == 0
