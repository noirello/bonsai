import asyncio
import sys
import time
from functools import wraps

import pytest
from conftest import (
    get_config,
    network_delay,
    new_client_with_simple_auth,
    pausable_proxy,
    MAX_IDLE_CPU,
)

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
        with await client.connect(True) as conn:
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


@pytest.mark.timeout(15)
@asyncio_test
async def test_connect_with_async_connect_option(client, turn_async_conn):
    """Open must complete when LDAP_OPT_CONNECT_ASYNC is enabled.

    Regression: with set_connect_async(True), _ldap_bind returns
    LDAP_X_CONNECTING and the bind PDU is not queued, so polling
    ldap_result on the (undefined) bind msgid returned 0 forever and
    open() hung indefinitely.
    """
    async with client.connect(True, timeout=10) as conn:
        assert not conn.closed


@pytest.mark.timeout(25)
@asyncio_test
async def test_connect_with_async_connect_option_under_delay(client, turn_async_conn):
    """The async-connect retry path drives the connect to completion.

    With network_delay slowing the TCP handshake, the open should still
    complete by retrying _ldap_bind on socket write-readiness.
    """
    with network_delay(2.0):
        async with client.connect(True, timeout=20) as conn:
            assert not conn.closed


@asyncio_test
async def test_paged_search(client, basedn, set_auto_page_acquire):
    """Test paged results control."""
    set_auto_page_acquire(client, False)
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
async def test_paged_search_with_auto_acq(client, basedn, set_auto_page_acquire):
    """Test paged search with auto page acquiring."""
    set_auto_page_acquire(client, True)
    search_dn = "ou=nerdherd,%s" % basedn
    async with client.connect(True) as conn:
        cnt = 0
        result = await conn.paged_search(search_dn, 1, page_size=3)
        async for item in result:
            assert isinstance(item, LDAPEntry)
            cnt += 1
        assert cnt == 6


@asyncio_test
async def test_paged_search_async_for_no_auto_acquire(
    client, basedn, set_auto_page_acquire
):
    """Test that with auto acquire off, async for stops at the end of the first page."""
    set_auto_page_acquire(client, False)
    search_dn = "ou=nerdherd,%s" % basedn
    async with client.connect(True) as conn:
        res = await conn.paged_search(search_dn, 1, page_size=2)
        found = [ent async for ent in res]
    assert len(found) == 2


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


async def _first_page(conn, **kwargs):
    res = await conn.paged_search(
        "ou=nerdherd,dc=bonsai,dc=test", 1, page_size=3, **kwargs
    )
    for _ in range(3):
        next(res)
    return res


async def _collect(res):
    return [entry async for entry in res]


@asyncio_test
async def test_paged_search_waiting_does_not_spin_cpu():
    """Test that waiting for a page lets the event loop sleep."""
    with pausable_proxy() as proxy:
        async with new_client_with_simple_auth("127.0.0.1", proxy.port).connect(
            True
        ) as conn:
            res = await _first_page(conn)
            proxy.pause()
            task = asyncio.ensure_future(_collect(res))
            await asyncio.sleep(0.2)
            start = time.process_time()
            await asyncio.sleep(1.0)
            used = time.process_time() - start
            proxy.resume()
            assert len(await task) == 3
    assert used < MAX_IDLE_CPU


@asyncio_test
async def test_paged_search_timeout_on_next_page():
    """Test that the timeout applies to the pages after the first one."""
    with pausable_proxy() as proxy:
        async with new_client_with_simple_auth("127.0.0.1", proxy.port).connect(
            True
        ) as conn:
            res = await _first_page(conn, timeout=1.0)
            proxy.pause()
            start = time.monotonic()
            with pytest.raises(asyncio.TimeoutError):
                await res.__anext__()
            assert 0.8 < time.monotonic() - start < 4.0
            proxy.resume()


@asyncio_test
async def test_cancelled_page_wait_cleans_up():
    """Test that cancelling the wait for a page leaves nothing behind in the loop."""
    errors = []
    asyncio.get_running_loop().set_exception_handler(
        lambda loop, ctx: errors.append(ctx)
    )
    with pausable_proxy() as proxy:
        async with new_client_with_simple_auth("127.0.0.1", proxy.port).connect(
            True
        ) as conn:
            res = await _first_page(conn)
            proxy.pause()
            task = asyncio.ensure_future(res.__anext__())
            await asyncio.sleep(0.2)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            start = time.process_time()
            await asyncio.sleep(1.0)
            used = time.process_time() - start
            proxy.resume()
            await asyncio.sleep(0.5)  # Let the late response arrive.
            # The connection is still usable.
            assert len(await conn.search("ou=nerdherd,dc=bonsai,dc=test", 1)) == 6
    assert used < MAX_IDLE_CPU
    assert not errors


@asyncio_test
async def test_connect_waiting_for_bind_does_not_spin_cpu():
    """Test that opening a connection lets the event loop sleep, while the server
    is slow to answer the bind request."""
    with pausable_proxy() as proxy:
        proxy.pause()
        task = asyncio.ensure_future(
            new_client_with_simple_auth("127.0.0.1", proxy.port).connect(True)
        )
        await asyncio.sleep(0.4)
        start = time.process_time()
        await asyncio.sleep(1.0)
        used = time.process_time() - start
        proxy.resume()
        conn = await asyncio.wait_for(task, 10)
        assert not conn.closed
        conn.close()
    assert used < MAX_IDLE_CPU


def test_connection_used_on_another_loop(client):
    """Test that using a connection on a different loop than the one that
    created it is okay, and doesn't fail."""
    owner_loop = asyncio.new_event_loop()

    async def open_conn():
        return await client.connect(True)

    try:
        conn = owner_loop.run_until_complete(open_conn())

        async def search():
            assert owner_loop != asyncio.get_event_loop()
            return await conn.search(timeout=5)

        start = time.monotonic()
        asyncio.run(search())
        assert time.monotonic() - start < 2.0
        conn.close()
    finally:
        owner_loop.close()
