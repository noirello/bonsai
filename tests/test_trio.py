import sys
from functools import wraps, partial

import pytest
from conftest import get_config, network_delay

from bonsai import LDAPEntry, LDAPClient
import bonsai.errors

try:
    import trio
    from bonsai.trio import TrioLDAPConnection
except ImportError:
    pass
trio = pytest.importorskip("trio")


def trio_test(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        trio.run(partial(func, *args, **kwargs))

    return wrapper


@pytest.fixture(scope="module")
def tclient():
    """Get an LDAPClient with TrioLDAPConnection async class."""
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
    cli.set_async_connection_class(TrioLDAPConnection)
    return cli


@trio_test
async def test_connection(tclient):
    """Test opening a connection."""
    conn = await tclient.connect(True)
    assert conn is not None
    assert conn.closed == False


@trio_test
async def test_search(tclient):
    """Test search."""
    async with tclient.connect(True) as conn:
        res = await conn.search()
        assert res is not None


@trio_test
async def test_add_and_delete(tclient, basedn):
    """Test adding and deleting an LDAP entry."""
    async with tclient.connect(True) as conn:
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


@trio_test
async def test_recursive_delete(tclient, basedn):
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
        with (await tclient.connect(True)) as conn:
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


@trio_test
async def test_modify_and_rename(tclient, basedn):
    """Test modifying and renaming LDAP entry."""
    async with tclient.connect(True) as conn:
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


@trio_test
async def test_obj_err(tclient, basedn):
    """Test object class violation error."""
    entry = LDAPEntry("cn=async_test,%s" % basedn)
    entry["cn"] = ["async_test"]
    with pytest.raises(bonsai.errors.ObjectClassViolation):
        async with tclient.connect(True) as conn:
            await conn.add(entry)


@trio_test
async def test_whoami(tclient):
    """Test whoami."""
    async with tclient.connect(True) as conn:
        cfg = get_config()
        obj = await conn.whoami()
        expected_res = [
            "dn:%s" % cfg["SIMPLEAUTH"]["user"],
            cfg["SIMPLEAUTH"]["adusername"],
        ]
        assert obj in expected_res


@pytest.mark.timeout(18)
@trio_test
async def test_connection_timeout(tclient):
    """Test connection timeout."""
    with network_delay(6.0):
        with pytest.raises(bonsai.errors.TimeoutError):
            await tclient.connect(True, timeout=8.0)


@pytest.mark.timeout(18)
@trio_test
async def test_search_timeout(tclient):
    """Test search timeout."""
    async with tclient.connect(True) as conn:
        with network_delay(5.1):
            with pytest.raises(bonsai.errors.TimeoutError):
                await conn.search(timeout=4.0)


@trio_test
async def test_paged_search(tclient, basedn):
    """Test paged results control."""
    tclient.auto_page_acquire = False
    search_dn = "ou=nerdherd,%s" % basedn
    async with tclient.connect(True) as conn:
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


@trio_test
async def test_paged_search_with_auto_acq(tclient, basedn):
    """Test paged search with auto page acquiring."""
    search_dn = "ou=nerdherd,%s" % basedn
    async with tclient.connect(True) as conn:
        cnt = 0
        result = await conn.paged_search(search_dn, 1, page_size=3)
        async for item in result:
            assert isinstance(item, LDAPEntry)
            cnt += 1
        assert cnt == 6


@trio_test
async def test_async_with(tclient):
    """Test async with context manager (with backward compatibility)."""
    mgr = tclient.connect(True)
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
