import os.path
import sys

import pytest

from bonsai import LDAPClient
from bonsai import LDAPEntry
from bonsai import LDAPModOp
from bonsai import LDAPDN
import bonsai.errors
from bonsai.errors import AuthenticationError, InvalidDN
from bonsai.active_directory import UserAccountControl


@pytest.fixture
def test_entry():
    """Create a test LDAP entry."""
    gconn = None
    entry = None

    def _create_entry(conn, dname):
        nonlocal gconn
        nonlocal entry
        entry = LDAPEntry(dname)
        entry["objectclass"] = [
            "top",
            "inetOrgPerson",
            "person",
            "organizationalPerson",
        ]
        entry["sn"] = "test"
        gconn = conn
        try:
            conn.add(entry)
        except bonsai.AlreadyExists:
            conn.delete(entry.dn)
            conn.add(entry)
        return entry

    yield _create_entry

    if gconn.closed:
        gconn = gconn.open()
    gconn.delete(entry.dn)
    gconn.close()


@pytest.fixture
def test_ad_user():
    """Create a test AD user."""
    gconn = None
    entry = None

    def _create_entry(conn, dname, password):
        nonlocal gconn
        nonlocal entry
        entry = LDAPEntry(dname)
        entry["objectclass"] = [
            "top",
            "inetOrgPerson",
            "person",
            "organizationalPerson",
            "user",
        ]
        entry["sn"] = "ad_user"
        entry["cn"] = "ad_user"
        entry["givenName"] = "AD"
        entry["userPrincipalName"] = "ad_user"
        entry["displayName"] = "ad_user"
        entry["sAMAccountName"] = "ad_user"
        entry["userPassword"] = password
        entry["mail"] = "ad_user@bonsai.test"
        gconn = conn
        try:
            conn.add(entry)
        except bonsai.AlreadyExists:
            conn.delete(entry.dn)
            conn.add(entry)
        return entry

    yield _create_entry

    if gconn.closed:
        gconn = gconn.open()
    gconn.delete(entry.dn)
    gconn.close()


def test_set_get():
    """Test LDAPEntry's SetItem, GetItem and get methods."""
    entry = LDAPEntry("cn=test")
    entry["sn"] = "Test"
    assert entry == {"dn": LDAPDN("cn=test"), "sn": ["Test"]}
    entry["givenname"] = "Test"
    assert entry.get("None") is None
    assert entry.get("GivenName") == entry["givenNAME"]
    del entry["sn"]
    with pytest.raises(KeyError):
        _ = entry["sn"]


def test_append_extend():
    """Test append and extend methods of LDAPEntry's attribute."""
    entry = LDAPEntry("cn=test")
    entry["givenName"] = "test"
    entry["givenname"].append("test2")
    assert entry["givenname"] == ["test", "test2"]
    assert entry["givenname"][0] == "test"
    with pytest.raises(ValueError):
        entry["GivenName"].extend(["teSt", "test3"])


def test_pop():
    """Test LDAPEntry's pop method."""
    entry = LDAPEntry("cn=test")
    entry["test"] = "test"
    with pytest.raises(TypeError):
        _ = entry.pop()
    with pytest.raises(TypeError):
        _ = entry.pop("t", 2, 3)
    with pytest.raises(KeyError):
        _ = entry.pop("t")
    assert entry.pop("test") == ["test"]
    assert entry.pop("test", None) is None


def test_popitem():
    """Test LDAPEntry's popitem method."""
    entry = LDAPEntry("cn=test")
    entry["test"] = "test"
    entry["test2"] = "test"
    item = entry.popitem()
    assert len(item) == 2
    assert item[0] not in entry
    entry[item[0]] = item[1]
    assert entry[item[0]] == item[1]


def test_popitem_empty():
    """Test LDAPEntry's popitem raises KeyError if it is empty."""
    entry = LDAPEntry("cn=test")
    with pytest.raises(KeyError):
        _ = entry.popitem()


def test_clear():
    """Test LDAPEntry's clear method."""
    entry = LDAPEntry("cn=test")
    entry["sn"] = ["test1", "test2"]
    entry["gn"] = ["test3"]
    entry.clear()
    assert entry == {"dn": LDAPDN("cn=test")}
    assert entry.dn == "cn=test"


def test_items():
    """Test LDAPEntry's items method."""
    entry = LDAPEntry("cn=test")
    entry["cn"] = "test"
    entry["sn"] = "Test"
    assert len(entry.items()) == 3
    assert ("dn", entry.dn) in entry.items()
    assert ("cn", entry["cn"]) in entry.items()
    assert ("sn", entry["sn"]) in entry.items()
    assert len(list(entry.items(exclude_dn=True))) == 2
    assert ("dn", entry.dn) not in entry.items(exclude_dn=True)
    assert ("cn", entry["cn"]) in entry.items(exclude_dn=True)
    assert ("sn", entry["sn"]) in entry.items(exclude_dn=True)


def test_keys():
    """Test LDAPEntry's keys method."""
    entry = LDAPEntry("cn=test")
    entry["cn"] = "test"
    entry["sn"] = "Test"
    assert set(entry.keys()) == set(["dn", "cn", "sn"])
    assert set(entry.keys(exclude_dn=True)) == set(["cn", "sn"])


def test_values():
    """Test LDAPEntry's values method."""
    entry = LDAPEntry("cn=test")
    entry["cn"] = "test"
    entry["sn"] = "Test"
    assert len(entry.values()) == 3
    assert entry.dn in entry.values()
    assert entry["cn"] in entry.values()
    assert entry["sn"] in entry.values()
    assert len(list(entry.values(exclude_dn=True))) == 2
    assert entry.dn not in entry.values(exclude_dn=True)
    assert entry["cn"] in entry.values(exclude_dn=True)
    assert entry["sn"] in entry.values(exclude_dn=True)


def test_update():
    """Test updating LDAPEntry object."""
    entry = LDAPEntry("cn=test")
    entry.update({"GivenName": "test2", "mail": "test@mail"})
    entry.update([("sn", "test")])
    with pytest.raises(ValueError):
        entry.update([("sn", "test", 1)])
    entry.update(uidnumber=1, gidnumber=1)
    assert entry["mail"] == ["test@mail"]
    assert entry["givenname"] == ["test2"]
    assert entry["sn"][0] == "test"
    assert entry["uidnumber"] == [1]
    assert entry["gidnumber"] == [1]


def test_equal():
    """Test equality check."""
    entry1 = LDAPEntry("cn=test")
    entry2 = LDAPEntry("cn=test")
    entry3 = LDAPEntry("cn=test1")
    assert entry1 == entry2
    assert not (entry1 == entry3)
    assert entry1 == {"dn": LDAPDN("cn=test")}
    assert not (entry1 == 2)


def test_special_char(client, basedn):
    """Test adding entry with special character in its DN."""
    with client.connect() as conn:
        entry = LDAPEntry(r"cn=test\, *\+withspec,%s" % basedn)
        entry["objectclass"] = ["top", "inetOrgPerson"]
        entry["sn"] = "Test,*special"
        conn.add(entry)
        result = conn.search(basedn, 1)
        entry.delete()
        assert entry.dn in [res.dn for res in result]


def test_dn_with_space(client, basedn):
    """Test adding entry with DN that has a space in it."""
    with client.connect() as conn:
        entry = LDAPEntry("cn=test, %s" % basedn)
        entry["objectclass"] = ["top", "inetOrgPerson"]
        entry["sn"] = "Test with space"
        conn.add(entry)
        result = conn.search(basedn, 1)
        entry.delete()
        assert " " in str(entry.dn)
        assert entry.dn.rdns[0][0][1] in [res.dn.rdns[0][0][1] for res in result]


def test_unicode(client, basedn):
    """Test adding entry with special character in its DN."""
    with client.connect() as conn:
        dname = "cn=test_µčབྷñ,%s" % basedn
        entry = LDAPEntry(dname)
        entry["objectclass"] = ["top", "inetOrgPerson"]
        entry["sn"] = "unicode_µčབྷñ"
        conn.add(entry)
        result = conn.search(dname, 0)
        entry.delete()
        assert dname in [res.dn for res in result]


def test_binary(client, basedn):
    """Test adding binary data."""
    curdir = os.path.abspath(os.path.dirname(__file__))
    conn = client.connect()
    dname = "cn=binary,%s" % basedn
    entry = LDAPEntry(dname)
    entry["objectclass"] = ["top", "inetOrgPerson"]
    entry["sn"] = "binary_test"
    with open("%s/testenv/test.jpeg" % curdir, "rb") as image:
        entry["jpegPhoto"] = image.read()
    conn.add(entry)
    result = conn.search(dname, 0)
    entry.delete()
    conn.close()
    assert "jpegPhoto" in result[0].keys()
    assert result[0]["jpegphoto"][0] == entry["jpegphoto"][0]


def test_connection(client, basedn):
    """Test set and get connection object from LDAPEntry."""
    entry = LDAPEntry("cn=test,%s" % basedn)
    with pytest.raises(ValueError):
        _ = entry.connection
    conn = client.connect()
    entry.connection = conn
    assert entry.connection == conn
    with pytest.raises(TypeError):
        entry.connection = "string"
    with pytest.raises(TypeError):
        del entry.connection


def test_rename(client, basedn, test_entry):
    """Test LDAPEntry's rename LDAP operation."""
    with client.connect() as conn:
        entry = test_entry(conn, "cn=test,%s" % basedn)
        entry.rename("cn=test2,%s" % basedn)
        assert str(entry.dn) == "cn=test2,%s" % basedn
        obj = conn.search("cn=test,%s" % basedn, 0)
        assert obj == []
        obj = conn.search("cn=test2,%s" % basedn, 0)[0]
        assert entry.dn == obj.dn


@pytest.mark.skipif(
    sys.platform.startswith("win"), reason="Cannot rename entry with old RDN on Windows"
)
def test_rename_with_old_rdn(client, basedn, test_entry):
    """Test LDAPEntry's rename LDAP operation."""
    with client.connect() as conn:
        entry = test_entry(conn, "cn=test,%s" % basedn)
        entry.rename("uid=test2,%s" % basedn, delete_old_rdn=False)
        assert str(entry.dn) == "uid=test2,%s" % basedn
        obj = conn.search("cn=test,%s" % basedn, 0)
        assert obj == []
        obj = conn.search("uid=test2,%s" % basedn, 0)[0]
        assert entry.dn == obj.dn
        assert "test2" in obj["uid"]
        assert "test" in obj["cn"]


def test_rename_error(client, basedn, test_entry):
    """Test LDAPEntry's rename error handling."""
    dname = bonsai.LDAPDN("cn=test,%s" % basedn)
    entry = LDAPEntry(dname)
    with pytest.raises(ValueError):
        entry.rename("cn=test2")
    with client.connect() as conn:
        entry = test_entry(conn, dname)
        with pytest.raises(TypeError):
            entry.rename(0)
        with pytest.raises(TypeError):
            entry.rename(0, delete_old_rdn=0)
        try:
            newdn = bonsai.LDAPDN("cn=test2,ou=invalid,%s" % basedn)
            entry.rename(newdn)
        except bonsai.LDAPError:
            assert entry.dn == dname
    with pytest.raises(bonsai.errors.ClosedConnection):
        entry.rename("cn=test2")


def test_sync_operations(client, basedn):
    """
    Test LDAPEntry's add, modify and delete synchronous operations.
    """
    entry = LDAPEntry("cn=test,%s" % basedn)
    with pytest.raises(ValueError):
        entry.modify()
    with client.connect() as conn:
        entry["sn"] = "test"
        with pytest.raises(bonsai.ObjectClassViolation):
            conn.add(entry)
        entry["objectclass"] = [
            "top",
            "inetOrgPerson",
            "person",
            "organizationalPerson",
        ]
        try:
            conn.add(entry)
        except bonsai.AlreadyExists:
            conn.delete(entry.dn)
            conn.add(entry)
        except:
            pytest.fail("Adding LDAPEntry to the server is failed.")
        entry["sn"] = "Test_modify"
        try:
            entry.modify()
        except:
            pytest.fail("Modify failed.")
        obj = conn.search("cn=test,%s" % basedn, 0)[0]
        assert entry["sn"] == obj["sn"]
        try:
            entry.delete()
        except:
            pytest.fail("Delete failed.")
    with pytest.raises(bonsai.errors.ClosedConnection):
        entry.modify()


def test_dn_attr(basedn):
    """Test LDAPEntry's DN attribute."""
    entry = LDAPEntry("cn=test,%s" % basedn)
    entry.dn = "cn=test"
    assert str(entry.dn) == "cn=test"
    with pytest.raises(TypeError):
        del entry.dn
    with pytest.raises(TypeError):
        entry["dn"] = 5


def test_wrong_params():
    """Test passing wrong params to LDAPEntry."""
    with pytest.raises(TypeError):
        _ = LDAPEntry("", 1)
    with pytest.raises(InvalidDN):
        _ = LDAPEntry("5", 1)


@pytest.mark.skipif(
    sys.platform.startswith("win"), reason="Cannot use password policy on Windows"
)
def test_password_modify(client):
    """
    Test modifying password with simple modify operation and
    password policy.
    """
    cli = LDAPClient(client.url)
    user_dn = "cn=jeff,ou=nerdherd,dc=bonsai,dc=test"
    cli.set_password_policy(True)
    cli.set_credentials("SIMPLE", user_dn, "p@ssword")
    conn, _ = cli.connect()
    entry = conn.search(user_dn, 0)[0]
    try:
        entry["userPassword"] = "newpassword"
        entry.modify()
    except Exception as exc:
        assert isinstance(exc, bonsai.errors.PasswordModNotAllowed)
    user_dn = "cn=skip,ou=nerdherd,dc=bonsai,dc=test"
    cli.set_credentials("SIMPLE", user_dn, "p@ssword")
    conn, _ = cli.connect()
    entry = conn.search(user_dn, 0)[0]
    try:
        entry["userPassword"] = "short"
        entry.modify()
    except Exception as exc:
        assert isinstance(exc, bonsai.errors.PasswordTooShort)
    try:
        entry["userPassword"] = "p@ssword"
        entry.modify()
    except Exception as exc:
        assert isinstance(exc, bonsai.errors.PasswordInHistory)


def test_extended_dn_attr():
    """Test that extended dn attribute is read only."""
    entry = LDAPEntry("cn=test")
    with pytest.raises(AttributeError):
        entry.extended_dn = "cn=test2"


def test_change_attribute(client):
    """Test change_attribute method."""
    user_dn = "cn=sam,ou=nerdherd,dc=bonsai,dc=test"
    if sys.platform == "win32":
        multiattr = "otherTelephone"
    else:
        multiattr = "mail"
    with client.connect() as conn:
        entry = LDAPEntry(user_dn, conn)
        entry.change_attribute("mail", LDAPModOp.ADD, "sam@bonsai.test")
        assert entry["mail"].status == 1
        entry.modify()
        assert conn.search(user_dn, 0)[0]["mail"][0] == "sam@bonsai.test"
        entry.change_attribute("mail", 1, "sam@bonsai.test")
        assert entry["mail"].status == 1
        entry.modify()
        with pytest.raises(KeyError):
            _ = conn.search(user_dn, 0)[0]["mail"]
        entry.change_attribute(
            multiattr, LDAPModOp.REPLACE, "sam@bonsai.test", "x@bonsai.test"
        )
        assert entry[multiattr].status == 2
        entry.modify()
        res = conn.search(user_dn, 0)[0][multiattr]
        assert "sam@bonsai.test" in res
        assert "x@bonsai.test" in res
        entry.change_attribute(multiattr, 1, "x@bonsai.test")
        entry.change_attribute(multiattr, 0, "sam2@bonsai.test")
        entry.modify()
        res = conn.search(user_dn, 0)[0][multiattr]
        assert "sam@bonsai.test" in res
        assert "sam2@bonsai.test" in res
        entry.change_attribute(multiattr, 1)
        entry.modify()
        assert multiattr not in conn.search(user_dn, 0)[0].keys()


def test_change_attribute_error(client):
    """Test change_attribute method's error handling."""
    user_dn = "cn=sam,ou=nerdherd,dc=bonsai,dc=test"
    with client.connect() as conn:
        entry = LDAPEntry(user_dn, conn)
        with pytest.raises(ValueError):
            entry.change_attribute("mail", 4, "t")
        entry.change_attribute("sn", 0, "Lembeck")
        with pytest.raises(bonsai.TypeOrValueExists):
            entry.modify()
        entry.clear_attribute_changes("sn")
        entry.change_attribute("description", LDAPModOp.DELETE, "sam")
        with pytest.raises(bonsai.NoSuchAttribute):
            entry.modify()


def test_clear_attribute_changes():
    """Test clear_attribute_changes method."""
    user_dn = "cn=sam,ou=nerdherd,dc=bonsai,dc=test"
    entry = LDAPEntry(user_dn)
    entry.change_attribute("uidNumber", 0, 4)
    assert entry["uidNumber"].added == [4]
    entry.change_attribute("uidNumber", 1, 4)
    assert entry["uidNumber"].deleted == [4]
    entry.clear_attribute_changes("uidNumber")
    assert entry["uidNumber"].status == 0
    assert entry["uidNumber"].added == []
    assert entry["uidNumber"].deleted == []


@pytest.mark.skipif(
    sys.platform.startswith("win"), reason="Cannot use ManageDsaIT on Windows"
)
def test_modify_referrals(client):
    """Test modifying an LDAP referral with ManageDdsIT control."""
    refdn = bonsai.LDAPDN("o=invalid-ref,ou=nerdherd-refs,dc=bonsai,dc=test")
    newref = "ldap://invalid.host/cn=nobody"
    cli = LDAPClient(client.url)
    cli.set_credentials(client.mechanism, **client.credentials)
    cli.managedsait = True
    with cli.connect() as conn:
        entry = LDAPEntry(refdn, conn)
        entry.change_attribute("ref", LDAPModOp.ADD, newref)
        entry.modify()
        res = conn.search(refdn, 0, attrlist=["ref"])[0]
        assert len(res["ref"]) == 3
        assert newref in res["ref"]
        entry.change_attribute("ref", LDAPModOp.DELETE, newref)
        entry.modify()


@pytest.mark.skipif(
    not sys.platform.startswith("win"),
    reason="Makes sense when the remote server is an Active Directory",
)
def test_create_ad_user(cfg, basedn, test_ad_user):
    """Test creating and enabling an AD user ."""
    url = "ldap://%s:%s/%s??%s" % (
        cfg["SERVER"]["hostname"],
        cfg["SERVER"]["port"],
        cfg["SERVER"]["basedn"],
        cfg["SERVER"]["search_scope"],
    )
    cli = LDAPClient(url, tls=True)
    cli.set_ca_cert("./tests/testenv/certs/cacert.pem")
    cli.set_credentials(
        "SIMPLE", user=cfg["SIMPLEAUTH"]["user"], password=cfg["SIMPLEAUTH"]["password"]
    )
    ad_user_dn = "cn=ad_user,%s" % basedn
    password = "C0mpleX_P4ssW0rd"
    with cli.connect() as conn:
        entry = test_ad_user(conn, ad_user_dn, password)
        res = conn.search(entry.dn, 0)
        assert res
        uac = UserAccountControl(res[0]["userAccountControl"][0])
        assert uac.value != 66048
        assert uac.properties["accountdisable"]
        user_cli = LDAPClient(url, tls=True)
        user_cli.set_credentials("SIMPLE", ad_user_dn, password)
        with pytest.raises(AuthenticationError):
            _ = user_cli.connect()
        entry.change_attribute("userAccountControl", LDAPModOp.REPLACE, 66048)
        entry.modify()
        with user_cli.connect() as uconn:
            res = uconn.search(entry.dn, 0)
            assert not UserAccountControl(res[0]["userAccountControl"][0]).properties[
                "accountdisable"
            ]
            assert uconn.whoami() == "u:BONSAI\\ad_user"
