import os
import sys
import subprocess
import tempfile
import time

import pytest
from conftest import get_config, network_delay

import bonsai
from bonsai import LDAPDN
from bonsai import LDAPClient
from bonsai import LDAPConnection
from bonsai import LDAPSearchScope
import bonsai.errors
from bonsai.errors import ClosedConnection, SizeLimitError
from bonsai.ldapconnection import BaseLDAPConnection


class SimpleAsyncConn(BaseLDAPConnection):
    def __init__(self, client):
        super().__init__(client, True)

    def _evaluate(self, msg_id, timeout=None):
        return msg_id


@pytest.fixture(scope="module")
def ipaddr():
    """Get IP address."""
    cfg = get_config()
    return cfg["SERVER"]["hostip"]


@pytest.fixture(scope="module")
def ktpath():
    """Get keytab file path."""
    cfg = get_config()
    proj_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
    ktpath = os.path.abspath(os.path.join(proj_dir, cfg["GSSAPIAUTH"]["keytab"]))
    return ktpath


@pytest.fixture
def binding():
    """Create a binding with the server."""

    def _create_binding(auth, mech, authzid=None, realm=None):
        cfg = get_config()
        host = "ldap://%s" % cfg["SERVER"]["hostname"]
        client = LDAPClient(host)
        client.set_credentials(
            mech, cfg[auth]["user"], cfg[auth]["password"], realm, authzid
        )
        return client.connect()

    return _create_binding


@pytest.fixture
def kinit():
    def _create_kinit(authzid=None):
        try:
            cfg = get_config()
            user = cfg["GSSAPIAUTH"]["user"]
            password = cfg["GSSAPIAUTH"]["password"]
            proc = subprocess.Popen(
                ["kinit", "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
            )
            output = " ".join(proc.communicate())
            if "Heimdal" in output:
                # Heimdal Kerberos implementation.
                with tempfile.NamedTemporaryFile() as psw_tmp:
                    psw_tmp.write(password.encode())
                    psw_tmp.flush()
                    cmd = ["kinit", "--password-file=%s" % psw_tmp.name, user]
                    subprocess.check_call(cmd)
            else:
                # MIT Kerberos implementation.
                cmd = 'echo "%s" | kinit %s' % (password, user)
                subprocess.check_output(cmd, shell=True)
            host = "ldap://%s" % cfg["SERVER"]["hostname"]
            client = LDAPClient(host)
            client.set_credentials(
                "GSSAPI",
                cfg["GSSAPIAUTH"]["user"],
                cfg["GSSAPIAUTH"]["password"],
                None,
                authzid,
            )
            return client.connect()
        except subprocess.CalledProcessError:
            pytest.fail("Receiving TGT is failed.")

    yield _create_kinit
    subprocess.call("kdestroy")


@pytest.fixture
def large_org():
    """Create a heavily populated organization LDAP entry."""
    gconn = None
    entry = None
    gnum = None

    def _create_org(conn, org_dn, entry_num):
        nonlocal gconn
        nonlocal entry
        nonlocal gnum
        entry = bonsai.LDAPEntry(org_dn)
        entry["objectclass"] = ["top", "organizationalUnit"]
        entry["ou"] = entry.dn.rdns[0][0][1]
        gconn = conn
        gnum = entry_num
        try:
            conn.add(entry)
        except bonsai.AlreadyExists:
            conn.delete(entry.dn, recursive=True)
            conn.add(entry)
        for idx in range(entry_num):
            item = bonsai.LDAPEntry(f"cn=test_{idx},{entry.dn}")
            item["objectclass"] = [
                "top",
                "inetOrgPerson",
                "person",
                "organizationalPerson",
            ]
            item["sn"] = f"test_{idx}"
            conn.add(item)
        return entry

    yield _create_org

    if gconn.closed:
        gconn = gconn.open()
    for idx in range(gnum):
        # Delete entries one by one to avoid Administration Limit Exceeded with AD.
        item = bonsai.LDAPEntry(f"cn=test_{idx},{entry.dn}")
        gconn.delete(item.dn)
    gconn.delete(entry.dn, recursive=True)
    gconn.close()


@pytest.fixture
def external_binding():
    """Create a binding using external mechanism."""

    def _create_external(authzid=None):
        tls_impl = bonsai.get_tls_impl_name()
        if tls_impl == "GnuTLS" or tls_impl == "OpenSSL":
            cfg = get_config()
            curdir = os.path.abspath(os.path.dirname(__file__))
            cert_path = os.path.join(curdir, "testenv", "certs")
            host = "ldap://%s" % cfg["SERVER"]["hostname"]
            cli = LDAPClient(host, tls=True)
            cli.set_ca_cert(cert_path + "/cacert.pem")
            cli.set_client_cert(cert_path + "/client.pem")
            cli.set_client_key(cert_path + "/client.key")
            cli.set_credentials("EXTERNAL", authz_id=authzid)
            return cli.connect()
        else:
            pytest.skip("")

    return _create_external


def _generate_client(cfg):
    srv = cfg["SERVER"]
    url = f"ldap://{srv['hostip']}:{srv['port']}/ou=nerdherd,{srv['basedn']}?{srv['search_attr']}?{srv['search_scope']}"
    client = LDAPClient(url)
    client.set_credentials(
        "SIMPLE", user=cfg["SIMPLEAUTH"]["user"], password=cfg["SIMPLEAUTH"]["password"]
    )
    client.auto_page_acquire = False
    return client


@pytest.fixture
def conn():
    """Create a connection."""
    cfg = get_config()
    client = _generate_client(cfg)
    return client.connect()


@pytest.fixture
def anonym_conn():
    """Create a connection with anonymous user."""
    cfg = get_config()
    client = _generate_client(cfg)
    client.set_credentials("SIMPLE")
    return client.connect()


@pytest.fixture
def async_conn():
    cfg = get_config()
    client = _generate_client(cfg)
    return SimpleAsyncConn(client)


def test_bind_digest(binding):
    """Test DIGEST-MD5 connection."""
    with binding("DIGESTAUTH", "DIGEST-MD5") as conn:
        assert "anonymous" != conn.whoami()


@pytest.mark.skipif(
    sys.platform.startswith("win") or get_config()["DIGESTAUTH"]["authzid"] == "None",
    reason="Authzid is not set",
)
def test_bind_digest_with_authzid(binding, cfg):
    """Test DIGEST-MD5 connection with authorization ID."""
    authzid = cfg["DIGESTAUTH"]["authzid"]
    with binding("DIGESTAUTH", "DIGEST-MD5", authzid) as conn:
        assert cfg["DIGESTAUTH"]["dn"] == conn.whoami()


@pytest.mark.skipif(
    sys.platform.startswith("win"), reason="NTLM is not enabled on Windows."
)
def test_bind_ntlm(binding):
    """Test NTLM connection."""
    with binding("NTLMAUTH", "NTLM") as conn:
        assert "anonymous" != conn.whoami()


@pytest.mark.skipif(
    sys.platform == "darwin", reason="SCRAM is not supported on clients on Mac."
)
def test_bind_not_supported_auth(binding):
    """Test not supported authentication mechanism by the server."""
    with pytest.raises(bonsai.AuthMethodNotSupported):
        _ = binding("DIGESTAUTH", "SCRAM-SHA-1")


@pytest.mark.skipif(
    sys.platform.startswith("win"), reason="Kinit is unavailable on Windows."
)
def test_bind_gssapi_kinit(kinit):
    """Test GSSAPI connection."""
    with kinit() as conn:
        assert "anonymous" != conn.whoami()


@pytest.mark.skipif(
    sys.platform.startswith("win"), reason="Kinit is unavailable on Windows."
)
def test_bind_gssapi_with_authzid_kinit(kinit, cfg):
    """Test GSSAPI connection with authorization ID."""
    authzid = cfg["GSSAPIAUTH"]["authzid"]
    with kinit(authzid) as conn:
        assert cfg["GSSAPIAUTH"]["dn"] == conn.whoami()


@pytest.mark.skipif(
    not bonsai.has_krb5_support() or sys.platform == "darwin",
    reason="Module doesn't have KRB5 support.",
)
def test_bind_gssapi(binding, cfg):
    """Test GSSAPI connection with automatic TGT requesting."""
    with binding(
        "GSSAPIAUTH", "GSSAPI", None, cfg["GSSAPIAUTH"]["realm"].upper()
    ) as conn:
        assert "anonymous" != conn.whoami()


@pytest.mark.skipif(
    not bonsai.has_krb5_support() or sys.platform == "darwin",
    reason="Module doesn't have KRB5 support.",
)
def test_bind_gssapi_error(cfg):
    """Test automatic TGT requesting with wrong realm name."""
    client = _generate_client(cfg)
    client.set_credentials(
        "GSSAPI",
        cfg["GSSAPIAUTH"]["user"],
        cfg["GSSAPIAUTH"]["password"],
        cfg["GSSAPIAUTH"]["realm"],
        None,
    )
    with pytest.raises(bonsai.AuthenticationError):
        _ = client.connect()


@pytest.mark.skipif(
    not bonsai.has_krb5_support() or sys.platform != "linux",
    reason="Keytab-based auth only available on linux.",
)
def test_bind_gssapi_keytab_error(cfg, ktpath):
    client = LDAPClient("ldap://%s" % cfg["SERVER"]["hostname"])
    client.set_credentials(
        "GSSAPI",
        user=cfg["GSSAPIAUTH"]["user"],
        realm=cfg["GSSAPIAUTH"]["realm"].upper(),
        keytab="invalid",
    )
    with pytest.raises(bonsai.AuthenticationError):
        _ = client.connect()
    client.set_credentials(
        "GSSAPI",
        user="invalid",
        realm=cfg["GSSAPIAUTH"]["realm"].upper(),
        keytab=ktpath,
    )
    with pytest.raises(bonsai.AuthenticationError):
        _ = client.connect()


@pytest.mark.skipif(
    not bonsai.has_krb5_support() or sys.platform != "linux",
    reason="Keytab-based auth only available on linux.",
)
def test_bind_gssapi_keytab(cfg, ktpath):
    client = LDAPClient("ldap://%s" % cfg["SERVER"]["hostname"])
    client.set_credentials(
        "GSSAPI",
        user=cfg["GSSAPIAUTH"]["user"],
        realm=cfg["GSSAPIAUTH"]["realm"].upper(),
        keytab=ktpath,
    )
    conn = client.connect()
    assert conn.whoami() == "dn:cn=chuck,ou=nerdherd,dc=bonsai,dc=test"
    client.set_credentials(
        "GSSAPI", user="admin", realm=cfg["GSSAPIAUTH"]["realm"].upper(), keytab=ktpath
    )
    conn = client.connect()
    assert conn.whoami() == "dn:cn=admin,dc=bonsai,dc=test"


@pytest.mark.skipif(
    not sys.platform.startswith("win"),
    reason="No Windows logon credentials",
)
def test_bind_winlogon(cfg):
    """Test connection with Windows logon credentials"""
    expected_user = f"u:{os.getenv('userdomain')}\\{os.getlogin()}"
    client = LDAPClient("ldap://%s" % cfg["SERVER"]["hostname"])
    client.set_credentials("GSSAPI")
    with client.connect() as conn:
        assert conn.whoami() == expected_user
    client.set_credentials("GSS-SPNEGO")
    with client.connect() as conn:
        assert conn.whoami() == expected_user
    client.set_credentials("DIGEST-MD5")
    with pytest.raises(bonsai.AuthenticationError):
        _ = client.connect()


@pytest.mark.skipif(
    not sys.platform.startswith("win"), reason="No GSS-SPNEGO mech on Ubuntu and Mac"
)
def test_bind_spnego(binding, cfg):
    """Test GSS-SPNEGO connection with automatic TGT requesting."""
    with binding(
        "GSSAPIAUTH", "GSS-SPNEGO", None, cfg["GSSAPIAUTH"]["realm"].upper()
    ) as conn:
        assert "anonymous" != conn.whoami()


def test_bind_external(external_binding):
    """Test EXTERNAL connection."""
    with external_binding() as conn:
        assert "anonymous" != conn.whoami()


def test_bind_external_with_authzid(external_binding, cfg):
    """Test EXTERNAL connection with authorization ID."""
    authzid = cfg["EXTERNALAUTH"]["authzid"]
    with external_binding(authzid) as conn:
        assert cfg["EXTERNALAUTH"]["dn"] == conn.whoami()


def test_search(conn, basedn):
    """Test searching."""
    res = conn.search("ou=nerdherd,%s" % basedn, LDAPSearchScope.SUB)
    assert res is not None
    assert len(res) == len(conn.search())


def test_search_ldapdn(conn, basedn):
    """Test searching with LDAPDN object."""
    ldap_dn = LDAPDN(basedn)
    obj = conn.search(ldap_dn, 1)
    assert obj is not None


def test_search_attr(conn, basedn):
    """Test searching with given list of attributes."""
    obj = conn.search(basedn, 2, "(objectclass=person)", ["cn"])[0]
    assert obj is not None
    assert "cn" in obj.keys()


def test_search_attrsonly(conn, basedn):
    """Test search receiving only attributes."""
    obj = conn.search(basedn, 2, "(objectclass=person)", ["cn"], attrsonly=True)[0]
    assert obj is not None
    assert obj["cn"] == []


def test_add_and_delete(conn, basedn):
    """Test adding and removing an LDAP entry."""
    entry = bonsai.LDAPEntry("cn=example,%s" % basedn)
    entry.update(
        {"objectclass": ["top", "inetorgperson"], "cn": "example", "sn": "example"}
    )
    try:
        conn.add(entry)
        res = conn.search(entry.dn, 0)
        assert res[0] == entry
        conn.delete("cn=example,%s" % basedn)
        res = conn.search(entry.dn, 0)
        assert res == []
        with pytest.raises(ValueError):
            conn.add(bonsai.LDAPEntry(""))
    except bonsai.LDAPError:
        pytest.fail("Add and delete new entry is failed.")


def test_recursive_delete(conn, basedn):
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
        conn.add(org1)
        conn.add(org2)
        conn.add(entry)
        conn.delete(org1.dn, recursive=True)
        res = conn.search(org1.dn, 2)
        assert res == []
    except bonsai.LDAPError:
        pytest.fail("Recursive delete is failed.")


def test_whoami(conn, cfg):
    """Test whoami."""
    obj = conn.whoami()
    expected_res = [
        "dn:%s" % cfg["SIMPLEAUTH"]["user"],
        cfg["SIMPLEAUTH"]["adusername"],
    ]
    assert obj in expected_res


def test_connection_error():
    """Test connection error."""
    client = LDAPClient("ldap://invalid")
    with pytest.raises(bonsai.ConnectionError):
        _ = client.connect()


def test_simple_auth_error(cfg):
    """Test simple authentication error."""
    client = LDAPClient("ldap://%s" % cfg["SERVER"]["hostname"])
    client.set_credentials("SIMPLE", "cn=wrong", "wronger")
    with pytest.raises(bonsai.AuthenticationError):
        _ = client.connect()


def test_digest_auth_error(cfg):
    """Test DIGEST-MD5 authentication error."""
    client = LDAPClient("ldap://%s" % cfg["SERVER"]["hostname"])
    if cfg["DIGESTAUTH"]["realm"] == "None":
        realm = None
    else:
        realm = cfg["DIGESTAUTH"]["realm"].upper()
    client.set_credentials(
        "DIGEST-MD5", cfg["DIGESTAUTH"]["user"], "wrongpassword", realm, None
    )
    with pytest.raises(bonsai.AuthenticationError):
        _ = client.connect()


def test_sort_order(conn, basedn):
    """Test setting sort order."""
    obj = conn.search(basedn, 2, attrlist=["uidNumber"], sort_order=["-uidNumber"])
    sort = [o["uidNumber"][0] for o in obj if "uidNumber" in o]
    assert all(sort[i] >= sort[i + 1] for i in range(len(sort) - 1))


def test_fileno(conn, cfg):
    """Test fileno method."""
    assert isinstance(conn.fileno(), int)
    try:
        import socket

        sock = socket.fromfd(conn.fileno(), socket.AF_INET, socket.SOCK_RAW)
        assert sock.getpeername() == (
            cfg["SERVER"]["hostip"],
            int(cfg["SERVER"]["port"]),
        )
        sock.close()
    except OSError:
        pytest.fail("Not a valid socket descriptor.")


def test_close(conn):
    """Test close method."""
    conn.close()
    assert conn.closed
    with pytest.raises(bonsai.ClosedConnection):
        _ = conn.whoami()


def test_abandon(async_conn, basedn):
    """Test abandon method."""
    msgid = async_conn.open()
    while async_conn.get_result(msgid) is None:
        pass
    msgid = async_conn.search(basedn, 2)
    async_conn.abandon(msgid)
    with pytest.raises(bonsai.InvalidMessageID):
        _ = async_conn.get_result(msgid)


def test_async_close_remove_pendig_ops(async_conn, basedn):
    """Test remove pending operations after close."""
    msgid = async_conn.open()
    while async_conn.get_result(msgid) is None:
        pass
    async_conn.search(basedn, 2)
    async_conn.search(basedn, 0)
    async_conn.close()
    assert async_conn.closed


def test_vlv_offset(conn, basedn):
    """Test VLV control with offset."""
    search_dn = "ou=nerdherd,%s" % basedn
    res, ctrl = conn.virtual_list_search(
        search_dn,
        1,
        attrlist=["uidNumber"],
        offset=2,
        sort_order=["-uidNumber"],
        before_count=1,
        after_count=1,
        est_list_count=6,
    )
    assert len(res) == 3
    assert ctrl["target_position"] == 2
    assert ctrl["list_count"] == 6
    assert res[1]["uidNumber"][0] == 4


def test_vlv_attrvalue(conn, basedn):
    """Test VLV control with attribute value."""
    search_dn = "ou=nerdherd,%s" % basedn
    res, ctrl = conn.virtual_list_search(
        search_dn,
        1,
        attrlist=["uidNumber"],
        attrvalue=2,
        sort_order=["uidNumber"],
        before_count=1,
        after_count=2,
        est_list_count=6,
    )
    assert len(res) == 4
    assert ctrl["target_position"] == 3
    assert res[0]["uidNumber"][0] == 1


def test_vlv_without_sort_order(conn, basedn):
    """Test VLV control without sort control."""
    search_dn = "ou=nerdherd,%s" % basedn
    with pytest.raises(bonsai.UnwillingToPerform):
        _ = conn.virtual_list_search(
            search_dn,
            1,
            attrlist=["uidNumber"],
            offset=1,
            before_count=1,
            after_count=2,
            est_list_count=6,
        )


def test_paged_search(conn, basedn):
    """Test paged results control."""
    search_dn = "ou=nerdherd,%s" % basedn
    res = conn.paged_search(search_dn, 1, page_size=2)
    for ent in res:
        assert isinstance(ent, bonsai.LDAPEntry)
    page = 1  # First page is already acquired.
    while True:
        if len(res) > 2:
            pytest.fail("The size of the page is greater than expected.")
        msgid = res.acquire_next_page()
        if msgid is None:
            break
        res = conn.get_result(msgid)
        page += 1
    assert page == 3


def test_paged_search_with_auto_acq(cfg, basedn):
    """Test paged results control with automatic page acquiring."""
    client = LDAPClient("ldap://%s" % cfg["SERVER"]["hostname"])
    conn = client.connect()
    search_dn = "ou=nerdherd,%s" % basedn
    res = conn.paged_search(search_dn, 1, page_size=3)
    if len(res) != 3:
        pytest.fail("The size of the page is not what is expected.")
    entry = 0
    for ent in res:
        assert isinstance(ent, bonsai.LDAPEntry)
        entry += 1
    assert entry == 6
    assert res.acquire_next_page() is None


@pytest.mark.timeout(15)
def test_search_timeout(conn, basedn):
    """Test search method's timeout."""
    search_dn = "ou=nerdherd,%s" % basedn
    with pytest.raises(TypeError):
        _ = conn.search(search_dn, 1, timeout=True)
    with pytest.raises(ValueError):
        _ = conn.search(search_dn, 1, timeout=-15)
    with network_delay(6.1):
        with pytest.raises(bonsai.TimeoutError):
            _ = conn.search(search_dn, 1, timeout=3.0)


@pytest.mark.timeout(10)
def test_whoami_timeout(conn):
    """Test whoami's timeout."""
    with pytest.raises(TypeError):
        _ = conn.whoami(timeout="A")
    with pytest.raises(ValueError):
        _ = conn.whoami(timeout=-10)
    with pytest.raises(bonsai.TimeoutError):
        _ = conn.whoami(timeout=0)
    with network_delay(6.1):
        with pytest.raises(bonsai.TimeoutError):
            _ = conn.whoami(timeout=3.2)


def test_wrong_conn_param():
    """Test passing wrong parameters for LDAPConnection."""
    with pytest.raises(TypeError):
        _ = LDAPConnection("wrong")
    with pytest.raises(TypeError):
        _ = LDAPConnection(1)


def test_wrong_search_param(ipaddr):
    """Test passing wrong parameters for search method."""
    with pytest.raises(ClosedConnection):
        cli = LDAPClient("ldap://%s" % ipaddr)
        LDAPConnection(cli).search()
    with pytest.raises(ValueError):
        cli = LDAPClient("ldap://%s" % ipaddr)
        LDAPConnection(cli).open().search()
    with pytest.raises(TypeError):
        cli = LDAPClient("ldap://%s" % ipaddr)
        LDAPConnection(cli).open().search("", 0, 3)


def test_wrong_add_param(conn, ipaddr):
    """Test passing wrong parameter for add method."""
    with pytest.raises(ClosedConnection):
        cli = LDAPClient("ldap://%s" % ipaddr)
        LDAPConnection(cli).add(bonsai.LDAPEntry("cn=dummy"))
    with pytest.raises(TypeError):
        conn.add("wrong")


def test_wrong_delete_param(conn, ipaddr):
    """Test passing wrong parameter for delete method."""
    with pytest.raises(ClosedConnection):
        cli = LDAPClient("ldap://%s" % ipaddr)
        LDAPConnection(cli).delete("cn=dummy")
    with pytest.raises(TypeError):
        conn.delete(0)


@pytest.mark.skipif(
    sys.platform == "win32", reason="Cannot use password policy on Windows."
)
def test_password_lockout(conn, ipaddr):
    """Test password locking with password policy."""
    user_dn = "cn=jeff,ou=nerdherd,dc=bonsai,dc=test"
    cli = LDAPClient("ldap://%s" % ipaddr)
    cli.set_password_policy(True)
    try:
        cli.set_credentials("SIMPLE", user_dn, "wrong_pass")
        test_conn, ctrl = cli.connect()
    except bonsai.errors.AuthenticationError:
        with pytest.raises(bonsai.errors.AccountLocked):
            cli.set_credentials("SIMPLE", user_dn, "p@ssword")
            test_conn, ctrl = cli.connect()
    finally:
        entry = conn.search(user_dn, 0, attrlist=["pwdAccountLockedTime"])[0]
        if "pwdAccountLockedTime" in entry.keys():
            del entry["pwdAccountLockedTime"]
            entry.modify()


@pytest.mark.skipif(
    sys.platform.startswith("win"), reason="Cannot use password policy on Windows."
)
def test_password_expire(conn, ipaddr):
    """Test password expiring with password policy."""
    user_dn = "cn=skip,ou=nerdherd,dc=bonsai,dc=test"
    cli = LDAPClient("ldap://%s" % ipaddr)
    cli.set_password_policy(True)
    cli.set_credentials("SIMPLE", user_dn, "p@ssword")
    test_conn, ctrl = cli.connect()
    entry = test_conn.search(user_dn, 0)[0]
    entry["userPassword"] = "newvalidpassword"
    entry.modify()
    test_conn.close()
    cli.set_credentials("SIMPLE", user_dn, "newvalidpassword")
    time.sleep(2.0)
    test_conn, ctrl = cli.connect()
    if not (ctrl["expire"] <= 10 and ctrl["expire"] > 0):
        pytest.fail("Expire time is in the wrong range (Expire: %d)." % ctrl["expire"])
    test_conn.close()
    time.sleep(10)
    test_conn, ctrl = cli.connect()
    assert ctrl["grace"] == 1
    test_conn.close()
    with pytest.raises(bonsai.errors.PasswordExpired):
        test_conn, ctrl = cli.connect()
    entry = conn.search(user_dn, 0, attrlist=["userPassword"])[0]
    entry["userPassword"] = "p@ssword"
    entry.modify()
    entry = conn.search(user_dn, 0, attrlist=["pwdChangeTime", "pwdGraceUseTime"])[0]
    if ("pwdChangeTime", "pwdGraceUseTime") in entry.keys():
        del entry["pwdChangeTime"]
        del entry["pwdGraceUseTime"]
        entry.modify()


@pytest.mark.skipif(
    sys.platform.startswith("win"),
    reason="Cannot use password modify extended operation on Windows.",
)
def test_password_modify_extop(conn, ipaddr):
    """Test Password Modify extended operation."""
    user_dn = LDAPDN("cn=skip,ou=nerdherd,dc=bonsai,dc=test")
    cli = LDAPClient("ldap://%s" % ipaddr)
    cli.set_credentials("SIMPLE", str(user_dn), "p@ssword")
    test_conn = cli.connect()
    with pytest.raises(TypeError):
        test_conn.modify_password(new_password=0)
    test_conn.modify_password(user_dn, "newpassword", "p@ssword")
    test_conn.close()
    with pytest.raises(ClosedConnection):
        test_conn.modify_password()
    try:
        cli.set_credentials("SIMPLE", str(user_dn), "newpassword")
        cli.set_password_policy(True)
        test_conn, ctrl = cli.connect()
        newpass = test_conn.modify_password()
        test_conn.close()
        assert isinstance(newpass, str)
        cli.set_credentials("SIMPLE", str(user_dn), newpass)
        test_conn, ctrl = cli.connect()
        test_conn.close()
    except bonsai.AuthenticationError:
        pytest.fail("Failed to authenticate with the new password.")
    finally:
        entry = conn.search(user_dn, 0, attrlist=["userPassword"])[0]
        entry["userPassword"] = "p@ssword"
        entry.modify()
        entry = conn.search(user_dn, 0, attrlist=["pwdChangeTime", "pwdGraceUseTime"])[
            0
        ]
        if ("pwdChangeTime", "pwdGraceUseTime") in entry.keys():
            del entry["pwdChangeTime"]
            del entry["pwdGraceUseTime"]
            entry.modify()


@pytest.mark.skipif(
    sys.platform.startswith("win"), reason="Cannot use ManageDsaIT on Windows"
)
def test_search_with_managedsait_ctrl(ipaddr):
    """Test searching with manageDsaIT control."""
    refdn = LDAPDN("o=admin,ou=nerdherd-refs,dc=bonsai,dc=test")
    cli = LDAPClient("ldap://%s" % ipaddr)
    cli.set_server_chase_referrals(True)
    with cli.connect() as conn:
        res = conn.search(refdn, LDAPSearchScope.BASE, attrlist=["ref"])[0]
        assert str(res.dn) == "cn=admin,dc=bonsai,dc=test"
    cli.set_managedsait(True)
    with cli.connect() as conn:
        res = conn.search(refdn, LDAPSearchScope.BASE, attrlist=["ref"])[0]
        assert refdn == res.dn
        assert "ldap://bonsai.test/cn=admin,dc=bonsai,dc=test" == res["ref"][0]


@pytest.mark.skipif(
    sys.platform.startswith("win"), reason="Cannot use ManageDsaIT on Windows"
)
def test_add_and_delete_referrals(cfg, ipaddr):
    """Test add and delete an LDAP referral with ManageDdsIT control."""
    refdn = bonsai.LDAPDN("o=test-ref,ou=nerdherd,dc=bonsai,dc=test")
    ref = "ldap://test.host/cn=nobody"
    cli = LDAPClient("ldap://%s" % ipaddr)
    cli.set_credentials(
        "SIMPLE", user=cfg["SIMPLEAUTH"]["user"], password=cfg["SIMPLEAUTH"]["password"]
    )
    cli.managedsait = True
    with cli.connect() as conn:
        entry = bonsai.LDAPEntry(refdn, conn)
        entry["objectClass"] = ["referral", "extensibleObject"]
        entry["o"] = "test-ref"
        entry["ref"] = ref
        conn.add(entry)
        res = conn.search(refdn, 0, attrlist=["ref"])[0]
        assert entry.dn == res.dn
        assert entry["ref"] == res["ref"]
    cli.managedsait = False
    with cli.connect() as conn:
        with pytest.raises(bonsai.LDAPError):
            conn.delete(entry.dn)
    cli.managedsait = True
    with cli.connect() as conn:
        conn.delete(entry.dn)
        res = conn.search(refdn, 0, attrlist=["ref"])
        assert res == []


def test_client_sizelimit_error(conn, basedn):
    """Test raising SizeLimitError when reaching client side size limit."""
    with pytest.raises(SizeLimitError):
        conn.search(
            "ou=nerdherd,dc=bonsai,dc=test", LDAPSearchScope.SUBTREE, sizelimit=2
        )


def test_server_sizelimit_error(conn, anonym_conn, basedn, large_org):
    """Test raising SizeLimitError when reaching server side size limit."""
    import math

    entry_num = 1048
    page_size = 4
    org = large_org(conn, f"ou=limited,{basedn}", entry_num)
    with pytest.raises(SizeLimitError):
        anonym_conn.search(org.dn, 1)
    paged = anonym_conn.paged_search(org.dn, 1, page_size=page_size)
    page_num = 1
    try:
        while True:
            msgid = paged.acquire_next_page()
            if msgid is None:
                break
            paged = anonym_conn.get_result(msgid)
            page_num += 1
    except SizeLimitError as err:
        if sys.platform.startswith("win"):
            raise err
    expected = math.ceil(entry_num / page_size)
    expected = (
        expected
        if sys.platform.startswith("win")
        else expected - (entry_num - 1024) / page_size
    )
    assert page_num == expected


@pytest.mark.skipif(
    not sys.platform.startswith("win"),
    reason="Large page result test is tested only with AD",
)
def test_paged_search_large_result(conn, anonym_conn, basedn, large_org):
    page_size = 128
    entry_num = 65535
    org = large_org(conn, f"ou=large,{basedn}", entry_num)
    collected_entry = 0
    result = anonym_conn.paged_search(org.dn, 1, page_size=page_size)
    while True:
        collected_entry += sum(1 for _ in result)
        msgid = result.acquire_next_page()
        if msgid is None:
            break
        result = anonym_conn.get_result(msgid)

    assert entry_num == collected_entry
