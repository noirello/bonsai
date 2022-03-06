import sys

import pytest
from conftest import get_config, network_delay

import bonsai
from bonsai import LDAPClient
from bonsai.ldapconnection import LDAPConnection


@pytest.fixture(scope="module")
def url():
    """Get the LDAPURL."""
    cfg = get_config()
    url = "ldap://%s:%s" % (cfg["SERVER"]["hostip"], cfg["SERVER"]["port"])
    return bonsai.LDAPURL(url)


@pytest.fixture(scope="module")
def ldaps_url():
    """Get the LDAPURL for LDAP over TLS."""
    cfg = get_config()
    url = "ldaps://%s" % (cfg["SERVER"]["hostname"])
    return bonsai.LDAPURL(url)


def test_ldapurl(url):
    """Test setting LDAPURL."""
    cli = LDAPClient(url)
    assert cli.url == url
    with pytest.raises(TypeError):
        _ = LDAPClient(None)
    cli.url = "ldap://localhost"
    assert cli.url == "ldap://localhost"


def test_connect(client):
    """Test connect method."""
    assert client.connect() is not None


def test_rootdse(client):
    """Test receiving root DSE."""
    root_dse = client.get_rootDSE()
    assert root_dse["supportedLDAPVersion"][0] == 3


def test_raw_attributes(client):
    """Test setting raw attributes to keep in bytearray format."""
    with pytest.raises(TypeError):
        client.set_raw_attributes([5])
    with pytest.raises(ValueError):
        client.raw_attributes = ["ou", "cn", "ou"]
    client.set_raw_attributes(["ou"])
    conn = client.connect()
    result = conn.search("ou=nerdherd,dc=bonsai,dc=test", 0)[0]
    assert isinstance(result["ou"][0], bytes)
    assert not isinstance(result["objectClass"][0], bytes)


def test_set_credentials(url):
    """Test set_credentials method, mechanism and credentials properties."""
    client = LDAPClient(url)
    with pytest.raises(TypeError):
        client.set_credentials(2323, user=None)
    with pytest.raises(TypeError):
        client.set_credentials("Simple", "Name", 2, None, None)
    with pytest.raises(TypeError):
        client.set_credentials(
            "Simple", user="name", password="password", keytab="./keytab"
        )
    client.set_credentials("SIMPLE", "cn=admin", "password")
    assert client.mechanism == "SIMPLE"
    assert client.credentials == {
        "user": "cn=admin",
        "password": "password",
        "realm": None,
        "authz_id": None,
        "keytab": None,
    }
    client.set_credentials("EXTERNAL", authz_id="authzid")
    assert client.credentials["authz_id"] == "authzid"


def test_vendor_info():
    """Test vendor information."""
    info = bonsai.get_vendor_info()
    assert len(info) == 2
    assert isinstance(info[0], str)
    assert isinstance(info[1], int)


def test_tls_impl_name():
    """Test TLS implementation name."""
    tls_impl = bonsai.get_tls_impl_name()
    assert tls_impl in ("GnuTLS", "MozNSS", "OpenSSL", "SChannel")


def test_debug():
    """Test setting debug mode."""
    import subprocess

    code = "import bonsai; bonsai.set_debug(True); bonsai.LDAPClient('ldap://a.com').connect()"
    try:
        output = subprocess.check_output(
            [sys.executable, "-c", code], universal_newlines=True
        )
    except subprocess.CalledProcessError as exc:
        output = exc.output
    assert "DBG: ldapconnection_new " in output


@pytest.mark.timeout(18)
def test_connection_timeout(client):
    """Test connection timeout."""
    with pytest.raises(TypeError):
        _ = client.connect(timeout="Wrong")
    with pytest.raises(ValueError):
        _ = client.connect(timeout=-1.5)
    with pytest.raises(bonsai.TimeoutError):
        _ = client.connect(timeout=0)
    with network_delay(9.0):
        with pytest.raises(bonsai.TimeoutError):
            client.connect(timeout=5.0)


def test_ppolicy(url):
    """Test password policy setting."""
    client = LDAPClient(url)
    with pytest.raises(TypeError):
        client.set_password_policy("F")
    client.password_policy = True
    client.set_credentials(
        "SIMPLE", "cn=chuck,ou=nerdherd,dc=bonsai,dc=test", "p@ssword"
    )
    ret_val = client.connect()
    assert isinstance(ret_val, tuple)
    assert isinstance(ret_val[0], LDAPConnection)
    if ret_val[1] is None:
        pass  # Password policy is not supported.
    elif isinstance(ret_val[1], dict):
        assert "oid" in ret_val[1].keys()
        assert "expire" in ret_val[1].keys()
        assert "grace" in ret_val[1].keys()
        assert "1.3.6.1.4.1.42.2.27.8.5.1" == ret_val[1]["oid"]
    else:
        pytest.fail("Invalid second object in the tuple.")
    ret_val[0].close()


def test_extended_dn(url):
    """Test extended dn control."""
    client = LDAPClient(url)
    with pytest.raises(TypeError):
        client.set_extended_dn("A")
    with pytest.raises(ValueError):
        client.set_extended_dn(2)
    client.extended_dn_format = 0
    assert client.extended_dn_format == 0
    conn = client.connect()
    root_dse = client.get_rootDSE()
    result = conn.search("ou=nerdherd,dc=bonsai,dc=test", 0)[0]
    if "1.2.840.113556.1.4.529" in root_dse["supportedControl"]:
        assert result.extended_dn is not None
        assert result.extended_dn.split(";")[-1] == str(result.dn)
    else:
        assert result.extended_dn is None


def test_readonly_attributes(client):
    """Test read-only attributes of LDAPClient."""
    with pytest.raises(AttributeError):
        client.mechanism = "SIMPLE"
    with pytest.raises(AttributeError):
        client.credentials = {"user": "test", "password": "test"}
    with pytest.raises(AttributeError):
        client.tls = False


def test_auto_acquire_prop(client):
    """Test auto_page_acquire property."""
    with pytest.raises(TypeError):
        client.set_auto_page_acquire("A")
    assert client.auto_page_acquire
    client.auto_page_acquire = False
    assert not client.auto_page_acquire


def test_server_chase_referrals(client):
    """Test server_chase_referrals property."""
    with pytest.raises(TypeError):
        client.set_server_chase_referrals(2)
    assert client.server_chase_referrals == False
    client.server_chase_referrals = True
    assert client.server_chase_referrals


def test_ignore_referrals(client):
    """Test ignore_referrals property."""
    with pytest.raises(TypeError):
        client.set_ignore_referrals("A")
    assert client.ignore_referrals
    client.ignore_referrals = False
    assert not client.ignore_referrals


def test_managedsait(client):
    """Test managedsait property."""
    with pytest.raises(TypeError):
        client.set_managedsait("B")
    assert not client.managedsait
    client.managedsait = True
    assert client.managedsait


@pytest.mark.skipif(
    get_config()["SERVER"]["has_tls"] == "False", reason="TLS is not set"
)
def test_ldap_over_tls(ldaps_url):
    """Test LDAP over TLS connection."""
    client = LDAPClient(ldaps_url)
    client.set_cert_policy("ALLOW")
    client.set_ca_cert(None)
    client.set_ca_cert_dir(None)
    try:
        conn = client.connect()
        assert conn is not None
        conn.close()
    except Exception as exc:
        pytest.fail("TLS connection is failed with: %s" % str(exc))


@pytest.mark.skipif(
    get_config()["SERVER"]["has_tls"] == "False", reason="TLS is not set"
)
def test_starttls(url):
    """Test STARTTLS connection."""
    client = LDAPClient(url, True)
    client.set_cert_policy("ALLOW")
    client.set_ca_cert(None)
    client.set_ca_cert_dir(None)
    try:
        conn = client.connect()
        assert conn is not None
        conn.close()
    except Exception as exc:
        pytest.fail("TLS connection is failed with: %s" % str(exc))


@pytest.mark.skipif(
    get_config()["SERVER"]["has_tls"] == "False", reason="TLS is not set"
)
@pytest.mark.timeout(18)
def test_tls_timeout(url):
    """Test TLS connection timeout."""
    client = LDAPClient(url, True)
    client.set_cert_policy("ALLOW")
    client.set_ca_cert(None)
    client.set_ca_cert_dir(None)
    with network_delay(9.0):
        with pytest.raises(bonsai.TimeoutError):
            client.connect(timeout=5.0)


@pytest.mark.skipif(
    sys.platform != "linux", reason="No IPC support on Windows or Mac with Docker"
)
def test_ldapi():
    """Test making connection via IPC."""
    client = LDAPClient("ldapi://%2Ftmp%2Fbonsai%2Fldapi")
    assert client.connect() is not None


def test_set_sasl_sec_properties(url):
    client = LDAPClient(url)
    with pytest.raises(TypeError):
        client.set_sasl_security_properties(no_anonymous="false")
    with pytest.raises(TypeError):
        client.set_sasl_security_properties(no_anonymous=True, no_dict="false")
    with pytest.raises(TypeError):
        client.set_sasl_security_properties(no_anonymous=True, no_plain=0)
    with pytest.raises(TypeError):
        client.set_sasl_security_properties(
            no_anonymous=True, no_plain=True, forward_sec=-2
        )
    with pytest.raises(TypeError):
        client.set_sasl_security_properties(
            no_anonymous=True, no_plain=True, min_ssf="aas"
        )
    with pytest.raises(TypeError):
        client.set_sasl_security_properties(max_ssf="false")
    with pytest.raises(TypeError):
        client.set_sasl_security_properties(max_bufsize=0.5)
    with pytest.raises(ValueError):
        client.set_sasl_security_properties(min_ssf=-123)
    with pytest.raises(ValueError):
        client.set_sasl_security_properties(max_ssf=-1)
    with pytest.raises(ValueError):
        client.set_sasl_security_properties(max_bufsize=-1)
    client.set_sasl_security_properties(no_anonymous=True)
    assert client.sasl_security_properties == "noanonymous"
    client.set_sasl_security_properties(no_anonymous=True, no_plain=True)
    assert client.sasl_security_properties == "noanonymous,noplain"
    client.set_sasl_security_properties(
        no_anonymous=True, no_plain=True, forward_sec=True
    )
    assert client.sasl_security_properties == "noanonymous,noplain,forwardsec"
    client.set_sasl_security_properties(no_plain=True, pass_cred=True)
    assert client.sasl_security_properties == "noplain,passcred"
    client.set_sasl_security_properties(max_ssf=128)
    assert client.sasl_security_properties == "maxssf=128"
    client.set_sasl_security_properties(no_plain=True, max_ssf=128)
    assert client.sasl_security_properties == "noplain,maxssf=128"
    client.set_sasl_security_properties(
        no_anonymous=True,
        no_dict=True,
        no_plain=True,
        forward_sec=True,
        pass_cred=True,
        min_ssf=16,
        max_ssf=1024,
        max_bufsize=2048,
    )
    assert (
        client.sasl_security_properties
        == "noanonymous,nodict,noplain,forwardsec,passcred,minssf=16,maxssf=1024,maxbufsize=2048"
    )
    with client.connect() as conn:
        assert conn is not None
