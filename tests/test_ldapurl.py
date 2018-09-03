import pytest

from bonsai import LDAPURL
from bonsai import LDAPDN
from bonsai.errors import InvalidDN


@pytest.fixture
def valid_ldapurl():
    """ Get a valid LDAPURL. """
    strurl = "ldaps://testurl:444/cn=test,dc=test?sn,gn?base?(objectclass=*)?1.2.3.4"
    return LDAPURL(strurl)


def test_get_address(valid_ldapurl):
    """ Test get_address method. """
    ldapi_url = LDAPURL("ldapi://%2Ftmp%2Fldapi")
    assert valid_ldapurl.get_address() == "ldaps://testurl:444"
    assert ldapi_url.get_address() == "ldapi://%2Ftmp%2Fldapi"


def test_get_host_properties(valid_ldapurl):
    """ Test getting LDAPURL host properties. """
    ldapi_url = LDAPURL("ldapi://%2Ftmp%2Fldapi")
    assert valid_ldapurl.scheme == "ldaps"
    assert valid_ldapurl.host == "testurl"
    assert valid_ldapurl.port == 444
    assert ldapi_url.scheme == "ldapi"
    assert ldapi_url.port == 0


def test_set_host_properties():
    """ Test setting LDAPURL host properties. """
    url = LDAPURL()
    with pytest.raises(ValueError):
        url.host = ":malformed,@äđĐ-"
    with pytest.raises(ValueError):
        url.port = "9922"
    with pytest.raises(ValueError):
        url.scheme = "http"

    url.host = "testurl2"
    url.port = 589
    url.scheme = "ldap"
    assert url.scheme == "ldap"
    assert url.host == "testurl2"
    assert url.port == 589


def test_get_bind_properties(valid_ldapurl):
    """ Test getting LDAPURL bind properties. """
    assert valid_ldapurl.basedn == LDAPDN("cn=test,dc=test")
    assert valid_ldapurl.scope == "base"
    assert valid_ldapurl.filter_exp == "(objectclass=*)"
    assert valid_ldapurl.attributes == ["sn", "gn"]


def test_set_bind_properties():
    """ Test setting LDAPURL bind properties. """
    url = LDAPURL()
    with pytest.raises(InvalidDN):
        url.basedn = "test"

    url.basedn = LDAPDN("cn=test")
    assert str(url.basedn) == "cn=test"


def test_str(valid_ldapurl):
    """ Test __str__ method of LDAPURL. """
    assert (
        str(valid_ldapurl)
        == "ldaps://testurl:444/cn=test,dc=test?sn,gn?base?(objectclass=*)?1.2.3.4"
    )
    assert str(LDAPURL("ldap://127.0.0.1/cn=x?cn")) == "ldap://127.0.0.1:389/cn=x?cn"
    assert str(LDAPURL("ldap:///")) == "ldap://localhost:389"
    assert str(LDAPURL("ldapi:///")) == "ldapi://localhost"
    assert not LDAPURL("ldap:///") == "http://localhost:389"
    assert "<LDAPURL" in repr(valid_ldapurl)


def test_conversion():
    """ Test ValueError exception for invalid URL format. """
    with pytest.raises(ValueError):
        _ = LDAPURL("ldap://failed.com/?falsedn?d")


def test_del_attr(valid_ldapurl):
    """ Test trying to delete an attribute. """
    with pytest.raises(AttributeError):
        del valid_ldapurl.host
    try:
        _ = valid_ldapurl.host
    except AttributeError:
        pytest.fail("Attribute not should be deleted.")


def test_invalid():
    """ Test invalid LDAP URLs. """
    with pytest.raises(ValueError):
        _ = LDAPURL("http://localhost")
    with pytest.raises(ValueError):
        _ = LDAPURL("ldaps://localost.")


def test_scope():
    """ Test scope and scope_num property. """
    url = LDAPURL("ldap:///??one")
    assert url.scope_num == 1
    url.scope = "base"
    assert url.scope_num == 0

    with pytest.raises(TypeError):
        url.scope = 2.1
    with pytest.raises(ValueError):
        url.scope = "all"


def test_ipv6():
    """ Test IPv6 address """
    url = LDAPURL(
        "ldap://[2001:db8:85a3::8a2e:370:7334]:1498/"
        "o=University%20of%20Michigan,c=US??one?"
        "(cn=Babs%20Jensen)"
    )
    assert url.host == "2001:db8:85a3::8a2e:370:7334"
    assert url.port == 1498
    assert url.scope == "one"
    assert url.filter_exp == "(cn=Babs Jensen)"
    addr = url.get_address()
    assert addr == "ldap://[2001:db8:85a3::8a2e:370:7334]:1498"
    with pytest.raises(ValueError):
        _ = LDAPURL("ldap://2001::85::37:7334")
