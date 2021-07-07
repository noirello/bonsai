import pytest

from bonsai import LDAPDN
from bonsai import errors

VALID_STRDN = "cn=user,dc=test,dc=local"


@pytest.fixture
def dnobj():
    """ Get a LDAPDN object with valid DN. """
    return LDAPDN(VALID_STRDN)


def test_rdn(dnobj):
    """ Test methods for retrieving and changing RDNs. """
    assert dnobj.rdns[0] == (("cn", "user"),)
    assert dnobj[0] == "cn=user"
    assert dnobj[1:] == "dc=test,dc=local"
    dnobj[1:] = "dc=test2"
    assert dnobj == "cn=user,dc=test2"
    with pytest.raises(IndexError):
        _ = dnobj[7]
    with pytest.raises(TypeError):
        _ = dnobj["test"]
    with pytest.raises(ValueError):
        dnobj.rdns = (("dc", "test"),)


def test_str(dnobj):
    """ Test __str__ method of LDAPDN object. """
    assert str(dnobj) == VALID_STRDN


def test_emptydn():
    """ Test empty distinguished name. """
    empty = LDAPDN("")
    assert empty[1:] == ""


def test_equal(dnobj):
    """ Test __eq__ method of LDAPDN object. """
    assert dnobj == LDAPDN(VALID_STRDN)
    assert dnobj == LDAPDN(VALID_STRDN.title())
    assert dnobj == VALID_STRDN.upper()


def test_invaliddn():
    """ Test InvalidDN exception. """
    with pytest.raises(errors.InvalidDN):
        _ = LDAPDN("cn=test,dc=one+two")


def test_special_char():
    """ Test parsing special characters in DN string. """
    spec = LDAPDN(r"cn=special\, name,dc=test,dc=local")
    assert str(spec) == r"cn=special\, name,dc=test,dc=local"


def test_setitem():
    """ Test setting RDNs for DN object. """
    dnobj = LDAPDN("sn=some+gn=thing,dc=test,dc=local")
    assert "sn=some+gn=thing" == dnobj[0]
    dnobj[0] = "cn=user"
    assert "cn=user,dc=test,dc=local" == dnobj
    dnobj[1] = "ou=group1,ou=group2"
    assert "cn=user,ou=group1,ou=group2,dc=local" == dnobj
    dnobj[2:] = "dc=local"
    assert "cn=user,ou=group1,dc=local" == dnobj

    with pytest.raises(TypeError):
        dnobj["invalid"] = "ou=group1,ou=group2"
    with pytest.raises(ValueError):
        dnobj[0] = 3
    with pytest.raises(errors.InvalidDN):
        dnobj[1] = "test,group"


def test_repr(dnobj):
    """ Test representation. """
    assert "<LDAPDN" in repr(dnobj)


def test_space_after_comma():
    """ Test allowing space after comma for attribute type. """
    with pytest.raises(errors.InvalidDN):
        _ = LDAPDN("c n=user,dc=test,dc=local")
    with pytest.raises(errors.InvalidDN):
        _ = LDAPDN("cn=user,dc =test,dc=local")
    dn = LDAPDN("cn=user, dc=test, dc=local")
    assert str(dn) == "cn=user, dc=test, dc=local"
    assert dn.rdns[1][0][0] == "dc"
