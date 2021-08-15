import pytest

from bonsai.active_directory import UserAccountControl


def test_init():
    """ Test creating UserAccountControl. """
    with pytest.raises(TypeError):
        _ = UserAccountControl("123")
    uac = UserAccountControl(209)
    assert uac is not None


def test_value():
    """ Test value property. """
    uac = UserAccountControl(209)
    assert uac.value == 209


def test_properties():
    """ Test properties property. """
    uac = UserAccountControl(514)
    assert uac.properties["accountdisable"]
    assert uac.properties["normal_account"]
    assert all(
        val == False
        for key, val in uac.properties.items()
        if key not in ("accountdisable", "normal_account")
    )
    uac = UserAccountControl(67584)
    assert uac.properties["dont_expire_password"]
    assert uac.properties["interdomain_trust_account"]
    assert all(
        val == False
        for key, val in uac.properties.items()
        if key not in ("dont_expire_password", "interdomain_trust_account")
    )
