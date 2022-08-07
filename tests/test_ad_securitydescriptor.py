import os
import struct
import sys

import pytest
from conftest import get_config, test_ace

from bonsai import LDAPClient
from bonsai.active_directory.acl import ACE, ACL, ACLRevision
from bonsai.active_directory.sid import SID
from bonsai.active_directory import SecurityDescriptor


@pytest.fixture
def client():
    """Create a client with authentication settings."""
    cfg = get_config()
    url = f"ldap://{cfg['SERVER']['hostname']}:{cfg['SERVER']['port']}"
    client = LDAPClient(url)
    client.set_credentials(
        "SIMPLE", user=cfg["SIMPLEAUTH"]["user"], password=cfg["SIMPLEAUTH"]["password"]
    )
    return client


@pytest.fixture
def test_sd():
    return SecurityDescriptor(
        {
            "self_relative": False,
            "rm_control_valid": False,
            "sacl_protected": False,
            "dacl_protected": False,
            "sacl_auto_inherited": False,
            "dacl_auto_inherited": False,
            "sacl_computed_inheritance_required": False,
            "dacl_computed_inheritance_required": False,
            "server_security": False,
            "dacl_trusted": True,
            "sacl_defaulted": False,
            "sacl_present": False,
            "dacl_defaulted": False,
            "dacl_present": False,
            "group_defaulted": True,
            "owner_defaulted": True,
        },
        SID("S-1-1-0"),
        SID("S-1-1-0"),
        None,
        None,
    )


def test_from_binary():
    """Test from_binary method."""
    with pytest.raises(TypeError):
        _ = SecurityDescriptor.from_binary(0)
    with pytest.raises(TypeError):
        _ = SecurityDescriptor.from_binary("INVALID")
    with pytest.raises(ValueError):
        _ = SecurityDescriptor.from_binary(b"\x05\nH\x00\x07\x00")
    curdir = os.path.abspath(os.path.dirname(__file__))
    with open(os.path.join(curdir, "testenv", "sd-sample0.bin"), "rb") as data:
        input_data = data.read()
        sec_desc = SecurityDescriptor.from_binary(input_data)
        assert sec_desc.revision == 1
        assert sec_desc.group_sid == "S-1-5-21-3526669579-2242266465-3136906013-512"
        assert sec_desc.owner_sid == "S-1-5-21-3526669579-2242266465-3136906013-512"
        assert sec_desc.sbz1 == 0
        assert sec_desc.control["dacl_present"]
        assert len(sec_desc.dacl.aces) == 24
        assert sec_desc.dacl.aces[0].type == 5
        assert str(sec_desc.dacl.aces[0].trustee_sid) == "S-1-5-32-554"
        assert not sec_desc.control["sacl_present"]
        assert sec_desc.sacl is None
    with open(os.path.join(curdir, "testenv", "sd-sample1.bin"), "rb") as data:
        input_data = data.read()
        sec_desc = SecurityDescriptor.from_binary(input_data)
        assert sec_desc.revision == 1
        assert sec_desc.group_sid == "S-1-5-21-3526669579-2242266465-3136906013-512"
        assert sec_desc.owner_sid == "S-1-5-21-3526669579-2242266465-3136906013-512"
        assert sec_desc.sbz1 == 0
        assert sec_desc.control["dacl_present"]
        assert len(sec_desc.dacl.aces) == 24
        assert sec_desc.dacl.aces[0].type == 5
        assert sec_desc.dacl.aces[0].trustee_sid == "S-1-5-32-554"
        assert sec_desc.control["sacl_present"]
        assert len(sec_desc.sacl.aces) == 3
        assert sec_desc.sacl.aces[0].type == 2
        assert sec_desc.sacl.aces[0].trustee_sid == "S-1-1-0"


@pytest.mark.parametrize(
    "file",
    ["sd-sample0.bin", "sd-sample1.bin"],
)
def test_to_binary(file):
    """Test to_binary method."""
    curdir = os.path.abspath(os.path.dirname(__file__))
    with open(os.path.join(curdir, "testenv", file), "rb") as data:
        expected_data = data.read()
        test_sec_desc = SecurityDescriptor.from_binary(expected_data)
        test_data = test_sec_desc.to_binary()
        (
            expected_rev,
            expected_sbz1,
            expected_ctrl,
            expected_offset_owner,
            expected_offset_group,
            expected_offset_sacl,
            expected_offset_dacl,
        ) = struct.unpack("<BBHIIII", expected_data[:20])
        (
            test_rev,
            test_sbz1,
            test_ctrl,
            test_offset_owner,
            test_offset_group,
            test_offset_sacl,
            test_offset_dacl,
        ) = struct.unpack("<BBHIIII", test_data[:20])
        assert len(test_data) == len(expected_data)
        assert test_rev == expected_rev
        assert test_sbz1 == expected_sbz1
        assert test_ctrl == expected_ctrl
        if expected_offset_owner:
            assert (
                test_data[
                    test_offset_owner : test_offset_owner + test_sec_desc.owner_sid.size
                ]
                == expected_data[
                    expected_offset_owner : expected_offset_owner
                    + test_sec_desc.owner_sid.size
                ]
            )
        if expected_offset_group:
            assert (
                test_data[
                    test_offset_group : test_offset_group + test_sec_desc.group_sid.size
                ]
                == expected_data[
                    expected_offset_group : expected_offset_group
                    + test_sec_desc.group_sid.size
                ]
            )
        if expected_offset_sacl:
            assert (
                test_data[test_offset_sacl : test_offset_sacl + test_sec_desc.sacl.size]
                == expected_data[
                    expected_offset_sacl : expected_offset_sacl
                    + test_sec_desc.sacl.size
                ]
            )
        if expected_offset_dacl:
            assert (
                test_data[test_offset_dacl : test_offset_dacl + test_sec_desc.dacl.size]
                == expected_data[
                    expected_offset_dacl : expected_offset_dacl
                    + test_sec_desc.dacl.size
                ]
            )
        assert SecurityDescriptor.from_binary(test_data).to_binary() == test_data


@pytest.mark.skipif(
    not sys.platform.startswith("win"),
    reason="Cannot query SecurityDescriptor from OpenLDAP",
)
@pytest.mark.parametrize(
    "sd_flags, owner_sid, group_sid, dacl, sacl",
    [
        (1, True, False, False, False),
        (2, False, True, False, False),
        (3, True, True, False, False),
        (4, False, False, True, False),
        (8, False, False, False, True),
        (15, True, True, True, True),
    ],
    ids=["only-owner", "only-group", "owner-group", "only-dacl", "only-sacl", "all"],
)
def test_sd_flags(client, sd_flags, owner_sid, group_sid, dacl, sacl):
    """Test LDAP_SERVER_SD_FLAGS_OID control"""
    client.sd_flags = sd_flags
    with client.connect() as conn:
        res = conn.search(
            "cn=chuck,ou=nerdherd,dc=bonsai,dc=test",
            0,
            attrlist=["nTSecurityDescriptor"],
        )[0]
        sec_desc = SecurityDescriptor.from_binary(res["nTSecurityDescriptor"][0])
        assert sec_desc.revision == 1
        if owner_sid:
            assert sec_desc.owner_sid is not None
            assert isinstance(sec_desc.owner_sid, SID)
        else:
            assert sec_desc.owner_sid is None
        if group_sid:
            assert sec_desc.group_sid is not None
            assert isinstance(sec_desc.group_sid, SID)
        else:
            assert sec_desc.group_sid is None
        assert sec_desc.control["dacl_present"] is dacl
        if dacl:
            assert isinstance(sec_desc.dacl, ACL)
        else:
            assert sec_desc.dacl is None
        assert sec_desc.control["sacl_present"] is sacl
        if sacl:
            assert isinstance(sec_desc.sacl, ACL)
        else:
            assert sec_desc.sacl is None


def test_sd_set_control(test_sd: SecurityDescriptor):
    """Test setting controls for SecurityDescriptor."""
    with pytest.raises(TypeError):
        test_sd.set_control("string")
    with pytest.raises(TypeError):
        test_sd.set_control({"a": "b", "c": True})
    with pytest.raises(ValueError):
        test_sd.set_control(-2)
    test_sd.set_control(0)
    assert all(val is False for val in test_sd.control.values())
    test_sd.control = {"sacl_protected": True}
    assert test_sd.control["sacl_protected"]
    assert all(
        val is False for key, val in test_sd.control.items() if key != "sacl_protected"
    )
    test_sd.control = 0x8 + 0x20
    assert test_sd.control["dacl_defaulted"]
    assert test_sd.control["sacl_defaulted"]
    assert all(
        val is False
        for key, val in test_sd.control.items()
        if key not in ("dacl_defaulted", "sacl_defaulted")
    )


def test_sd_set_owner_sid(test_sd: SecurityDescriptor):
    """Test setting owner SID for SecurityDescriptor."""
    assert test_sd.owner_sid == SID("S-1-1-0")
    with pytest.raises(TypeError):
        test_sd.set_owner_sid("string")
    with pytest.raises(TypeError):
        test_sd.set_owner_sid(0)
    with pytest.raises(TypeError):
        test_sd.owner_sid = True
    test_sd.set_owner_sid(SID("S-1-5-10"))
    assert test_sd.owner_sid == SID("S-1-5-10")
    test_sd.owner_sid = SID("S-1-5-20")
    assert test_sd.owner_sid == SID("S-1-5-20")


def test_sd_set_group_sid(test_sd: SecurityDescriptor):
    """Test setting group SID for SecurityDescriptor."""
    assert test_sd.group_sid == SID("S-1-1-0")
    with pytest.raises(TypeError):
        test_sd.set_group_sid("string")
    with pytest.raises(TypeError):
        test_sd.set_group_sid(0)
    with pytest.raises(TypeError):
        test_sd.group_sid = True
    test_sd.set_group_sid(SID("S-1-5-10"))
    assert test_sd.group_sid == SID("S-1-5-10")
    test_sd.group_sid = SID("S-1-5-20")
    assert test_sd.group_sid == SID("S-1-5-20")


def test_sd_set_dacl(test_sd: SecurityDescriptor, test_ace: ACE):
    """Test setting dacl for SecurityDescriptor."""
    assert test_sd.dacl is None
    with pytest.raises(TypeError):
        test_sd.set_dacl("string")
    with pytest.raises(TypeError):
        test_sd.set_dacl(0)
    with pytest.raises(TypeError):
        test_sd.dacl = True
    with pytest.raises(TypeError):
        test_sd.set_dacl(["A", "b"])
    test_sd.set_dacl(ACL(ACLRevision.ACL_REVISION, []))
    assert test_sd.dacl is not None
    assert test_sd.control["dacl_present"]
    test_sd.dacl = ACL(ACLRevision.ACL_REVISION, [test_ace])
    assert test_sd.dacl is not None
    assert test_sd.dacl.aces[0] == test_ace
    test_sd.dacl = None
    assert test_sd.dacl is None
    assert test_sd.control["dacl_present"] is False


def test_sd_set_sacl(test_sd: SecurityDescriptor, test_ace: ACE):
    """Test setting sacl for SecurityDescriptor."""
    assert test_sd.sacl is None
    with pytest.raises(TypeError):
        test_sd.set_sacl("string")
    with pytest.raises(TypeError):
        test_sd.set_sacl(0)
    with pytest.raises(TypeError):
        test_sd.sacl = True
    with pytest.raises(TypeError):
        test_sd.set_sacl(["A", "b"])
    test_sd.set_sacl(ACL(ACLRevision.ACL_REVISION, []))
    assert test_sd.sacl is not None
    assert test_sd.control["sacl_present"]
    test_sd.sacl = ACL(ACLRevision.ACL_REVISION, [test_ace])
    assert test_sd.sacl is not None
    assert test_sd.sacl.aces[0] == test_ace
    test_sd.sacl = None
    assert test_sd.sacl is None
    assert test_sd.control["sacl_present"] is False
