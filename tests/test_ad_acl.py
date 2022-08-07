import os
import uuid

import pytest

from bonsai.active_directory import ACL, SID
from bonsai.active_directory.acl import ACE, ACEFlag, ACEType, ACERight, ACLRevision

from conftest import test_ace

ACE_BINARY_TEST_DATA = b"\x05\nH\x00\x07\x00\x00\x00\x03\x00\x00\x00\x01\xc9u\xc9\xealoK\x83\x19\xd6\x7fED\x95\x06\x14\xcc(H7\x14\xbcE\x9b\x07\xado\x01^_(\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\x15\xb3LK\xd2\xfb\x90s\xc2\xdf9\xb9\\\x04\x00\x00"


def test_ace_from_binary():
    """Test ACE's from_binary method."""
    with pytest.raises(TypeError):
        _ = ACE.from_binary(0)
    with pytest.raises(TypeError):
        _ = ACE.from_binary("INVALID")
    with pytest.raises(ValueError):
        _ = ACE.from_binary(b"\x05\nH\x00\x07\x00\x00\x00")
    ace = ACE.from_binary(ACE_BINARY_TEST_DATA)
    assert ace.type == ACEType.ACCESS_ALLOWED_OBJECT
    assert ace.type.is_object_type
    assert ace.type.is_access_allowed
    assert not ace.type.is_access_denied
    assert ace.mask == 7
    assert ace.rights == {
        ACERight.DS_CREATE_CHILD,
        ACERight.DS_DELETE_CHILD,
        ACERight.ACTRL_DS_LIST,
    }
    assert ace.size == len(ACE_BINARY_TEST_DATA)
    assert ace.flags == {ACEFlag.INHERIT_ONLY, ACEFlag.CONTAINER_INHERIT}
    assert ace.is_inherited is False
    assert sum(ace.flags) == 10
    assert ace.trustee_sid == "S-1-5-21-1263317781-1938881490-3107577794-1116"
    assert ace.object_type == uuid.UUID("c975c901-6cea-4b6f-8319-d67f45449506")
    assert ace.inherited_object_type == uuid.UUID(
        "4828cc14-1437-45bc-9b07-ad6f015e5f28"
    )
    assert ace.application_data == b""


def test_ace_to_binary():
    """Test ACE's from_binary method."""
    assert ACE.from_binary(ACE_BINARY_TEST_DATA).to_binary() == ACE_BINARY_TEST_DATA


def test_ace_set_access_rights(test_ace: ACE):
    """Test setting ACE's access rights."""
    assert test_ace.rights == {ACERight.GENERIC_READ}
    with pytest.raises(TypeError):
        test_ace.set_access_rights(None)
    with pytest.raises(TypeError):
        test_ace.set_access_rights("GENERIC_READ")
    with pytest.raises(TypeError):
        test_ace.set_access_rights({ACERight.GENERIC_READ, 12})
    with pytest.raises(ValueError):
        test_ace.set_access_rights(-12)
    test_ace.set_access_rights(268435464)
    assert test_ace.mask == 268435464
    assert test_ace.rights == {ACERight.GENERIC_ALL, ACERight.DS_SELF}
    test_ace.mask = 0
    assert test_ace.rights == set()
    new_rights = {ACERight.GENERIC_WRITE, ACERight.ACTRL_DS_LIST}
    test_ace.rights = new_rights
    assert test_ace.rights == new_rights
    assert test_ace.mask == sum(new_rights)


def test_ace_set_application_data(test_ace: ACE):
    """Test setting ACE's application data."""
    assert test_ace.application_data == b""
    with pytest.raises(TypeError):
        test_ace.set_application_data("string")
    test_ace.set_application_data(b"\x00\x10")
    assert test_ace.application_data == b"\x00\x10"
    test_ace.application_data = b"\x11\x10"
    assert test_ace.application_data == b"\x11\x10"


def test_ace_set_flags(test_ace: ACE):
    """Test setting ACE's flags."""
    assert test_ace.flags == {ACEFlag.INHERITED}
    with pytest.raises(TypeError):
        test_ace.set_flags("string")
    with pytest.raises(TypeError):
        test_ace.set_flags(42)
    test_ace.set_flags({ACEFlag.INHERIT_ONLY})
    assert test_ace.flags == {ACEFlag.INHERIT_ONLY}
    test_ace.flags = {ACEFlag.OBJECT_INHERIT, ACEFlag.SUCCESSFUL_ACCESS}
    assert test_ace.flags == {ACEFlag.OBJECT_INHERIT, ACEFlag.SUCCESSFUL_ACCESS}


def test_ace_set_object_type(test_ace: ACE):
    """Test setting ACE's object type."""
    assert test_ace.object_type is None
    with pytest.raises(TypeError):
        test_ace.set_object_type("string")
    with pytest.raises(TypeError):
        test_ace.set_object_type(42)
    obj_id = uuid.UUID("c975c901-6cea-4b6f-8319-d67f45449506")
    test_ace.set_object_type(obj_id)
    assert test_ace.object_type == obj_id
    test_ace.object_type = None
    assert test_ace.object_type is None


def test_ace_set_inherited_object_type(test_ace: ACE):
    """Test setting ACE's inherited object type."""
    assert test_ace.inherited_object_type == uuid.UUID(
        "c975c901-6cea-4b6f-8319-d67f45449506"
    )
    with pytest.raises(TypeError):
        test_ace.set_inherited_object_type("string")
    with pytest.raises(TypeError):
        test_ace.set_inherited_object_type(42)
    obj_id = uuid.UUID("c975c901-6cea-4b6f-8319-d67f45449507")
    test_ace.set_inherited_object_type(obj_id)
    assert test_ace.inherited_object_type == obj_id
    test_ace.inherited_object_type = None
    assert test_ace.inherited_object_type is None


def test_ace_set_type(test_ace: ACE):
    """Test setting ACE's type."""
    assert test_ace.type == ACEType.ACCESS_ALLOWED
    assert test_ace.type.is_access_allowed
    with pytest.raises(TypeError):
        test_ace.set_type("string")
    with pytest.raises(TypeError):
        test_ace.set_type(42)
    test_ace.set_type(ACEType.ACCESS_DENIED)
    assert test_ace.type == ACEType.ACCESS_DENIED
    assert test_ace.type.is_access_denied
    test_ace.type = ACEType.ACCESS_DENIED_CALLBACK
    assert test_ace.type == ACEType.ACCESS_DENIED_CALLBACK
    assert test_ace.type.is_access_denied


def test_ace_set_trustee_sid(test_ace: ACE):
    """Test setting ACE's trustee SID."""
    assert test_ace.trustee_sid == SID("S-1-1-0")
    with pytest.raises(TypeError):
        test_ace.set_trustee_sid("string")
    with pytest.raises(TypeError):
        test_ace.set_trustee_sid(42)
    test_ace.set_trustee_sid(SID("S-1-5-10"))
    assert test_ace.trustee_sid == SID("S-1-5-10")
    test_ace.trustee_sid = SID("S-1-5-11")
    assert test_ace.trustee_sid == SID("S-1-5-11")


def test_eq(test_ace: ACE):
    """Test ACE's __eq__ method."""
    assert not test_ace == 21
    other_ace = ACE(
        ACEType.ACCESS_ALLOWED,
        {ACEFlag.INHERITED},
        0x10000000,
        SID("S-1-1-0"),
        None,
        uuid.UUID("c975c901-6cea-4b6f-8319-d67f45449506"),
        b"",
    )
    assert not test_ace == other_ace
    other_ace = ACE(
        ACEType.ACCESS_ALLOWED,
        {ACEFlag.INHERITED},
        0x80000000,
        SID("S-1-1-0"),
        None,
        uuid.UUID("c975c901-6cea-4b6f-8319-d67f45449506"),
        b"\x01",
    )
    assert not test_ace == other_ace
    other_ace = ACE.from_binary(ACE_BINARY_TEST_DATA)
    assert not test_ace == other_ace
    other_ace = ACE(
        ACEType.ACCESS_ALLOWED,
        {ACEFlag.INHERITED},
        0x80000000,
        SID("S-1-1-0"),
        None,
        uuid.UUID("c975c901-6cea-4b6f-8319-d67f45449506"),
        b"",
    )
    assert test_ace == other_ace


def test_acl_from_binary():
    """Test ACL's from_binary method."""
    with pytest.raises(TypeError):
        _ = ACL.from_binary(True)
    with pytest.raises(TypeError):
        _ = ACL.from_binary("INVALID")
    with pytest.raises(ValueError):
        _ = ACL.from_binary(
            b"\x05\nH\x00\x07\x00\x00\x00\x03\x00\x00\x00\x01\xc9u\xc9\xealoK\x83\x19\xd6\x7fED\x95\x06\x14\xcc(H7\x14\xbcE\x9b\x07\xado\x01^_("
        )
    curdir = os.path.abspath(os.path.dirname(__file__))
    with open(os.path.join(curdir, "testenv", "acl-sample.bin"), "rb") as data:
        input_data = data.read()
        acl = ACL.from_binary(input_data)
        assert acl.size == len(input_data)
        assert acl.revision == ACLRevision.ACL_REVISION_DS
        assert len(acl.aces) == 85
        assert all(isinstance(ace, ACE) for ace in acl.aces)
        assert acl.aces[0].type == ACEType.ACCESS_ALLOWED_OBJECT
        assert acl.aces[0].inherited_object_type == uuid.UUID(
            "4828cc14-1437-45bc-9b07-ad6f015e5f28"
        )
        assert acl.aces[-1].type == ACEType.ACCESS_ALLOWED
        assert (
            acl.aces[0].trustee_sid == "S-1-5-21-1263317781-1938881490-3107577794-1116"
        )
        assert acl.aces[-1].trustee_sid == "S-1-5-18"


def test_acl_to_binary():
    """Test ACL's from_binary method."""
    curdir = os.path.abspath(os.path.dirname(__file__))
    with open(os.path.join(curdir, "testenv", "acl-sample.bin"), "rb") as data:
        input_data = data.read()
        assert ACL.from_binary(input_data).to_binary() == input_data


def test_acl_set_aces(test_ace):
    """Test setting ACL's aces list."""
    test_acl = ACL(ACLRevision.ACL_REVISION, [])
    assert test_acl.aces == []
    with pytest.raises(TypeError):
        test_acl.set_aces([1, 2, 3])
    with pytest.raises(TypeError):
        test_acl.set_aces([test_ace, 3])
    test_acl.set_aces([test_ace])
    assert test_acl.aces == [test_ace]
    test_acl.aces = []
    assert test_acl.aces == []


def test_str():
    """Test __str__ method."""
    ace = ACE.from_binary(ACE_BINARY_TEST_DATA)
    assert (
        str(ace)
        == "(OA;CIIO;CCDCLC;c975c901-6cea-4b6f-8319-d67f45449506;4828cc14-1437-45bc-9b07-ad6f015e5f28;S-1-5-21-1263317781-1938881490-3107577794-1116)"
    )
