import os
import uuid

import pytest

from bonsai.active_directory import ACL
from bonsai.active_directory.acl import ACE, ACEFlag, ACEType, ACERight, ACLRevision


def test_ace_from_binary():
    """ Test ACE's from_binary method. """
    input_data = b"\x05\nH\x00\x07\x00\x00\x00\x03\x00\x00\x00\x01\xc9u\xc9\xealoK\x83\x19\xd6\x7fED\x95\x06\x14\xcc(H7\x14\xbcE\x9b\x07\xado\x01^_(\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\x15\xb3LK\xd2\xfb\x90s\xc2\xdf9\xb9\\\x04\x00\x00"
    with pytest.raises(TypeError):
        _ = ACE.from_binary(0)
    with pytest.raises(TypeError):
        _ = ACE.from_binary("INVALID")
    with pytest.raises(ValueError):
        _ = ACE.from_binary(b"\x05\nH\x00\x07\x00\x00\x00")
    ace = ACE.from_binary(input_data)
    assert ace.type == ACEType.ACCESS_ALLOWED_OBJECT
    assert ace.mask == 7
    assert ace.rights == {
        ACERight.DS_CREATE_CHILD,
        ACERight.DS_DELETE_CHILD,
        ACERight.ACTRL_DS_LIST,
    }
    assert ace.size == len(input_data)
    assert ace.flags == {ACEFlag.INHERIT_ONLY, ACEFlag.CONTAINER_INHERIT}
    assert sum(ace.flags) == 10
    assert ace.trustee_sid == "S-1-5-21-1263317781-1938881490-3107577794-1116"
    assert ace.object_type == uuid.UUID("c975c901-6cea-4b6f-8319-d67f45449506")
    assert ace.inherited_object_type == uuid.UUID(
        "4828cc14-1437-45bc-9b07-ad6f015e5f28"
    )
    assert ace.application_data == b""


def test_ace_to_binary():
    """ Test ACE's from_binary method. """
    input_data = b"\x05\nH\x00\x07\x00\x00\x00\x03\x00\x00\x00\x01\xc9u\xc9\xealoK\x83\x19\xd6\x7fED\x95\x06\x14\xcc(H7\x14\xbcE\x9b\x07\xado\x01^_(\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\x15\xb3LK\xd2\xfb\x90s\xc2\xdf9\xb9\\\x04\x00\x00"
    assert ACE.from_binary(input_data).to_binary() == input_data

def test_acl_from_binary():
    """ Test ACL's from_binary method. """
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
    """ Test ACL's from_binary method. """
    curdir = os.path.abspath(os.path.dirname(__file__))
    with open(os.path.join(curdir, "testenv", "acl-sample.bin"), "rb") as data:
        input_data = data.read()
        assert ACL.from_binary(input_data).to_binary() == input_data

def test_str():
    """ Test __str__ method. """
    input_data = b"\x05\nH\x00\x07\x00\x00\x00\x03\x00\x00\x00\x01\xc9u\xc9\xealoK\x83\x19\xd6\x7fED\x95\x06\x14\xcc(H7\x14\xbcE\x9b\x07\xado\x01^_(\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\x15\xb3LK\xd2\xfb\x90s\xc2\xdf9\xb9\\\x04\x00\x00"
    ace = ACE.from_binary(input_data)
    assert (
        str(ace)
        == "(OA;CIIO;CCDCLC;c975c901-6cea-4b6f-8319-d67f45449506;4828cc14-1437-45bc-9b07-ad6f015e5f28;S-1-5-21-1263317781-1938881490-3107577794-1116)"
    )
