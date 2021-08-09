import os

import pytest

from bonsai.active_directory import ACL
from bonsai.active_directory.acl import ACE, ACEType, ACLRevision


def test_ace_from_binary():
    input_data = b"\x05\nH\x00\x07\x00\x00\x00\x03\x00\x00\x00\x01\xc9u\xc9\xealoK\x83\x19\xd6\x7fED\x95\x06\x14\xcc(H7\x14\xbcE\x9b\x07\xado\x01^_(\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\x15\xb3LK\xd2\xfb\x90s\xc2\xdf9\xb9\\\x04\x00\x00"
    with pytest.raises(TypeError):
        _ = ACE.from_binary(0)
    with pytest.raises(TypeError):
        _ = ACE.from_binary("INVALID")
    with pytest.raises(ValueError):
        _ = ACE.from_binary(b"\x05\nH\x00\x07\x00\x00\x00")
    ace = ACE.from_binary(input_data)
    assert ace.type == ACEType.ACCESS_ALLOWED_OBJECT
    assert ace.mask == b"\x07\x00\x00\x00"
    assert ace.size == len(input_data)
    assert ace.flags == 10
    assert str(ace.trustee_sid) == "S-1-5-21-1263317781-1938881490-3107577794-1116"
    assert ace.object_type == b"\x01\xc9u\xc9\xealoK\x83\x19\xd6\x7fED\x95\x06"
    assert ace.inherited_object_type == b"\x14\xcc(H7\x14\xbcE\x9b\x07\xado\x01^_("
    assert ace.application_data is None


def test_acl_from_binary():
    with pytest.raises(TypeError):
        _ = ACL.from_binary(True)
    with pytest.raises(TypeError):
        _ = ACL.from_binary("INVALID")
    with pytest.raises(ValueError):
        _ = ACL.from_binary(b"\x05\nH\x00\x07\x00\x00\x00\x03\x00\x00\x00\x01\xc9u\xc9\xealoK\x83\x19\xd6\x7fED\x95\x06\x14\xcc(H7\x14\xbcE\x9b\x07\xado\x01^_(")
    curdir = os.path.abspath(os.path.dirname(__file__))
    with open(os.path.join(curdir, "testenv", "acl-sample.bin"), "rb") as data:
        input_data = data.read()
        acl = ACL.from_binary(input_data)
        assert acl.size == len(input_data)
        assert acl.count == 85
        assert acl.revision == ACLRevision.ACL_REVISION_DS
        assert acl.sbz1 == 0
        assert acl.sbz2 == 0
        assert len(acl.aces) == acl.count
        assert all(isinstance(ace, ACE) for ace in acl.aces)
        assert acl.aces[0].type == ACEType.ACCESS_ALLOWED_OBJECT
        assert (
            acl.aces[0].inherited_object_type
            == b"\x14\xcc(H7\x14\xbcE\x9b\x07\xado\x01^_("
        )
        assert acl.aces[-1].type == ACEType.ACCESS_ALLOWED
        assert (
            str(acl.aces[0].trustee_sid)
            == "S-1-5-21-1263317781-1938881490-3107577794-1116"
        )
        assert str(acl.aces[-1].trustee_sid) == "S-1-5-18"
