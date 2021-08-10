import os
import pytest

from bonsai.active_directory import SecurityDescriptor


def test_from_binary():
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
