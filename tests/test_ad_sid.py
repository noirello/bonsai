import pytest

from bonsai.active_directory import SID


def test_from_binary():
    with pytest.raises(ValueError):
        _ = SID.from_binary(b"NOT-A-SID")
    with pytest.raises(ValueError):
        _ = SID.from_binary(
            b"\x01\x05\x00\x00\x00\x05\x15\x00\x00\x00\xdc\xf4\xdc;\x83=+F\x82\xa6(\x00\x02\x00\x00"
        )
    with pytest.raises(TypeError):
        _ = SID.from_binary(True)
    with pytest.raises(TypeError):
        _ = SID.from_binary("S-1-1-1")
    input_data = b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\xdc\xf4\xdc;\x83=+F\x82\x8b\xa6(\x00\x02\x00\x00"
    expected_sid = "S-1-5-21-1004336348-1177238915-682003330-512"
    sid = SID.from_binary(input_data)
    assert sid.revision == 1
    assert sid.identifier_authority == 5
    assert sid.subauthorities == (21, 1004336348, 1177238915, 682003330, 512)
    assert str(sid) == expected_sid


def test_from_string():
    with pytest.raises(ValueError):
        _ = SID.from_string("NOT-A-SID")
    with pytest.raises(ValueError):
        _ = SID.from_string("S--")
    with pytest.raises(ValueError):
        _ = SID.from_string("S-1")
    with pytest.raises(ValueError):
        _ = SID.from_string("S-1-NOT-SID")
    with pytest.raises(ValueError):
        _ = SID.from_string("NOT")
    with pytest.raises(TypeError):
        _ = SID.from_string(0)
    with pytest.raises(TypeError):
        _ = SID.from_string(b"S-1-1-1")
    sid = SID.from_string("S-1-5-21-3623811015-3361044348-30300820-1013")
    assert sid.revision == 1
    assert sid.identifier_authority == 5
    assert sid.subauthorities == (21, 3623811015, 3361044348, 30300820, 1013)
    everyone_sid = SID.from_string("S-1-1-0")
    assert everyone_sid.identifier_authority == 1
    assert everyone_sid.subauthorities == (0,)


def test_str():
    test_sid = "S-1-5-21-3623811015-3361044348-30300820-1013"
    assert str(SID.from_string(test_sid)) == test_sid
    test_sid = "S-1-1-0"
    assert str(SID.from_string(test_sid)) == test_sid


def test_repr():
    sid = SID.from_string("S-1-1-0")
    assert SID.__name__ in repr(sid)
    assert "S-1-1-0" in repr(sid)

