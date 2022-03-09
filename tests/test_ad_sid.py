import pytest

from bonsai.active_directory import SID


def test_create_from_bytes_le():
    """Test create SID from binary."""
    with pytest.raises(ValueError):
        _ = SID(bytes_le=b"NOT-A-SID")
    with pytest.raises(ValueError):
        _ = SID(
            bytes_le=b"\x01\x05\x00\x00\x00\x05\x15\x00\x00\x00\xdc\xf4\xdc;\x83=+F\x82\xa6(\x00\x02\x00\x00"
        )
    with pytest.raises(TypeError):
        _ = SID(bytes_le=True)
    with pytest.raises(TypeError):
        _ = SID(bytes_le="S-1-1-1")
    input_data = b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\xdc\xf4\xdc;\x83=+F\x82\x8b\xa6(\x00\x02\x00\x00"
    expected_sid = "S-1-5-21-1004336348-1177238915-682003330-512"
    sid = SID(bytes_le=input_data)
    assert sid.revision == 1
    assert sid.identifier_authority == 5
    assert sid.subauthorities == (21, 1004336348, 1177238915, 682003330, 512)
    assert sid == expected_sid


def test_create_from_str_rep():
    """Test create SID from string."""
    with pytest.raises(ValueError):
        _ = SID("NOT-A-SID")
    with pytest.raises(ValueError):
        _ = SID("S--")
    with pytest.raises(ValueError):
        _ = SID(str_rep="S-1")
    with pytest.raises(ValueError):
        _ = SID("S-1-NOT-SID")
    with pytest.raises(ValueError):
        _ = SID("NOT")
    with pytest.raises(TypeError):
        _ = SID(str_rep=0)
    with pytest.raises(TypeError):
        _ = SID(b"S-1-1-1")
    sid = SID("S-1-5-21-3623811015-3361044348-30300820-1013")
    assert sid.revision == 1
    assert sid.identifier_authority == 5
    assert sid.subauthorities == (21, 3623811015, 3361044348, 30300820, 1013)
    everyone_sid = SID("S-1-1-0")
    assert everyone_sid.identifier_authority == 1
    assert everyone_sid.subauthorities == (0,)


def test_bytes_le():
    """Test bytes_le property."""
    expected_bytes = b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\xdc\xf4\xdc;\x83=+F\x82\x8b\xa6(\x00\x02\x00\x00"
    test_sid = SID("S-1-5-21-1004336348-1177238915-682003330-512")
    assert test_sid.bytes_le == expected_bytes
    assert (
        SID(bytes_le=test_sid.bytes_le).identifier_authority
        == test_sid.identifier_authority
    )
    assert SID(bytes_le=test_sid.bytes_le).subauthorities == test_sid.subauthorities


def test_str():
    """Test __str__ method."""
    test_sid = "S-1-5-21-3623811015-3361044348-30300820-1013"
    assert str(SID(test_sid)) == test_sid
    test_sid = "S-1-1-0"
    assert str(SID(test_sid)) == test_sid


def test_repr():
    """Test __repr__ method."""
    sid = SID("S-1-1-0")
    assert SID.__name__ in repr(sid)
    assert "S-1-1-0" in repr(sid)


def test_eq():
    """Test __eq__ method."""
    sid0 = SID("S-1-1-0")
    sid1 = SID("S-1-1-0")
    assert sid0 == sid1
    assert sid0 != True
    assert sid0 == "S-1-1-0"


def test_hash():
    """Test __hash__ method."""
    test_sid = "S-1-5-21-3623811015-3361044348-30300820-1013"
    sid0 = SID(test_sid)
    assert hash(sid0) == hash(test_sid)
    assert set((sid0, SID(test_sid))) == {sid0}


@pytest.mark.parametrize(
    "sid, alias",
    [
        (SID("S-1-1-0"), "WD"),
        (SID("S-1-5-32-559"), "LU"),
        (SID("S-1-5-21-3623811015-3361044348-30300820-500"), "LA"),
        (SID("S-1-5-21-3623811015-3361044348-30300820-520"), "PA"),
        (SID("S-1-5-21-3623811015-3361044348-30300820-1013"), None),
        (SID("S-1-5-34-3623811015-3361044348-30300820-500"), None),
    ],
)
def test_sddl_alias(sid, alias):
    """Test sddl_alias property."""
    assert sid.sddl_alias == alias


@pytest.mark.parametrize(
    "sid",
    [
        SID("S-1-1-0"),
        SID("S-1-5-32-559"),
        SID("S-1-5-34-3623811015-3361044348-30300820-500"),
    ],
)
def test_size(sid):
    """Test size property."""
    assert sid.size == len(sid.bytes_le)
