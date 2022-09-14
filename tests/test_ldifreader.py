import pytest
import base64
import os

from io import StringIO, BytesIO
from bonsai import LDIFReader, LDIFError


def test_init_params():
    """Test constructor parameters for LDIFReader."""
    with pytest.raises(TypeError):
        _ = LDIFReader("wrong")
    with pytest.raises(TypeError):
        _ = LDIFReader(StringIO(), max_length=None)
    with pytest.raises(TypeError):
        _ = LDIFReader(BytesIO())
    inp = StringIO()
    ldif = LDIFReader(inp, max_length=100)
    assert ldif.input_file == inp
    assert ldif.max_length == 100


def test_version():
    """Test setting version attribute from LDIF."""
    text = "version: 1\ndn: cn=test\ncn: test\n"
    with StringIO(text) as ldif:
        reader = LDIFReader(ldif)
        ent = next(reader)
        assert reader.version == 1
        assert ent.dn == "cn=test"


def test_missing_dn():
    """Test missing distinguished name in LDIF entry."""
    text = "changetype: add\nsn: test\ncn: test\n"
    with StringIO(text) as ldif:
        reader = LDIFReader(ldif)
        with pytest.raises(LDIFError) as excinfo:
            _ = next(reader)
        assert "Missing distinguished name" in str(excinfo.value)
        assert "entry #1" in str(excinfo.value)


def test_invalid_file():
    """Test invalid lines."""
    text = " invalid\n"
    with StringIO(text) as ldif:
        reader = LDIFReader(ldif)
        with pytest.raises(LDIFError) as excinfo:
            _ = next(reader)
        assert "Parser error" in str(excinfo.value)
        assert isinstance(excinfo.value.__context__, IndexError)
    text = "dn: cn=test\nnotvalid attribute\n"
    with StringIO(text) as ldif:
        reader = LDIFReader(ldif)
        with pytest.raises(LDIFError) as excinfo:
            _ = next(reader)
        assert "Invalid attribute value pair:" in str(excinfo.value)
        assert "entry #1" in str(excinfo.value)
        assert "value separator" in str(excinfo.value.__context__)
    text = "dn: :cn=test notvalid attribute\n"
    with StringIO(text) as ldif:
        reader = LDIFReader(ldif)
        with pytest.raises(LDIFError) as excinfo:
            _ = next(reader)
        assert "Invalid attribute value pair:" in str(excinfo.value)
        assert "entry #1" in str(excinfo.value)
        assert "safe first character" in str(excinfo.value.__context__)


def test_invalid_base64():
    """Test LDIF line with invalid base64 data."""
    text = "dn:: cn=test notvalid: attribute\n"
    with StringIO(text) as ldif:
        reader = LDIFReader(ldif)
        with pytest.raises(LDIFError) as excinfo:
            _ = next(reader)
        assert "Invalid attribute value pair:" in str(excinfo.value)
        assert "entry #1" in str(excinfo.value)
        assert "Incorrect padding" in str(excinfo.value.__context__)
    text = "cn:: dGV4dCx2YWx1ZSxkYXRhNNO"
    with StringIO(text) as ldif:
        reader = LDIFReader(ldif)
        with pytest.raises(LDIFError) as excinfo:
            _ = next(reader)
        assert "Invalid attribute value pair:" in str(excinfo.value)
        assert "entry #1" in str(excinfo.value)
        assert "Incorrect padding" in str(excinfo.value.__context__)


def test_too_long_line():
    """Test LDIF input with too long line."""
    text = "dn: cn=toolong\n"
    with StringIO(text) as ldif:
        reader = LDIFReader(ldif, max_length=12)
        with pytest.raises(LDIFError) as excinfo:
            _ = next(reader)
        assert "too long" in str(excinfo.value)
        assert "Line 1" in str(excinfo.value)


def test_comment():
    """Test parsing comment lines in LDIF files."""
    ldif = "# DN: cn=test\ndn: cn=test\n#Other comment line.\ncn: test\n"
    with StringIO(ldif) as test:
        reader = LDIFReader(test)
        ent = next(reader)
        assert ent.dn == "cn=test"
        assert ent["cn"] == ["test"]
    multiline = "# A long multiline comment\n in an LDIF file.\ndn: cn=test\n"
    with StringIO(multiline) as test:
        reader = LDIFReader(test)
        ent = next(reader)
        assert ent.dn == "cn=test"


def test_input_file():
    """Test input_file property."""
    inp = StringIO()
    ldif = LDIFReader(inp)
    assert ldif.input_file == inp
    with pytest.raises(TypeError):
        ldif.input_file = None
    inp2 = StringIO()
    ldif.input_file = inp2
    assert ldif.input_file == inp2


def test_autoload():
    """Test autoload property."""
    inp = StringIO()
    ldif = LDIFReader(inp)
    assert ldif.autoload == True
    with pytest.raises(TypeError):
        ldif.autoload = "Yes"
    ldif.autoload = False
    assert ldif.autoload == False


def test_resource_handlers():
    """Test resource_handlers property."""
    inp = StringIO()
    ldif = LDIFReader(inp)
    assert isinstance(ldif.resource_handlers, dict)
    assert "file" in ldif.resource_handlers.keys()
    with pytest.raises(AttributeError):
        ldif.resource_handlers = {"New": "dict"}
    ldif.resource_handlers["http"] = lambda x: x
    assert "http" in ldif.resource_handlers.keys()


def test_multiline_attribute():
    """Test parsing multiline attributes in LDIF."""
    text = "dn: cn=unimaginably+sn=very,ou=very,dc=very,dc=long,\n dc=line\ncn: unimaginably\nsn: very\nsn: long\n"
    with StringIO(text) as test:
        reader = LDIFReader(test)
        ent = next(reader)
    assert ent.dn == "cn=unimaginably+sn=very,ou=very,dc=very,dc=long,dc=line"
    assert ent["cn"][0] == "unimaginably"
    assert ent["sn"][0] == "very"
    assert ent["sn"][1] == "long"


def test_multiple_entries():
    """Test parsing multiple entries in one LDIF."""
    text = "dn: cn=test1\ncn: test1\n\ndn: cn=test2\ncn: test2\n"
    with StringIO(text) as test:
        reader = LDIFReader(test)
        entries = list(reader)
    assert len(entries) == 2
    assert entries[0].dn == "cn=test1"
    assert entries[1]["cn"][0] == "test2"


def test_encoded_attributes():
    """Test parsing base64 encoded attributes."""
    attr = "test"
    text = f"version: 1\ndn: cn=test\ncn:: {base64.b64encode(attr.encode('UTF-8')).decode('UTF-8')}\n"
    with StringIO(text) as test:
        reader = LDIFReader(test)
        ent = next(reader)
    assert ent.dn == "cn=test"
    assert ent["cn"][0] == attr


def test_load_resource():
    """Test load_resource method."""
    curdir = os.path.abspath(os.path.dirname(__file__))
    with StringIO() as test:
        test.name = "dummy"
        reader = LDIFReader(test)
        with pytest.raises(LDIFError) as err:
            reader.load_resource("ftp://dummy.com")
            assert "Unsupported URL format" in str(err)
        with pytest.raises(LDIFError) as err:
            reader.load_resource("ftp//dummy.com")
            assert "Unsupported URL format" in str(err)
        url = f"file://{os.path.join(curdir, os.path.join('testenv', 'test.jpeg'))}"
        content = reader.load_resource(url)
        assert len(content) != 0
        assert isinstance(content, bytes)


def test_url_attribute():
    """Test URL attribute in LDIF file."""
    text = "dn: cn=test\ncn: test1\njpegPhoto:< file://./testenv/test.jpeg\n"
    with StringIO(text) as test:
        test.name = __file__
        reader = LDIFReader(test)
        ent = next(reader)
    assert ent.dn == "cn=test"
    assert len(ent["jpegPhoto"][0]) == 1959
    assert isinstance(ent["jpegPhoto"][0], bytes)


def test_changetype():
    """Test changetype attribute in LDIF file."""
    text = "dn: cn=test\nchangetype: add\ncn: test\n"
    with StringIO(text) as test:
        reader = LDIFReader(test)
        ent = next(reader)
    assert ent.dn == "cn=test"
    assert "cn" in ent
    assert "changetype" not in ent


def test_missing_attribute():
    """Test missing attribute in LDIF-CHANGE."""
    text = "dn: cn=test\nchangetype: modify\nadd: sn\ncn: test\n"
    with StringIO(text) as test:
        reader = LDIFReader(test)
        with pytest.raises(LDIFError):
            _ = next(reader)


def test_value_with_colon():
    """Test attribute value with containing colon."""
    text = "dn: cn=test\npostaladdress: p.o. box: 1234\ncn: test\n"
    with StringIO(text) as test:
        test.name = __file__
        reader = LDIFReader(test)
        ent = next(reader)
    assert ent.dn == "cn=test"
    assert ent["postaladdress"][0] == "p.o. box: 1234"
    assert ent["cn"][0] == "test"


def test_modify_change():
    """Test loading modified attributes from LDIF-CHANGE."""
    text = """dn: cn=test
changetype: modify
add: sn
sn: testing1
sn: testing2
-
replace: uid
uid: tester
-
delete: gidNumber
-
delete: objectclass
objectClass: posixUser

"""
    with StringIO(text) as test:
        reader = LDIFReader(test)
        ent = next(reader)
        status = ent._status()
        assert status["sn"]["@status"] == 1
        assert status["sn"]["@added"] == ["testing1", "testing2"]
        assert status["sn"]["@deleted"] == []
        assert status["uid"]["@status"] == 2
        assert status["uid"]["@added"] == ["tester"]
        assert status["uid"]["@deleted"] == []
        assert status["objectClass"]["@status"] == 1
        assert status["objectClass"]["@added"] == []
        assert status["objectClass"]["@deleted"] == ["posixUser"]
        assert status["@deleted_keys"] == ["gidNumber"]
