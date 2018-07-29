import pytest

from base64 import b64decode
from io import StringIO, BytesIO
from bonsai import LDIFWriter
from bonsai import LDAPEntry


def test_init_params():
    """ Test constructor parameters for LDIFWriter. """
    with pytest.raises(TypeError):
        _ = LDIFWriter("wrong")
    with pytest.raises(TypeError):
        _ = LDIFWriter(StringIO(), max_length=None)
    with pytest.raises(TypeError):
        _ = LDIFWriter(BytesIO())
    out = StringIO()
    ldif = LDIFWriter(out, 100)
    assert ldif.outfile == out
    assert ldif.max_length == 100


def test_write_entry():
    """ Test serializing an LDAP entry. """
    ent = LDAPEntry("cn=test")
    ent["cn"] = "test"
    ent["jpegPhoto"] = b"1223122130008283938282931232"
    ent["sn"] = "test😊"
    ent["sn"].append(" test2")

    with StringIO() as out:
        ldif = LDIFWriter(out, max_length=32)
        ldif.write_entry(ent)
        content = out.getvalue()
    contlines = content.split("\n")
    surnames = [
        b64decode(line.split("::")[1]).decode("UTF-8")
        for line in contlines
        if "sn" in line
    ]
    jpeg_lines = []
    for idx, line in enumerate(contlines):
        if "jpegPhoto::" in line:
            jpeg_lines.append(line.split(" ")[1])
            jpeg_lines.append(contlines[idx + 1][1:])
    jpegPhoto = b64decode("".join(jpeg_lines))

    assert all(len(line) <= 32 for line in contlines)
    assert "dn: {0}".format(ent.dn) == contlines[0]
    assert "cn: {0}\n".format(ent["cn"][0]) in content
    assert content.count("sn::") == 2
    assert surnames == ent["sn"]
    assert jpegPhoto == ent["jpegPhoto"][0]
