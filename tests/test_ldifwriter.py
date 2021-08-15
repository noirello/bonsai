import pytest

from base64 import b64decode
from io import StringIO, BytesIO
from bonsai import LDIFWriter
from bonsai import LDAPEntry, LDAPModOp


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
    assert ldif.output_file == out
    assert ldif.max_length == 100


def test_write_entry():
    """ Test serialising an LDAP entry. """
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
    surnames = {
        b64decode(line.split(":: ")[1]).decode("UTF-8")
        for line in contlines
        if "sn" in line
    }
    jpeg_lines = []
    for idx, line in enumerate(contlines):
        if "jpegPhoto::" in line:
            jpeg_lines.append(line.split(" ")[1])
            jpeg_lines.append(contlines[idx + 1][1:])
    jpegPhoto = b64decode("".join(jpeg_lines))

    assert all(len(line) <= 32 for line in contlines)
    assert f"dn: {ent.dn}" == contlines[0]
    assert f"cn: {ent['cn'][0]}\n" in content
    assert content.count("sn:: ") == 2
    assert surnames == set(ent["sn"])
    assert content.count("jpegPhoto:: ") == 1
    assert jpegPhoto == ent["jpegPhoto"][0]


def test_write_entries():
    """ Test writing multiple entries into the same output. """
    ent0 = LDAPEntry("cn=test0")
    ent0["cn"] = "test0"
    ent1 = LDAPEntry("cn=test1")
    ent1["cn"] = "test1"
    entries = (ent0, ent1)

    with StringIO() as out:
        ldif = LDIFWriter(out)
        ldif.write_entries(entries, write_version=False)
        content = out.getvalue()

    assert f"dn: {ent0.dn}" in content
    assert f"dn: {ent1.dn}" in content
    assert f"cn: {ent0['cn'][0]}" in content
    assert f"cn: {ent1['cn'][0]}" in content
    assert "version" not in content

    with StringIO() as out:
        ldif = LDIFWriter(out)
        ldif.write_entries(entries)
        content = out.getvalue()

    assert f"dn: {ent0.dn}" in content
    assert f"dn: {ent1.dn}" in content
    assert "version: 1" == content.split("\n")[0]


def test_write_changes():
    """ Test writing LDIF changes of an LDAP Entry. """
    ent = LDAPEntry("cn=test")
    ent["cn"] = "test"
    ent["sn"] = ["sntest1", "sntest2"]
    ent.change_attribute("givenName", LDAPModOp.REPLACE, "test")
    ent.change_attribute("uidNumber", LDAPModOp.DELETE, 0)
    ent.change_attribute("gidNumber", LDAPModOp.DELETE)

    with StringIO() as out:
        ldif = LDIFWriter(out)
        ldif.write_changes(ent)
        content = out.getvalue()
    lines = content.split("\n")

    assert f"dn: {ent.dn}" == lines.pop(0)  # First line.
    assert "changetype: modify" == lines.pop(0)  # Second line.
    assert "add: cn" in lines
    assert f"cn: {ent['cn'][0]}" == lines[lines.index("add: cn") + 1]
    assert "add: sn" in lines
    assert set(ent["sn"]) == {lin.split("sn: ")[1] for lin in lines if "sn: " in lin}
    assert "replace: givenName" in lines
    assert (
        f"givenName: {ent['givenName'][0]}"
        == lines[lines.index("replace: givenName") + 1]
    )
    assert "delete: uidNumber" in lines
    assert "uidNumber: 0" == lines[lines.index("delete: uidNumber") + 1]
    assert "delete: gidNumber" in lines
    # Remove the key entirely.
    assert "-" == lines[lines.index("delete: gidNumber") + 1]


def test_output_file():
    """ Test output_file property. """
    out = StringIO()
    ldif = LDIFWriter(out)
    assert ldif.output_file == out
    with pytest.raises(TypeError):
        ldif.output_file = None
    out2 = StringIO()
    ldif.output_file = out2
    assert ldif.output_file == out2
