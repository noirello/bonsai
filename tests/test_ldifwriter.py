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
    assert "dn: {0}".format(ent.dn) == contlines[0]
    assert "cn: {0}\n".format(ent["cn"][0]) in content
    assert content.count("sn:: ") == 2
    assert surnames == set(ent["sn"])
    assert content.count("jpegPhoto:: ") == 1
    assert jpegPhoto == ent["jpegPhoto"][0]


def test_write_entries():
    """ Test writing muliple entries into the same output. """
    ent0 = LDAPEntry("cn=test0")
    ent0["cn"] = "test0"
    ent1 = LDAPEntry("cn=test1")
    ent1["cn"] = "test1"
    entries = (ent0, ent1)

    with StringIO() as out:
        ldif = LDIFWriter(out)
        ldif.write_entries(entries, write_version=False)
        content = out.getvalue()

    assert "dn: {0}".format(ent0.dn) in content
    assert "dn: {0}".format(ent1.dn) in content
    assert "cn: {0}".format(ent0["cn"][0]) in content
    assert "cn: {0}".format(ent1["cn"][0]) in content
    assert "version" not in content

    with StringIO() as out:
        ldif = LDIFWriter(out)
        ldif.write_entries(entries)
        content = out.getvalue()

    assert "dn: {0}".format(ent0.dn) in content
    assert "dn: {0}".format(ent1.dn) in content
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
    blocks = content.split("-\n")[:-1]
    headlines = blocks.pop(0).split("\n")
    add_lines = [blk for blk in blocks if "add: " in blk][0].split("\n")
    replace_lines = [blk for blk in blocks if "replace: " in blk][0].split("\n")
    delete_blocks = [blk.split("\n") for blk in blocks if "delete: " in blk]
    del_attr = [
        blk for blk in delete_blocks for lin in blk if lin == "delete: uidNumber"
    ][0]
    del_key = [
        blk for blk in delete_blocks for lin in blk if lin == "delete: gidNumber"
    ][0]

    assert "dn: {0}".format(ent.dn) == headlines[0]
    assert "changetype: modify" == headlines[1]
    assert "add: cn" == headlines[2]
    assert "cn: {0}".format(ent["cn"][0]) == headlines[3]
    assert "add: sn" == add_lines[0]
    assert set(ent["sn"]) == {lin.split("sn: ")[1] for lin in add_lines[1:-1]}
    assert "replace: givenName" == replace_lines[0]
    assert "givenName: {0}".format(ent["givenName"][0]) == replace_lines[1]
    assert "delete: uidNumber" == del_attr[0]
    assert "uidNumber: 0" == del_attr[1]
    assert len(del_key) == 2
    assert "delete: gidNumber" == del_key[0]
    assert "" == del_key[1]