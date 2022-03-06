import pytest

from bonsai.ldapvaluelist import LDAPValueList


def test_append():
    """ Test LDAPValueList's append method. """
    lvl = LDAPValueList()
    lvl.append("test")
    assert "test" in lvl
    with pytest.raises(ValueError):
        lvl.append("Test")


def test_insert():
    """ Test LDAPValueList's insert method. """
    lvl = LDAPValueList(("test1",))
    lvl.insert(0, "test2")
    assert lvl == ["test2", "test1"]
    with pytest.raises(ValueError):
        lvl.insert(2, "test2")


def test_remove():
    """ Test LDAPValueList's remove method. """
    lvl = LDAPValueList(("test1", "test2"))
    lvl.remove("Test1")
    assert lvl == ["test2"]
    with pytest.raises(ValueError):
        lvl.remove("test1")


def test_set():
    """ Test LDAPValueList's __setitem__ method. """
    lvl = LDAPValueList()
    lvl[0:2] = ("test1", "test2", "test3")
    lvl[1] = "test4"
    assert lvl == ["test1", "test4", "test3"]
    with pytest.raises(ValueError):
        lvl[1] = "test3"
    with pytest.raises(ValueError):
        lvl[1:3] = ["test5", "test1"]
    del lvl[0:2]
    assert lvl == ["test3"]
    del lvl[0]
    assert lvl == []
    lvl = LDAPValueList([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])
    del lvl[slice(1, 10, 2)]
    assert lvl == [1, 3, 5, 7, 9, 11, 12]
    lvl[slice(2, 6, 2)] = (13, 14)
    assert lvl == [1, 3, 13, 7, 14, 11, 12]


def test_extend():
    """ Test LDAPValueList's extend method. """
    lvl = LDAPValueList(("test1",))
    lvl.extend(("test2", "test3"))
    assert lvl == ["test1", "test2", "test3"]
    with pytest.raises(ValueError):
        lvl.extend(("test4", "test1"))


def test_pop():
    """ Test LDAPValueList's pop method. """
    lvl = LDAPValueList(("test1", "test2"))
    assert lvl.pop(0) == "test1"
    assert lvl == ["test2"]
    lvl.pop()
    assert lvl == []
    with pytest.raises(IndexError):
        lvl.pop()


def test_copy():
    """ Test LDAPValueList's copy method. """
    lvl1 = LDAPValueList(("test1", "test2"))
    lvl2 = lvl1.copy()
    assert lvl1 == lvl2
    assert lvl1.status == lvl2.status


def test_add():
    """ Test adding list to an LDAPValueList. """
    lvl = LDAPValueList((1, 2, 3))
    assert lvl + [4, 5] == [1, 2, 3, 4, 5]
    with pytest.raises(TypeError):
        _ = lvl + 3
    with pytest.raises(TypeError):
        lvl += "x"
    lvl += [4, 5]
    assert lvl == [1, 2, 3, 4, 5]


def test_mul():
    """ Test multiplying an LDAPValueList. """
    lvl = LDAPValueList((1, 2, 3))
    with pytest.raises(TypeError):
        _ = lvl * 3


def test_set_status():
    """ Test setting LDAPValueList's status. """
    lvl = LDAPValueList()
    with pytest.raises(TypeError):
        lvl.status = "a"
    with pytest.raises(ValueError):
        lvl.status = -1
    lvl.status = 2
    assert lvl.status == 2


def test_clear():
    """ Test setting LDAPValueList's clear method. """
    lvl = LDAPValueList((1, 2, 3))
    lvl.append(4)
    lvl.clear()
    assert lvl == []


def test_readonly_attrs():
    """ Test modifying read-only attributes. """
    lvl = LDAPValueList((1, 2, 3))
    with pytest.raises(AttributeError):
        lvl.added = [1, 2, 3]
    with pytest.raises(AttributeError):
        lvl.deleted = [1, 2, 3]
    with pytest.raises(AttributeError):
        lvl._status_dict = {"status": 2}