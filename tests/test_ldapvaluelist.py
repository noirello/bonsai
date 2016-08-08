import unittest

from bonsai.ldapvaluelist import LDAPValueList

class LDAPValueListTest(unittest.TestCase):
    """ Test LDAPValueList object. """
    def test_append(self):
        """ Test LDAPValueList's append method. """
        lvl = LDAPValueList()
        lvl.append("test")
        self.assertRaises(ValueError, lambda: lvl.append("Test"))

    def test_insert(self):
        """ Test LDAPValueList's insert method. """
        lvl = LDAPValueList(("test1",))
        lvl.insert(0, "test2")
        self.assertEqual(lvl, ["test2", "test1"])
        self.assertRaises(ValueError, lambda: lvl.insert(2, "test2"))
    
    def test_remove(self):
        """ Test LDAPValueList's remove method. """
        lvl = LDAPValueList(("test1", "test2"))
        lvl.remove("Test1")
        self.assertEqual(lvl, ["test2"])
        self.assertRaises(ValueError, lambda: lvl.remove("test1"))

    def test_set(self):
        """ Test LDAPValueList's __setitem__ method. """
        lvl = LDAPValueList()
        lvl[0:2] = ("test1", "test2", "test3")
        lvl[1] = "test4"
        self.assertEqual(lvl, ["test1", "test4", "test3"])
        def set_item1():
             lvl[1] = "test3"
        def set_item2():
             lvl[1:2] = ["test5", "test1"]
        self.assertRaises(ValueError, set_item1)
        del lvl[0:2]
        self.assertEqual(lvl, ["test3"])
        del lvl[0]
        self.assertEqual(lvl, [])
        lvl = LDAPValueList([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])
        del lvl[slice(1,10,2)]
        self.assertEqual(lvl, [1, 3, 5, 7, 9, 11, 12])
        lvl[slice(2,6,2)] = (13, 14)
        self.assertEqual(lvl, [1, 3, 13, 7, 14, 11, 12])

    def test_extend(self):
        """ Test LDAPValueList's extend method. """
        lvl = LDAPValueList(("test1",))
        lvl.extend(("test2", "test3"))
        self.assertEqual(lvl, ["test1", "test2", "test3"])
        self.assertRaises(ValueError, lambda: lvl.extend(("test4", "test1")))
    
    def test_pop(self):
        """ Test LDAPValueList's pop method. """
        lvl = LDAPValueList(("test1", "test2"))
        lvl.pop(0)
        self.assertEqual(lvl, ["test2"])
        lvl.pop()
        self.assertEqual(lvl, [])
        self.assertRaises(IndexError, lambda: lvl.pop())

    def test_copy(self):
        """ Test LDAPValueList's copy method. """
        lvl1 = LDAPValueList(("test1", "test2"))
        lvl2 = lvl1.copy()
        self.assertEqual(lvl1, lvl2)
        self.assertEqual(lvl1.status, lvl2.status)

    def test_add(self):
        """ Test adding list to an LDAPValueList. """
        lvl = LDAPValueList((1,2,3))
        self.assertEqual(lvl + [4,5], [1,2,3,4,5])
        self.assertRaises(TypeError, lambda: lvl + 3)
        def wrong():
            nonlocal lvl
            lvl += 'x'
        self.assertRaises(TypeError, wrong)
        lvl += [4,5]
        self.assertEqual(lvl, [1,2,3,4,5])

    def test_mul(self):
        """ Test multiplying an LDAPValueList. """
        lvl = LDAPValueList((1,2,3))
        self.assertRaises(TypeError, lambda: lvl * 3)

    def test_set_status(self):
        """ Test setting LDAPValueList's status. """
        lvl = LDAPValueList()
        def wrong1():
            lvl.status = 'a'
        self.assertRaises(TypeError, wrong1)
        def wrong2():
            lvl.status = -1
        self.assertRaises(ValueError, wrong2)
        lvl.status = 2
        self.assertEqual(lvl.status, 2)

    def test_clear(self):
        """ Test setting LDAPValueList's clear method. """
        lvl = LDAPValueList((1,2,3))
        lvl.append(4)
        lvl.clear()
        self.assertEqual(lvl, [])

if __name__ == '__main__':
    unittest.main()