import unittest

from bonsai._bonsai import ldapvaluelist

class ldapvaluelistTest(unittest.TestCase):
    """ Test ldapvaluelist object. """
    def test_append(self):
        """ Test ldapvaluelist's append method. """
        lvl = ldapvaluelist()
        lvl.append("test")
        self.assertRaises(ValueError, lambda: lvl.append("Test"))

    def test_insert(self):
        """ Test ldapvaluelist's insert method. """
        lvl = ldapvaluelist(("test1",))
        lvl.insert(0, "test2")
        self.assertEqual(lvl, ["test2", "test1"])
        self.assertRaises(ValueError, lambda: lvl.insert(2, "test2"))
    
    def test_remove(self):
        """ Test ldapvaluelist's remove method. """
        lvl = ldapvaluelist(("test1", "test2"))
        lvl.remove("Test1")
        self.assertEqual(lvl, ["test2"])
        self.assertRaises(ValueError, lambda: lvl.remove("test1"))

    def test_set(self):
        """ Test ldapvaluelist's __setitem__ method. """
        lvl = ldapvaluelist()
        lvl[0:2] = ("test1", "test2", "test3")
        lvl[1] = "test4"
        self.assertEqual(lvl, ["test1", "test4", "test3"])
        def set_item():
             lvl[1] = "test3"
        self.assertRaises(ValueError, set_item)
        del lvl[0:2]
        self.assertEqual(lvl, ["test3"])
        lvl = ldapvaluelist([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])
        del lvl[slice(1,10,2)]
        self.assertEqual(lvl, [1, 3, 5, 7, 9, 11, 12])
        lvl[slice(2,6,2)] = (13, 14)
        self.assertEqual(lvl, [1, 3, 13, 7, 14, 11, 12])

    def test_extend(self):
        """ Test ldapvaluelist's extend method. """
        lvl = ldapvaluelist(("test1",))
        lvl.extend(("test2", "test3"))
        self.assertEqual(lvl, ["test1", "test2", "test3"])
        self.assertRaises(ValueError, lambda: lvl.extend(("test4", "test1")))
    
    def test_pop(self):
        """ Test ldapvaluelist's pop method. """
        lvl = ldapvaluelist(("test1", "test2"))
        lvl.pop(0)
        self.assertEqual(lvl, ["test2"])
        lvl.pop()
        self.assertEqual(lvl, [])
        self.assertRaises(IndexError, lambda: lvl.pop())

if __name__ == '__main__':
    unittest.main()