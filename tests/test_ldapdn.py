import unittest

from bonsai import LDAPDN
from bonsai import errors

from bonsai.ldapdn import escape_attribute_value

class LDAPDNTest(unittest.TestCase):
    """ Testing LDAP DN object. """
    def setUp(self):
        """ Set up distinguished name for testing. """
        self.strdn = "cn=user,dc=test,dc=local"
        self.dnobj = LDAPDN(self.strdn)

    def test_rdn(self):
        """ Test methods for retrieving and changing RDNs. """
        self.assertEqual(self.dnobj.rdns[0], (('cn', 'user'),))
        self.assertEqual(self.dnobj[0], "cn=user")
        self.assertEqual(self.dnobj[1:], "dc=test,dc=local")
        self.dnobj[1:] = "dc=test2"
        self.assertEqual(self.dnobj, "cn=user,dc=test2")
        self.assertRaises(IndexError, lambda: self.dnobj[7])
        self.assertRaises(TypeError, lambda: self.dnobj['test'])
        def set_rdns():
            self.dnobj.rdns = (("dc", "test"),)
        self.assertRaises(ValueError, set_rdns)

    def test_str(self):
        """ Test __str__ method of LDAPDN object. """
        self.assertEqual(str(self.dnobj), self.strdn)

    def test_emptydn(self):
        """ Test empty distinguished name. """
        empty = LDAPDN("")
        self.assertEqual(empty[1:], "")

    def test_equal(self):
        """ Test __eq__ method of LDAPDN object. """
        self.assertEqual(self.dnobj, LDAPDN(self.strdn))
        self.assertEqual(self.dnobj, LDAPDN(self.strdn.title()))
        self.assertEqual(self.dnobj, self.strdn.upper())

    def test_invaliddn(self):
        """ Test InvalidDN exception. """
        self.assertRaises(errors.InvalidDN,
                          lambda: LDAPDN("cn=test,dc=one+two"))

    def test_special_char(self):
        """ Test parsing special characters in DN string. """
        spec = LDAPDN("cn=special\, name,dc=test,dc=local")
        self.assertEqual(str(spec), "cn=special\, name,dc=test,dc=local")

    def test_setitem(self):
        """ Test setting RDNs for DN object. """
        dnobj = LDAPDN("sn=some+gn=thing,dc=test,dc=local")
        self.assertEqual("sn=some+gn=thing", dnobj[0])
        dnobj[0] = "cn=user"
        self.assertEqual("cn=user,dc=test,dc=local", dnobj)
        dnobj[1] = "ou=group1,ou=group2"
        self.assertEqual("cn=user,ou=group1,ou=group2,dc=local", dnobj)
        dnobj[2:] = "dc=local"
        self.assertEqual("cn=user,ou=group1,dc=local", dnobj)
        def str_idx():
            dnobj['invalid'] = "ou=group1,ou=group2"
        self.assertRaises(TypeError, str_idx)
        def not_str():
            dnobj[0] = 3
        self.assertRaises(ValueError, not_str)
        def invalid():
            dnobj[1] = "test,group"
        self.assertRaises(errors.InvalidDN, invalid)

    def test_repr(self):
        """ Test representation. """
        self.assertIn("<LDAPDN", repr(self.dnobj))

    def test_escape_attribute_value(self):
        """ Test escaping special characters in attribute values. """
        self.assertEqual(escape_attribute_value(" dummy=test,something+somethingelse"),
                         "\ dummy\=test\,something\+somethingelse")
        self.assertEqual(escape_attribute_value("#dummy=test "),
                         "\#dummy\=test\ ")
        self.assertEqual(escape_attribute_value("term\0"), "term\\0")

if __name__ == '__main__':
    unittest.main()
