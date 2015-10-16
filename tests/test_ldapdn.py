import unittest

from bonsai import LDAPDN
from bonsai import errors

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

    def test_invaliddn(self):
        """ Test InvalidDN exception. """
        self.assertRaises(errors.InvalidDN,
                          lambda: LDAPDN("cn=test,dc=one+two"))

    def test_special_char(self):
        """ Test parsing special characters in DN string. """
        spec = LDAPDN("cn=specal\, name,dc=test,dc=local")
        self.assertEqual(str(spec), "cn=specal\, name,dc=test,dc=local")

if __name__ == '__main__':
    unittest.main()
