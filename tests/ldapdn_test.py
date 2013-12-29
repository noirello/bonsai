import unittest

from pyLDAP import LDAPDN
from pyLDAP import errors

class LDAPDNTest(unittest.TestCase):
    def setUp(self):
        self.strdn = "cn=user,dc=test,dc=local"
        self.dn = LDAPDN(self.strdn)

    def tearDown(self):
        del self.dn

    def test_rdn(self):
        self.assertEqual(self.dn.get_rdn(0), "cn=user")

    def test_ancestors(self):
        self.assertEqual(self.dn.get_ancestors(), "dc=test,dc=local")

    def test_str(self):
        self.assertEqual(str(self.dn), self.strdn)

    def test_emptydn(self):
        empty = LDAPDN("")
        self.assertEqual(empty.get_ancestors(), "")

    def test_equel(self):
        self.assertEqual(self.dn, LDAPDN(self.strdn))

    def test_rdns(self):
        self.assertEqual(self.dn.rdns[1], (("dc", "test"),))

    def invalid(self):
        return LDAPDN("cn=test,dc=one+two")

    def test_invaliddn(self):
        self.assertRaises(errors.InvalidDN, self.invalid)

if __name__ == '__main__':
    unittest.main()
