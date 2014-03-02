import unittest

from pyldap import LDAPDN
from pyldap import errors

class LDAPDNTest(unittest.TestCase):
    def setUp(self):
        self.strdn = "cn=user,dc=test,dc=local"
        self.dn = LDAPDN(self.strdn)

    def tearDown(self):
        del self.dn

    def test_rdn(self):
        self.assertEqual(self.dn[0], "cn=user")

    def test_ancestors(self):
        self.assertEqual(self.dn[1:], "dc=test,dc=local")

    def test_str(self):
        self.assertEqual(str(self.dn), self.strdn)

    def test_emptydn(self):
        empty = LDAPDN("")
        self.assertEqual(empty[1:], "")

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
