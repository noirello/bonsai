import unittest

from pyldap import LDAPURL
from pyldap import LDAPDN

class LDAPURLTest(unittest.TestCase):
    """ Testing LDAPURL object. """
    def setUp(self):
        """ Set test URL. """
        self.strurl = "ldaps://testurl:444/cn=test,dc=test?sn,gn?base?(objectclass=*)"
        self.url = LDAPURL(self.strurl)

    def test_get_address(self):
        """ Test get_address method. """
        self.assertEqual(self.url.get_address(), "ldaps://testurl:444")

    def test_host_properties(self):
        """ Test LDAPURL host properties. """
        self.assertEqual(self.url.scheme, "ldaps")
        self.assertEqual(self.url.host, "testurl")
        self.assertEqual(self.url.port, 444)

    def test_bind_properties(self):
        """ Test LDAPURL bind properties. """
        self.assertEqual(self.url.basedn, LDAPDN("cn=test,dc=test"))
        self.assertEqual(self.url.scope, "base")
        self.assertEqual(self.url.filter, "(objectclass=*)")
        self.assertEqual(self.url.attributes, ["sn", "gn"])

    def test_str(self):
        """ Test __str__ method of LDAPURL. """
        self.assertEqual(str(self.url), self.strurl)

    def test_conversion(self):
        """ Test ValueError exception for invalid URL format. """
        self.assertRaises(ValueError,
                          lambda: LDAPURL("ldap://failed.com/?falsedn?d"))

if __name__ == '__main__':
    unittest.main()
