import unittest

from pyldap import LDAPURL
from pyldap import LDAPDN

class LDAPURLTest(unittest.TestCase):
    def setUp(self):
        self.strurl = "ldaps://testurl:444/cn=test,dc=test?sn,gn?base?(objectclass=*)"
        self.url = LDAPURL(self.strurl)

    def tearDown(self):
        del self.url
        del self.strurl

    def test_get_address(self):
        self.assertEqual(self.url.get_address(), "ldaps://testurl:444")

    def test_host_properties(self):
        self.assertEqual(self.url.scheme, "ldaps")
        self.assertEqual(self.url.host, "testurl")
        self.assertEqual(self.url.port, 444)

    def test_bind_properties(self):
        self.assertEqual(self.url.basedn, LDAPDN("cn=test,dc=test"))
        self.assertEqual(self.url.scope, "base")
        self.assertEqual(self.url.filter, "(objectclass=*)")
        self.assertEqual(self.url.attributes, ["sn", "gn"])

    def test_str(self):
        self.assertEqual(str(self.url), self.strurl)

    def failed_convert(self):
        return LDAPURL("ldap://failed.com/?falsedn?d")

    def test_conversion(self):
        self.assertRaises(ValueError, self.failed_convert)

if __name__ == '__main__':
    unittest.main()
