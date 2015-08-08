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

    def test_get_host_properties(self):
        """ Test getting LDAPURL host properties. """
        self.assertEqual(self.url.scheme, "ldaps")
        self.assertEqual(self.url.host, "testurl")
        self.assertEqual(self.url.port, 444)

    def test_set_host_properties(self):
        """ Test setting LDAPURL host properties. """
        url = LDAPURL()
        def invalid_host():
            url.host = ":malformed,@äđĐ-"
        self.assertRaises(ValueError, invalid_host)
        def invalid_port():
            url.port = '9922'
        self.assertRaises(ValueError, invalid_port)
        def invalid_scheme():
            url.scheme = 'http'
        self.assertRaises(ValueError, invalid_scheme)
        url.host = 'testurl2'
        url.port = 589
        url.scheme = 'ldap'
        self.assertEqual(url.scheme, "ldap")
        self.assertEqual(url.host, "testurl2")
        self.assertEqual(url.port, 589)

    def test_get_bind_properties(self):
        """ Test getting LDAPURL bind properties. """
        self.assertEqual(self.url.basedn, LDAPDN("cn=test,dc=test"))
        self.assertEqual(self.url.scope, "base")
        self.assertEqual(self.url.filter, "(objectclass=*)")
        self.assertEqual(self.url.attributes, ["sn", "gn"])

    def test_set_bind_properties(self):
        """ Test setting LDAPURL bind properties. """
        url = LDAPURL()
        def invalid_basedn():
            url.basedn = "cn=test"
        self.assertRaises(ValueError, invalid_basedn)
        def invalid_scope():
            url.scope = 'all'
        self.assertRaises(ValueError, invalid_scope)

    def test_str(self):
        """ Test __str__ method of LDAPURL. """
        self.assertEqual(str(self.url), self.strurl)

    def test_conversion(self):
        """ Test ValueError exception for invalid URL format. """
        self.assertRaises(ValueError,
                          lambda: LDAPURL("ldap://failed.com/?falsedn?d"))

    def test_del_attr(self):
        """ Test trying to delete an attribute. """
        def test():
            del self.url.host
        self.assertRaises(Exception, test)
        try:
            self.url.host
        except AttributeError:
            self.fail("Attribute not should be deleted.")

if __name__ == '__main__':
    unittest.main()
