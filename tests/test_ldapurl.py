import unittest

from bonsai import LDAPURL
from bonsai import LDAPDN
from bonsai.errors import InvalidDN

class LDAPURLTest(unittest.TestCase):
    """ Testing LDAPURL object. """
    def setUp(self):
        """ Set test URL. """
        self.strurl = "ldaps://testurl:444/cn=test,dc=test?sn,gn?base?(objectclass=*)?1.2.3.4"
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
            url.basedn = "test"
        self.assertRaises(InvalidDN, invalid_basedn)
        url.basedn = LDAPDN("cn=test")
        self.assertEqual(str(url.basedn), "cn=test")

    def test_str(self):
        """ Test __str__ method of LDAPURL. """
        self.assertEqual(str(self.url), self.strurl)
        self.assertEqual(str(LDAPURL("ldap://127.0.0.1/cn=x?cn")),
                         "ldap://127.0.0.1:389/cn=x?cn")
        self.assertEqual(str(LDAPURL("ldap:///")), "ldap://localhost:389")
        self.assertIn("<LDAPURL", repr(self.url))

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

    def test_invalid(self):
        """ Test invalid LDAP URLs. """
        self.assertRaises(ValueError,
                          lambda: LDAPURL("http://localhost"))
        self.assertRaises(ValueError,
                          lambda: LDAPURL("ldaps://localost."))

    def test_scope(self):
        """ Test scope and scope_num property. """
        url = LDAPURL("ldap:///??one")
        self.assertEqual(url.scope_num, 1)
        url.scope = "base"
        self.assertEqual(url.scope_num, 0)
        def invalid_scope_type():
            self.url.scope = 2.1
        self.assertRaises(TypeError, invalid_scope_type)
        def invalid_scope_value():
            url.scope = 'all'
        self.assertRaises(ValueError, invalid_scope_value)

    def test_ipv6(self):
        """ Test IPv6 address """
        url = LDAPURL("ldap://[2001:db8:85a3::8a2e:370:7334]:1498/"
                      "o=University%20of%20Michigan,c=US??one?"
                      "(cn=Babs%20Jensen)")
        self.assertEqual(url.host, "2001:db8:85a3::8a2e:370:7334")
        self.assertEqual(url.port, 1498)
        self.assertEqual(url.scope, "one")
        self.assertEqual(url.filter, "(cn=Babs Jensen)")
        addr = url.get_address()
        self.assertEqual(addr, "ldap://[2001:db8:85a3::8a2e:370:7334]:1498")
        self.assertRaises(ValueError,
                          lambda: LDAPURL("ldap://2001::85::37:7334"))

if __name__ == '__main__':
    unittest.main()
