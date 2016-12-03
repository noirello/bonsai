import configparser
import os.path
import unittest
import time
import xmlrpc.client as rpc

import bonsai
from bonsai import LDAPClient
from bonsai.ldapconnection import LDAPConnection

def receive_timeout_error(client):
    """ Function for connection TimeoutError. """
    client.connect(timeout=7.0)

class LDAPClientTest(unittest.TestCase):
    """ Testing LDAPClient object. """
    @classmethod
    def setUpClass(cls):
        """ Set host url and connection. """
        curdir = os.path.abspath(os.path.dirname(__file__))
        cfg = configparser.ConfigParser()
        cfg.read(os.path.join(curdir, 'test.ini'))
        cls.ipaddr = cfg["SERVER"]["hostip"]
        cls.url = "ldap://%s:%s" % (cls.ipaddr, cfg["SERVER"]["port"])
        cls.client = LDAPClient(cls.url)
        proxy = rpc.ServerProxy("http://%s:%d/" % (cls.ipaddr, 8000))
        proxy.remove_delay()

    def test_ldapurl(self):
        """ Test setting LDAPURL. """
        url = bonsai.LDAPURL(self.url)
        client = LDAPClient(url)
        self.assertEqual(client.url, url)
        self.assertRaises(TypeError, lambda: LDAPClient(None))

    def test_connect(self):
        """ Test connect method. """
        self.assertIsNotNone(self.client.connect())

    def test_rootdse(self):
        """ Test receiving root DSE. """
        root_dse = self.client.get_rootDSE()
        self.assertEqual(root_dse['supportedLDAPVersion'][0], 3)

    def test_raw_attributes(self):
        """ Test setting raw attributes to keep in bytearray format. """
        def type_err():
            self.client.set_raw_attributes([5])
        def value_err():
            self.client.raw_attributes = ['ou', 'cn', 'ou']
        self.assertRaises(TypeError, type_err)
        self.assertRaises(ValueError, value_err)
        self.client.set_raw_attributes(["ou"])
        conn = self.client.connect()
        result = conn.search("ou=nerdherd,dc=bonsai,dc=test", 0)[0]
        if type(result["ou"][0]) != bytes:
            self.fail("The type of the value is not bytes.")
        if type(result["objectClass"][0]) == bytes:
            self.fail("Not set attribute is bytes.")

    def test_set_credentials(self):
        """
        Test setcredentials method, mechanism and credentials properties.
        """
        self.assertRaises(TypeError,
                          lambda: self.client.set_credentials(2323, (None,)))
        self.assertRaises(TypeError,
                          lambda: self.client.set_credentials("Simple",
                                                              "pass"))
        self.assertRaises(TypeError, lambda: self.client
                          .set_credentials("Simple", ("Name", 2, None, None)))
        self.assertRaises(ValueError, lambda: self.client
                          .set_credentials("EXTERNAL", (None, None)))
        self.assertRaises(ValueError, lambda: self.client
                          .set_credentials("SIMPLE", (None, None, None)))
        self.assertRaises(ValueError, lambda: self.client
                          .set_credentials("DIGEST-MD5", (None, None)))
        self.client.set_credentials("SIMPLE", ("cn=admin", "password"))
        self.assertEqual(self.client.mechanism, "SIMPLE")
        self.assertEqual(self.client.credentials, ("cn=admin", "password"))
        self.client.set_credentials("EXTERNAL", ("authzid",))
        self.assertEqual(self.client.credentials, (None, None, None, "authzid"))

    def test_vendor_info(self):
        """ Test vendor information. """
        info = bonsai.get_vendor_info()
        if len(info) != 2:
            self.fail()
        self.assertIsInstance(info[0], str)
        self.assertIsInstance(info[1], int)

    def test_tls_impl_name(self):
        """ Test TLS implementation name. """
        tls_impl = bonsai.get_tls_impl_name()
        self.assertIn(tls_impl, ("GnuTLS", "MozNSS", "OpenSSL", "SChannel"))


    def test_connection_timeout(self):
        """
        Test connection timeout. Runs in a separate process,
        because that can be easily polled and terminated.
        """
        import multiprocessing
        self.assertRaises(TypeError, lambda: self.client.connect(timeout="Wrong"))
        self.assertRaises(ValueError, lambda: self.client.connect(timeout=-1.5))
        self.assertRaises(bonsai.TimeoutError, lambda: self.client.connect(timeout=0))
        proxy = rpc.ServerProxy("http://%s:%d/" % (self.ipaddr, 8000))
        proxy.set_delay(9.0, 15)
        time.sleep(3.0)
        pool = multiprocessing.Pool(processes=1)
        try:
            result = pool.apply_async(receive_timeout_error, args=(self.client,))
            result.get(timeout=18.0)
        except Exception as exc:
            self.assertIsInstance(exc, bonsai.TimeoutError)
        else:
            self.fail("Failed to receive TimeoutError.")
        finally:
            pool.terminate()
            proxy.remove_delay()

    def test_ppolicy(self):
        """ Test password policy setting. """
        client = LDAPClient(self.url)
        self.assertRaises(TypeError, lambda: client.set_password_policy("F"))
        client.password_policy = True
        client.set_credentials("SIMPLE", ("cn=chuck,ou=nerdherd,dc=bonsai,dc=test",
                                          "p@ssword"))
        ret_val = client.connect()
        self.assertIsInstance(ret_val, tuple)
        self.assertIsInstance(ret_val[0], LDAPConnection)
        if ret_val[1] is None:
            pass
        elif type(ret_val[1]) == dict:
            self.assertIn("oid", ret_val[1].keys())
            self.assertIn("expire", ret_val[1].keys())
            self.assertIn("grace", ret_val[1].keys())
            self.assertEqual('1.3.6.1.4.1.42.2.27.8.5.1', ret_val[1]['oid'])
        else:
            self.fail("Invalid second object in the tuple.")
        ret_val[0].close()

    def test_extended_dn(self):
        """ Test extended dn control. """
        client = LDAPClient(self.url)
        self.assertRaises(TypeError, lambda: client.set_extended_dn("A"))
        self.assertRaises(ValueError, lambda: client.set_extended_dn(2))
        client.extended_dn_format = 0
        self.assertEqual(client.extended_dn_format, 0)
        conn = client.connect()
        root_dse = client.get_rootDSE()
        result = conn.search("ou=nerdherd,dc=bonsai,dc=test", 0)[0]
        if '1.2.840.113556.1.4.529' in root_dse['supportedControl']:
            self.assertIsNotNone(result.extended_dn)
            self.assertEqual(result.extended_dn.split(';')[-1], str(result.dn))
        else:
            self.assertIsNone(result.extended_dn)

    def test_readonly_attributes(self):
        """ Test read-only attributes of LDAPClient. """
        def set_url():
            self.client.url = "ldap://test"
        self.assertRaises(ValueError, set_url)
        def set_mechanism():
            self.client.mechanism = "SIMPLE"
        self.assertRaises(ValueError, set_mechanism)
        def set_credentials():
            self.client.credentials = ("test", "test", None, None)
        self.assertRaises(ValueError, set_credentials)
        def set_tls():
            self.client.tls = False
        self.assertRaises(ValueError, set_tls)

    def test_auto_acquire_prop(self):
        """ Test auto_page_acquire property. """
        client = LDAPClient(self.url)
        self.assertRaises(TypeError, lambda: client.set_auto_page_acquire("A"))
        self.assertTrue(client.auto_page_acquire)
        client.auto_page_acquire = False
        self.assertFalse(client.auto_page_acquire)

if __name__ == '__main__':
    unittest.main()
