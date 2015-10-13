import configparser
import os
import unittest

from bonsai import LDAPDN
from bonsai import LDAPClient
from bonsai import LDAPConnection
import bonsai.errors

class LDAPConnectionTest(unittest.TestCase):
    """ Test LDAPConnection object. """
    def setUp(self):
        """ Set LDAP URL and open connection. """
        curdir = os.path.abspath(os.path.dirname(__file__))
        self.cfg = configparser.ConfigParser()
        self.cfg.read(os.path.join(curdir, 'test.ini'))
        self.url = "ldap://%s:%s/%s?%s?%s" % (self.cfg["SERVER"]["host"], \
                                        self.cfg["SERVER"]["port"], \
                                        self.cfg["SERVER"]["basedn"], \
                                        self.cfg["SERVER"]["search_attr"], \
                                        self.cfg["SERVER"]["search_scope"])
        self.basedn = self.cfg["SERVER"]["basedn"]
        client = LDAPClient(self.url)
        client.set_credentials("SIMPLE", (self.cfg["SIMPLEAUTH"]["user"],
                                          self.cfg["SIMPLEAUTH"]["password"]))
        self.conn = client.connect()
        self.async_conn = LDAPConnection(client, True)

    def tearDown(self):
        """ Close connection. """
        self.conn.close()
        del self.conn

    def test_bind_digest(self):
        """ Test DIGEST-MD5 connection. """
        if "DIGESTAUTH" not in self.cfg:
            self.skipTest("No digest authentication is set.")
        client = LDAPClient(self.url)
        if self.cfg["DIGESTAUTH"]["realm"] == "None":
            realm = None
        else:
            realm = self.cfg["DIGESTAUTH"]["realm"]
        if self.cfg["DIGESTAUTH"]["authzid"] == "None":
            authzid = None
        else:
            authzid = self.cfg["DIGESTAUTH"]["authzid"]
        client.set_credentials("DIGEST-MD5", (self.cfg["DIGESTAUTH"]["user"], \
                                        self.cfg["DIGESTAUTH"]["password"], \
                                        realm, authzid))
        try:
            conn = client.connect()
        except (bonsai.errors.ConnectionError, \
                bonsai.errors.AuthenticationError):
            self.fail()
        finally:
            self.assertNotEqual("anonymous", conn.whoami(), "Digest "
            "authentication was unsuccessful.")
            conn.close()

    def test_search(self):
        """ Test searching. """
        obj = self.conn.search(self.basedn, 2)
        self.assertIsNotNone(obj)
        self.assertEqual(obj, self.conn.search())

    def test_search_ldapdn(self):
        """ Test searching with LDAPDN object. """
        ldap_dn = LDAPDN(self.basedn)
        obj = self.conn.search(ldap_dn, 1)
        self.assertIsNotNone(obj)

    def test_search_attr(self):
        """ Test searching with given list of attributes. """
        obj = self.conn.search(self.basedn, 2, "(objectclass=person)",
                               ['cn'])[0]
        self.assertIsNotNone(obj)
        if 'cn' not in obj.keys():
            self.fail()

    def test_add_and_delete(self):
        entry = bonsai.LDAPEntry("cn=example,%s" % self.cfg["SERVER"]["basedn"])
        entry.update({"objectclass" : ["top", "inetorgperson"], "cn" : "example", "sn" : "example"})
        try:
            self.conn.add(entry)
            self.conn.delete("cn=example,%s" % self.cfg["SERVER"]["basedn"])
        except bonsai.LDAPError:
            self.fail("Add and delete new entry is failed.")

    def test_whoami(self):
        """ Test whoami. """
        obj = self.conn.whoami()
        expected_res = "dn:%s" % self.cfg["SIMPLEAUTH"]["user"]
        self.assertEqual(obj, expected_res)

    def test_tls(self):
        """ Test TLS connection. """
        if self.cfg['SERVER']['has_tls'] == 'False':
            self.skipTest("TLS is not set.")
        client = LDAPClient(self.url, True)
        client.set_cert_policy("ALLOW")
        client.set_ca_cert(None)
        client.set_ca_cert_dir(None)
        try:
            conn = client.connect()
            conn.close()
        except:
            self.fail("TLS connection is failed")

    def test_connection_error(self):
        """ Test connection error. """
        client = LDAPClient("ldap://invalid")
        self.assertRaises(bonsai.ConnectionError, lambda : client.connect())

    def test_simple_auth_error(self):
        """ Test simple authentication error. """
        client = LDAPClient(self.url)
        client.set_credentials("SIMPLE", ("cn=wrong", "wronger"))
        self.assertRaises(bonsai.AuthenticationError, lambda : client.connect())

    def test_digest_auth_error(self):
        """ Test DIGEST-MD5 authentication error. """
        if "DIGESTAUTH" not in self.cfg:
            self.skipTest("No digest authentication is set.")
        client = LDAPClient(self.url)
        if self.cfg["DIGESTAUTH"]["realm"] == "None":
            realm = None
        else:
            realm = self.cfg["DIGESTAUTH"]["realm"]
        client.set_credentials("DIGEST-MD5", (self.cfg["DIGESTAUTH"]["user"], \
                                        "wrongpassword", \
                                        realm, None))
        self.assertRaises(bonsai.AuthenticationError, lambda : client.connect())

    def test_sort_order(self):
        """ Test setting sort order. """
        self.conn.set_sort_order(["-uidNumber"])
        obj = self.conn.search(self.basedn, 2, attrlist=['uidNumber'])
        sort = [o['uidNumber'][0] for o in obj if 'uidNumber' in o]
        self.assertTrue((all(sort[i] >= sort[i+1]
                             for i in range(len(sort)-1))), "Not sorted")

    def test_fileno(self):
        """ Test fileno method. """
        self.assertIsInstance(self.conn.fileno(), int)
        try:
            import socket
            sock = socket.fromfd(self.conn.fileno(),
                                 socket.AF_INET,
                                 socket.SOCK_RAW)
            self.assertEqual(sock.getpeername(),
                            (self.cfg["SERVER"]["host"],
                             int(self.cfg["SERVER"]["port"])))
            sock.close()
        except OSError:
            self.fail("Not a valid socket descriptor.")

    def test_close(self):
        """ Test close method. """
        self.conn.close()
        self.assertTrue(self.conn.closed)
        self.assertRaises(bonsai.ClosedConnection, self.conn.whoami)

    def test_cancel(self):
        """ Test cancel method. """
        msgid = self.async_conn.open()
        self.async_conn.get_result(msgid, True)
        msgid = self.async_conn.search(self.basedn, 2)
        self.async_conn.cancel(msgid)
        self.assertRaises(bonsai.InvalidMessageID,
                          lambda: self.async_conn.get_result(msgid, True))

if __name__ == '__main__':
    unittest.main()
