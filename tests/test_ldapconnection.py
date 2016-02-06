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
        if (not self.async_conn.closed):
            self.async_conn.close()
        del self.conn
        del self.async_conn

    def _binding(self, auth, mech, authzid):
        if auth not in self.cfg:
            self.skipTest("%s authentication is not set." % mech)
        client = LDAPClient(self.url)
        if self.cfg[auth]["realm"] == "None":
            realm = None
        else:
            realm = self.cfg[auth]["realm"]
        client.set_credentials(mech, (self.cfg[auth]["user"],
                                      self.cfg[auth]["password"],
                                      realm, authzid))
        try:
            conn = client.connect()
        except (bonsai.errors.ConnectionError, \
                bonsai.errors.AuthenticationError):
            self.fail()
        else:
            self.assertNotEqual("anonymous", conn.whoami(),
                                "%s authentication was unsuccessful." % mech)
            return conn

    def test_bind_digest(self):
        """ Test DIGEST-MD5 connection. """
        conn = self._binding("DIGESTAUTH", "DIGEST-MD5", None)
        conn.close()

    def test_bind_digest_with_authzid(self):
        """ Test DIGEST-MD5 connection with authorization ID. """
        if self.cfg["DIGESTAUTH"]["authzid"] == "None":
            self.skipTest("Authorization ID is not set.")
        authzid = self.cfg["DIGESTAUTH"]["authzid"]
        conn = self._binding("DIGESTAUTH", "DIGEST-MD5", authzid)
        self.assertEqual(self.cfg["DIGESTAUTH"]["dn"], conn.whoami(),
                         "Digest authorization was failed. ")

    def test_bind_ntlm(self):
        """ Test NTLM connection. """
        conn = self._binding("NTLMAUTH", "NTLM", None)
        conn.close()

    def _bind_gssapi_kinit(self, authzid):
        import sys
        import subprocess
        if sys.platform == "win32":
             self.skipTest("Cannot use Kerberos auth on Windows"
                           " against OpenLDAP")
        cmd = 'echo "%s" | kinit %s' % (self.cfg["GSSAPIAUTH"]["password"],
                                        self.cfg["GSSAPIAUTH"]["user"])
        try:
            subprocess.check_output(cmd, shell=True)
            conn = self._binding("GSSAPIAUTH", "GSSAPI", authzid)
            subprocess.check_output("kdestroy", shell=True)
            return conn
        except subprocess.CalledProcessError:
            self.fail("Receiving TGT is failed.")

    def test_bind_gssapi_kinit(self):
        """ Test GSSAPI connection. """
        conn = self._bind_gssapi_kinit(None)

    def test_bind_gssapi_with_authzid_kinit(self):
        """ Test GSSAPI connection with authorization ID. """
        if self.cfg["GSSAPIAUTH"]["authzid"] == "None":
            self.skipTest("Authorization ID is not set.")
        authzid = self.cfg["GSSAPIAUTH"]["authzid"]
        conn = self._bind_gssapi_kinit(authzid)
        self.assertEqual(self.cfg["GSSAPIAUTH"]["dn"], conn.whoami(),
                         "Digest authorization was failed. ")
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
        except Exception as exc:
            self.fail("TLS connection is failed with: %s" % str(exc))

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

    def test_abandon(self):
        """ Test abandon method. """
        msgid = self.async_conn.open()
        while self.async_conn.get_result(msgid) is None:
            pass
        msgid = self.async_conn.search(self.basedn, 2)
        self.async_conn.abandon(msgid)
        self.assertRaises(bonsai.InvalidMessageID,
                          lambda: self.async_conn.get_result(msgid))

    def test_async_close_remove_pendig_ops(self):
        """ Test remove pending operations after close. """
        msgid = self.async_conn.open()
        while self.async_conn.get_result(msgid) is None:
            pass
        self.async_conn.search(self.basedn, 2)
        self.async_conn.search(self.basedn, 0)
        self.async_conn.close()
        self.assertTrue(self.async_conn.closed)

if __name__ == '__main__':
    unittest.main()