import configparser
import os
import sys
import unittest
import subprocess
import tempfile
import time
import xmlrpc.client as rpc

import bonsai
from bonsai import LDAPDN
from bonsai import LDAPClient
from bonsai import LDAPConnection
from bonsai import LDAPSearchScope
import bonsai.errors
from bonsai.errors import ClosedConnection

def invoke_kinit(user, password):
    """ Invoke kinit command with credential parameters. """
    proc = subprocess.Popen(['kinit', '--version'], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, universal_newlines=True)
    output = " ".join(proc.communicate())
    if "Heimdal" in output:
        # Heimdal Kerberos implementation.
        with tempfile.NamedTemporaryFile() as psw_tmp:
            psw_tmp.write(password.encode())
            psw_tmp.flush()
            cmd = ['kinit', '--password-file=%s' % psw_tmp.name, user]
            subprocess.check_call(cmd)
    else:
        # MIT Kerberos implementation.
        cmd = 'echo "%s" | kinit %s' % (password, user)
        subprocess.check_output(cmd, shell=True)

def receive_search_timeout(client, ipaddr, search_dn):
    """ Set network delay and wait for a TimeoutError during search. """
    conn = client.connect()
    proxy = rpc.ServerProxy("http://%s:%d/" % (ipaddr, 8000))
    proxy.set_delay(6.1)
    time.sleep(3.0)
    return conn.search(search_dn, 1, timeout=3.2)

def receive_whoami_timeout(client, ipaddr):
    """ Set network delay and wait for a TimeoutError during whoami. """
    conn = client.connect()
    proxy = rpc.ServerProxy("http://%s:%d/" % (ipaddr, 8000))
    proxy.set_delay(4.1)
    time.sleep(3.0)
    return conn.whoami(timeout=3.2)

class LDAPConnectionTest(unittest.TestCase):
    """ Test LDAPConnection object. """
    def setUp(self):
        """ Set LDAP URL and open connection. """
        curdir = os.path.abspath(os.path.dirname(__file__))
        self.cfg = configparser.ConfigParser()
        self.cfg.read(os.path.join(curdir, 'test.ini'))
        self.ipaddr = self.cfg["SERVER"]["hostip"]
        self.url = "ldap://%s:%s/ou=nerdherd,%s?%s?%s" % \
            (self.cfg["SERVER"]["hostip"], self.cfg["SERVER"]["port"],
             self.cfg["SERVER"]["basedn"], self.cfg["SERVER"]["search_attr"],
             self.cfg["SERVER"]["search_scope"])
        self.host = "ldap://%s" % self.cfg['SERVER']['hostname']
        self.basedn = self.cfg["SERVER"]["basedn"]
        client = LDAPClient(self.url)
        client.set_credentials("SIMPLE", (self.cfg["SIMPLEAUTH"]["user"],
                                          self.cfg["SIMPLEAUTH"]["password"]))
        client.auto_page_acquire = False
        self.conn = client.connect()
        self.async_conn = LDAPConnection(client, True)

    def tearDown(self):
        """ Close connection. """
        self.conn.close()
        if not self.async_conn.closed:
            self.async_conn.close()
        del self.conn
        del self.async_conn

    def _binding(self, auth, mech, authzid, realm=None):
        if auth not in self.cfg:
            self.skipTest("%s authentication is not set." % mech)
        client = LDAPClient(self.host)
        client.set_credentials(mech, (self.cfg[auth]["user"],
                                      self.cfg[auth]["password"],
                                      realm, authzid))
        try:
            conn = client.connect()
        except (bonsai.errors.ConnectionError, \
                bonsai.errors.AuthenticationError) as err:
            self.fail(err)
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
        if sys.platform == "win32":
            self.skipTest("Authz is not set on AD.")
        authzid = self.cfg["DIGESTAUTH"]["authzid"]
        with self._binding("DIGESTAUTH", "DIGEST-MD5", authzid) as conn:
            self.assertEqual(self.cfg["DIGESTAUTH"]["dn"], conn.whoami(),
                             "Digest authorization was failed. ")

    @unittest.skipIf(sys.platform.startswith("win"),
                     "NTLM is not enabled on Windows.")
    def test_bind_ntlm(self):
        """ Test NTLM connection. """
        conn = self._binding("NTLMAUTH", "NTLM", None)
        conn.close()

    def _bind_gssapi_kinit(self, authzid):
        if sys.platform == "win32":
            self.skipTest("Cannot use Kerberos kinit auth on Windows "
                          "against OpenLDAP")
        try:
            invoke_kinit(self.cfg["GSSAPIAUTH"]["user"],
                         self.cfg["GSSAPIAUTH"]["password"])
            conn = self._binding("GSSAPIAUTH", "GSSAPI", authzid)
            subprocess.check_call("kdestroy")
            return conn
        except subprocess.CalledProcessError:
            self.fail("Receiving TGT is failed.")

    def test_bind_gssapi_kinit(self):
        """ Test GSSAPI connection. """
        self._bind_gssapi_kinit(None)

    def test_bind_gssapi_with_authzid_kinit(self):
        """ Test GSSAPI connection with authorization ID. """
        if self.cfg["GSSAPIAUTH"]["authzid"] == "None":
            self.skipTest("Authorization ID is not set.")
        authzid = self.cfg["GSSAPIAUTH"]["authzid"]
        conn = self._bind_gssapi_kinit(authzid)
        self.assertEqual(self.cfg["GSSAPIAUTH"]["dn"], conn.whoami(),
                         "GSSAPI authorization was failed. ")
        conn.close()

    @unittest.skipIf(not bonsai.has_krb5_support(),
                     "Module doesn't have KRB5 support.")
    def test_bind_gssapi(self):
        """ Test GSSAPI connection with automatic TGT requesting. """
        if ("realm" not in self.cfg["GSSAPIAUTH"]
                or self.cfg["GSSAPIAUTH"]["realm"] == "None"):
            self.skipTest("Realm is not set.")
        if sys.platform == "linux":
            # Make sure keytab is empty.
            subprocess.check_call("kdestroy")
        conn = self._binding("GSSAPIAUTH", "GSSAPI", None,
                             self.cfg["GSSAPIAUTH"]["realm"].upper())
        conn.close()

    def test_bind_gssapi_error(self):
        """ Test automatic TGT requesting with wrong realm name. """
        if "GSSAPIAUTH" not in self.cfg:
            self.skipTest("GSSAPI authentication is not set.")
        if not bonsai.has_krb5_support():
            self.skipTest("Module doesn't have KRB5 support.")
        if ("realm" not in self.cfg["GSSAPIAUTH"]
                or self.cfg["GSSAPIAUTH"]["realm"] == "None"):
            self.skipTest("Realm is not set.")
        client = LDAPClient(self.url)
        client.set_credentials("GSSAPI", (self.cfg["GSSAPIAUTH"]["user"],
                                          self.cfg["GSSAPIAUTH"]["password"],
                                          self.cfg["GSSAPIAUTH"]["realm"],
                                          None))
        self.assertRaises(bonsai.AuthenticationError, client.connect)

    def _bind_external(self, authzid):
        if 'EXTERNALAUTH' not in self.cfg:
            self.skipTest("EXTERNAL authentication is not set.")
        if sys.platform == "win32":
            self.skipTest("Windows relies on set certs in its cert store.")
        tls_impl = bonsai.get_tls_impl_name()
        if tls_impl == "GnuTLS" or tls_impl == "OpenSSL":
            curdir = os.path.abspath(os.path.dirname(__file__))
            cert_path = os.path.join(curdir, 'testenv', 'certs')
            cli = LDAPClient(self.host, tls=True)
            cli.set_ca_cert(cert_path + '/cacert.pem')
            cli.set_client_cert(cert_path + '/client.pem')
            cli.set_client_key(cert_path + '/client.key')
            cli.set_credentials('EXTERNAL', (authzid,))
            try:
                conn = cli.connect()
            except (bonsai.errors.ConnectionError,
                    bonsai.errors.AuthenticationError):
                self.fail()
            else:
                self.assertNotEqual("anonymous", conn.whoami(),
                                    "EXTERNAL authentication was"
                                    " unsuccessful.")
                return conn
        else:
            self.skipTest("")

    def test_bind_external(self):
        """ Test EXTERNAL connection. """
        conn = self._bind_external(None)
        conn.close()

    def test_bind_external_with_authzid(self):
        """ Test EXTERNAL connection with authorization ID. """
        if self.cfg["EXTERNALAUTH"]["authzid"] == "None":
            self.skipTest("Authorization ID is not set.")
        authzid = self.cfg["EXTERNALAUTH"]["authzid"]
        with self._bind_external(authzid) as conn:
            self.assertEqual(self.cfg["EXTERNALAUTH"]["dn"], conn.whoami(),
                             "EXTERNAL authorization was failed. ")

    def test_search(self):
        """ Test searching. """
        obj = self.conn.search("ou=nerdherd,%s" % self.basedn,
                               LDAPSearchScope.SUB)
        self.assertIsNotNone(obj)
        self.assertCountEqual(obj, self.conn.search())

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

    def test_search_attrsonly(self):
        """ Test search receiving only attributes. """
        obj = self.conn.search(self.basedn, 2, "(objectclass=person)",
                               ['cn'], attrsonly=True)[0]
        self.assertIsNotNone(obj)
        self.assertListEqual(obj['cn'], [])

    def test_add_and_delete(self):
        """ Test adding and removing an LDAP entry. """
        entry = bonsai.LDAPEntry("cn=example,%s" % self.basedn)
        entry.update({"objectclass" : ["top", "inetorgperson"],
                      "cn" : "example", "sn" : "example"})
        try:
            self.conn.add(entry)
            res = self.conn.search(entry.dn, 0)
            self.assertEqual(res[0], entry)
            self.conn.delete("cn=example,%s" % self.cfg["SERVER"]["basedn"])
            res = self.conn.search(entry.dn, 0)
            self.assertListEqual(res, [])
            self.assertRaises(ValueError,
                              lambda: self.conn.add(bonsai.LDAPEntry("")))
        except bonsai.LDAPError:
            self.fail("Add and delete new entry is failed.")

    def test_recursive_delete(self):
        """ Test removing a subtree recursively. """
        org1 = bonsai.LDAPEntry("ou=testusers,%s" % self.basedn)
        org1.update({"objectclass" : ['organizationalUnit', 'top'],
                     "ou" : "testusers"})
        org2 = bonsai.LDAPEntry("ou=tops,ou=testusers,%s" % self.basedn)
        org2.update({"objectclass" : ['organizationalUnit', 'top'], "ou" : "tops"})
        entry = bonsai.LDAPEntry("cn=tester,ou=tops,ou=testusers,%s" % self.basedn)
        entry.update({"objectclass" : ["top", "inetorgperson"],
                      "cn" : "tester", "sn" : "example"})
        try:
            self.conn.add(org1)
            self.conn.add(org2)
            self.conn.add(entry)
            self.conn.delete(org1.dn, recursive=True)
            res = self.conn.search(org1.dn, 2)
            self.assertListEqual(res, [])
        except bonsai.LDAPError:
            self.fail("Recursive delete is failed.")

    def test_whoami(self):
        """ Test whoami. """
        obj = self.conn.whoami()
        expected_res = ["dn:%s" % self.cfg["SIMPLEAUTH"]["user"],
                        self.cfg["SIMPLEAUTH"]["adusername"]]
        self.assertIn(obj, expected_res)

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
        self.assertRaises(bonsai.ConnectionError, client.connect)

    def test_simple_auth_error(self):
        """ Test simple authentication error. """
        client = LDAPClient(self.url)
        client.set_credentials("SIMPLE", ("cn=wrong", "wronger"))
        self.assertRaises(bonsai.AuthenticationError, client.connect)

    def test_digest_auth_error(self):
        """ Test DIGEST-MD5 authentication error. """
        if "DIGESTAUTH" not in self.cfg:
            self.skipTest("No digest authentication is set.")
        client = LDAPClient(self.url)
        if self.cfg["DIGESTAUTH"]["realm"] == "None":
            realm = None
        else:
            realm = self.cfg["DIGESTAUTH"]["realm"]
        client.set_credentials("DIGEST-MD5", (self.cfg["DIGESTAUTH"]["user"],
                                              "wrongpassword",
                                              realm, None))
        self.assertRaises(bonsai.AuthenticationError, client.connect)

    def test_sort_order(self):
        """ Test setting sort order. """
        obj = self.conn.search(self.basedn, 2, attrlist=['uidNumber'],
                               sort_order=["-uidNumber"])
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
                             (self.cfg["SERVER"]["hostip"],
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

    def test_vlv_offset(self):
        """ Test VLV control with offset. """
        search_dn = "ou=nerdherd,%s" % self.basedn
        res, ctrl = self.conn.search(search_dn, 1, attrlist=['uidNumber'],
                                     offset=2, sort_order=["-uidNumber"],
                                     before_count=1, after_count=1,
                                     est_list_count=6)
        self.assertEqual(len(res), 3)
        self.assertEqual(ctrl['target_position'], 2)
        self.assertEqual(ctrl['list_count'], 6)
        self.assertEqual(res[1]['uidNumber'][0], 4)

    def test_vlv_attrvalue(self):
        """ Test VLV control with attribute value. """
        search_dn = "ou=nerdherd,%s" % self.basedn
        res, ctrl = self.conn.search(search_dn, 1, attrlist=['uidNumber'],
                                     attrvalue=2, sort_order=["uidNumber"],
                                     before_count=1, after_count=2,
                                     est_list_count=6)
        self.assertEqual(len(res), 4)
        self.assertEqual(ctrl['target_position'], 3)
        self.assertEqual(res[0]['uidNumber'][0], 1)

    def test_vlv_without_sort_order(self):
        """ Test VLV control wihtout sort control. """
        search_dn = "ou=nerdherd,%s" % self.basedn
        self.assertRaises(bonsai.UnwillingToPerform,
                          lambda: self.conn.search(search_dn, 1,
                                                   attrlist=['uidNumber'],
                                                   offset=1, before_count=1,
                                                   after_count=2,
                                                   est_list_count=6))

    def test_vlv_with_page_size(self):
        """ Test VLV control wiht page size. """
        search_dn = "ou=nerdherd,%s" % self.basedn
        self.assertRaises(bonsai.UnwillingToPerform,
                          lambda: self.conn.search(search_dn, 1, page_size=3,
                                                   sort_order=["-uidNumber"],
                                                   attrvalue=1, before_count=1,
                                                   after_count=2,
                                                   est_list_count=6))

    def test_paged_search(self):
        """ Test paged results control. """
        search_dn = "ou=nerdherd,%s" % self.basedn
        res = self.conn.search(search_dn, 1, page_size=2)
        for ent in res:
            self.assertIsInstance(ent, bonsai.LDAPEntry)
        page = 1  # First page already is acquired.
        while True:
            if len(res) > 2:
                self.fail("The size of the page is greater than expected.")
            msgid = res.acquire_next_page()
            if msgid is None:
                break
            res = self.conn.get_result(msgid)
            page += 1
        self.assertEqual(page, 3)

    def test_paged_search_with_auto_acq(self):
        """ Test paged results control with automatic page acquiring. """
        client = LDAPClient(self.url)
        conn = client.connect()
        search_dn = "ou=nerdherd,%s" % self.basedn
        res = conn.search(search_dn, 1, page_size=3)
        if len(res) != 3:
            self.fail("The size of the page is not what is expected.")
        entry = 0
        for ent in res:
            self.assertIsInstance(ent, bonsai.LDAPEntry)
            entry += 1
        self.assertEqual(entry, 6)
        self.assertIsNone(res.acquire_next_page())

    def test_search_timeout(self):
        """ Test search's timeout. """
        search_dn = "ou=nerdherd,%s" % self.basedn
        import multiprocessing
        self.assertRaises(TypeError,
                          lambda: self.conn.search(search_dn, 1, timeout=True))
        self.assertRaises(ValueError,
                          lambda: self.conn.search(search_dn, 1, timeout=-15))
        proxy = rpc.ServerProxy("http://%s:%d/" % (self.ipaddr, 8000))
        pool = multiprocessing.Pool(processes=1)
        try:
            client = LDAPClient(self.url)
            result = pool.apply_async(receive_search_timeout,
                                      args=(client, self.ipaddr, search_dn))
            result.get(timeout=9.0)
        except Exception as exc:
            self.assertIsInstance(exc, bonsai.TimeoutError)
        else:
            self.fail("Failed to receive TimeoutError.")
        finally:
            pool.terminate()
            proxy.remove_delay()

    def test_whoami_timeout(self):
        """ Test whoami's timeout. """
        import multiprocessing
        self.assertRaises(TypeError,
                          lambda: self.conn.whoami(timeout='A'))
        self.assertRaises(ValueError,
                          lambda: self.conn.whoami(timeout=-10))
        self.assertRaises(bonsai.TimeoutError,
                          lambda: self.conn.whoami(timeout=0))
        proxy = rpc.ServerProxy("http://%s:%d/" % (self.ipaddr, 8000))
        pool = multiprocessing.Pool(processes=1)
        try:
            client = LDAPClient(self.url)
            result = pool.apply_async(receive_whoami_timeout,
                                      args=(client, self.ipaddr))
            result.get(timeout=9.0)
        except Exception as exc:
            self.assertIsInstance(exc, bonsai.TimeoutError)
        else:
            self.fail("Failed to receive TimeoutError.")
        finally:
            pool.terminate()
            proxy.remove_delay()

    def test_wrong_conn_param(self):
        """ Test passing wrong parameters for LDAPConnection. """
        self.assertRaises(TypeError, lambda: LDAPConnection("wrong"))
        self.assertRaises(TypeError, lambda: LDAPConnection(LDAPClient(), 1))

    def test_wrong_search_param(self):
        """ Test passing wrong parameters for search method. """
        def close_conn():
            cli = LDAPClient("ldap://%s" % self.ipaddr)
            LDAPConnection(cli).search()
        def missing_scope():
            cli = LDAPClient("ldap://%s" % self.ipaddr)
            LDAPConnection(cli).open().search()
        def wrong():
            cli = LDAPClient("ldap://%s" % self.ipaddr)
            LDAPConnection(cli).open().search("", 0, 3)
        self.assertRaises(ClosedConnection, close_conn)
        self.assertRaises(ValueError, missing_scope)
        self.assertRaises(TypeError, wrong)

    def test_wrong_add_param(self):
        """ Test passing wrong parameter for add method. """
        def close_conn():
            cli = LDAPClient("ldap://%s" % self.ipaddr)
            LDAPConnection(cli).add(bonsai.LDAPEntry("cn=dummy"))
        self.assertRaises(ClosedConnection, close_conn)
        self.assertRaises(TypeError, lambda: self.conn.add("wrong"))

    def test_wrong_delete_param(self):
        """ Test passing wrong parameter for delete method. """
        def close_conn():
            cli = LDAPClient("ldap://%s" % self.ipaddr)
            LDAPConnection(cli).delete("cn=dummy")
        self.assertRaises(ClosedConnection, close_conn)
        self.assertRaises(TypeError, lambda: self.conn.delete(0))

    def test_password_lockout(self):
        """ Test password locking with password policy. """
        if sys.platform == "win32":
            self.skipTest("Cannot use password policy on Windows")
        user_dn = "cn=jeff,ou=nerdherd,dc=bonsai,dc=test"
        cli = LDAPClient("ldap://%s" % self.ipaddr)
        cli.set_password_policy(True)
        try:
            cli.set_credentials("SIMPLE", (user_dn, "wrong_pass"))
            conn, ctrl = cli.connect()
        except bonsai.errors.AuthenticationError:
            try:
                cli.set_credentials("SIMPLE", (user_dn, "p@ssword"))
                conn, ctrl = cli.connect()
            except Exception as exc:
                self.assertIsInstance(exc, bonsai.errors.AccountLocked)
            else:
                self.fail("No exception.")
        finally:
            entry = self.conn.search(user_dn, 0,
                                     attrlist=["pwdAccountLockedTime"])[0]
            if "pwdAccountLockedTime" in entry.keys():
                del entry['pwdAccountLockedTime']
                entry.modify()

    @unittest.skipIf(sys.platform.startswith("win"),
                     "Cannot use password policy on Windows")
    def test_password_expire(self):
        """ Test password expiring with password policy. """
        user_dn = "cn=skip,ou=nerdherd,dc=bonsai,dc=test"
        cli = LDAPClient("ldap://%s" % self.ipaddr)
        cli.set_password_policy(True)
        cli.set_credentials("SIMPLE", (user_dn, "p@ssword"))
        conn, ctrl = cli.connect()
        entry = conn.search(user_dn, 0)[0]
        entry['userPassword'] = "newvalidpassword"
        entry.modify()
        conn.close()
        cli.set_credentials("SIMPLE", (user_dn, "newvalidpassword"))
        time.sleep(2.0)
        conn, ctrl = cli.connect()
        if not (ctrl['expire'] <= 10 and ctrl['expire'] > 0):
            self.fail("Expire time is in "
                      "the wrong range (Expire: %d)." % ctrl['expire'])
        conn.close()
        time.sleep(10)
        conn, ctrl = cli.connect()
        self.assertEqual(ctrl['grace'], 1)
        conn.close()
        try:
            conn, ctrl = cli.connect()
        except Exception as exc:
            self.assertIsInstance(exc, bonsai.errors.PasswordExpired)
        finally:
            entry = self.conn.search(user_dn, 0,
                                     attrlist=["userPassword"])[0]
            entry['userPassword'] = "p@ssword"
            entry.modify()
            entry = self.conn.search(user_dn, 0,
                                     attrlist=["pwdChangeTime",
                                               "pwdGraceUseTime"])[0]
            if ("pwdChangeTime", "pwdGraceUseTime") in entry.keys():
                del entry['pwdChangeTime']
                del entry['pwdGraceUseTime']
                entry.modify()

    @unittest.skipIf(sys.platform.startswith("win"),
                     "Cannot use password modify extended opertion on Windows")
    def test_password_modify_extop(self):
        """ Test Password Modify extended operation. """
        user_dn = LDAPDN("cn=skip,ou=nerdherd,dc=bonsai,dc=test")
        cli = LDAPClient("ldap://%s" % self.ipaddr)
        cli.set_credentials("SIMPLE", (str(user_dn), "p@ssword"))
        conn = cli.connect()
        self.assertRaises(TypeError,
                          lambda: conn.modify_password(new_password=0))
        conn.modify_password(user_dn, "newpassword", "p@ssword")
        conn.close()
        self.assertRaises(ClosedConnection, conn.modify_password)
        try:
            cli.set_credentials("SIMPLE", (str(user_dn), "newpassword"))
            cli.set_password_policy(True)
            conn, ctrl = cli.connect()
            newpass = conn.modify_password()
            conn.close()
            self.assertIsInstance(newpass, str)
            cli.set_credentials("SIMPLE", (str(user_dn), newpass))
            conn, ctrl = cli.connect()
            conn.close()
        except bonsai.AuthenticationError:
            self.fail("Failed to authenticate with the new password.")
        finally:
            entry = self.conn.search(user_dn, 0,
                                     attrlist=["userPassword"])[0]
            entry['userPassword'] = "p@ssword"
            entry.modify()
            entry = self.conn.search(user_dn, 0,
                                     attrlist=["pwdChangeTime",
                                               "pwdGraceUseTime"])[0]
            if ("pwdChangeTime", "pwdGraceUseTime") in entry.keys():
                del entry['pwdChangeTime']
                del entry['pwdGraceUseTime']
                entry.modify()

    @unittest.skipIf(sys.platform.startswith("win"),
                     "Cannot use ManageDsaIT on Windows")
    def test_search_with_managedsait_ctrl(self):
        """ Test searching with manageDsaIT control. """
        refdn = LDAPDN("o=admin-ref,ou=nerdherd,dc=bonsai,dc=test")
        cli = LDAPClient("ldap://%s" % self.ipaddr)
        with cli.connect() as conn:
            res = conn.search(refdn, LDAPSearchScope.BASE, attrlist=['ref'])[0]
            self.assertEqual(str(res.dn), "cn=admin,dc=bonsai,dc=test")
        cli.set_managedsait(True)
        with cli.connect() as conn:
            res = conn.search(refdn, LDAPSearchScope.BASE, attrlist=['ref'])[0]
            self.assertEqual(refdn, res.dn)
            self.assertEqual('ldap://bonsai.test/cn=admin,dc=bonsai,dc=test',
                             res['ref'][0])

if __name__ == '__main__':
    unittest.main()
