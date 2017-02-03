import configparser
import os.path
import unittest
import sys

import bonsai
from bonsai import LDAPReference
from bonsai import LDAPClient
from bonsai import LDAPURL

class LDAPClientTest(unittest.TestCase):
    """ Testing LDAPReference object. """
    @classmethod
    def setUpClass(cls):
        """ Set host url and connection. """
        curdir = os.path.abspath(os.path.dirname(__file__))
        cfg = configparser.ConfigParser()
        cfg.read(os.path.join(curdir, 'test.ini'))
        cls.url = "ldap://%s:%s" % (cfg["SERVER"]["hostip"],
                                    cfg["SERVER"]["port"])
        cls.client = LDAPClient(cls.url)

    def test_init_errors(self):
        """ Testing  errors during initialization of LDAPReference. """
        client = LDAPClient(self.url)
        self.assertRaises(TypeError, lambda: LDAPReference(None, ["ldap://a"]))
        self.assertRaises(TypeError, lambda: LDAPReference(client, [0]))
        self.assertRaises(ValueError,
                          lambda: LDAPReference(client,
                                                ["asd", LDAPURL("ldap://b")]))

    def test_client_prop(self):
        """ Testing client property. """
        client = LDAPClient(self.url)
        ref = LDAPReference(client, [])
        self.assertEqual(ref.client, client)
        def error():
            ref.client = "b"
        self.assertRaises(TypeError, error)
        ref.client = LDAPClient()
        self.assertNotEqual(ref.client, client)

    def test_references_prop(self):
        """ Testing references property. """
        client = LDAPClient(self.url)
        reflist = [LDAPURL("ldap://localhost"), self.url]
        ref = LDAPReference(client, reflist)
        self.assertCountEqual(ref.references, reflist)
        def error():
            ref.references = None
        self.assertRaises(ValueError, error)

    def test_referral_chasing(self):
        """ Testing referral chasing option. """
        if sys.platform == "win32":
            self.skipTest("Referrals are not set in AD.")
        refdn = "o=admin-ref,ou=nerdherd,dc=bonsai,dc=test"
        client = LDAPClient(self.url)
        conn = client.connect()
        res = conn.search(refdn, 0)
        self.assertIsInstance(res[0], bonsai.LDAPEntry)
        conn.close()
        client.server_chase_referrals = False
        conn = client.connect()
        res = conn.search(refdn, 0)
        self.assertEqual(len(res), 0)
        res = conn.search("ou=nerdherd,dc=bonsai,dc=test", 1)
        refs = [item for item in res if isinstance(item, LDAPReference)]
        self.assertTrue(any(refs))

if __name__ == '__main__':
    unittest.main()
