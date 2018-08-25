import configparser
import os.path
import sys

import pytest

import bonsai
from bonsai import LDAPReference
from bonsai import LDAPClient
from bonsai import LDAPURL


@pytest.fixture
def host_url():
    """ Set host url for connection. """
    curdir = os.path.abspath(os.path.dirname(__file__))
    cfg = configparser.ConfigParser()
    cfg.read(os.path.join(curdir, "test.ini"))
    url = "ldap://%s:%s" % (cfg["SERVER"]["hostip"], cfg["SERVER"]["port"])
    return url


def test_init_errors(host_url):
    """ Testing errors during initialization of LDAPReference. """
    client = LDAPClient(host_url)
    with pytest.raises(TypeError):
        _ = LDAPReference(None, ["ldap://a"])
    with pytest.raises(TypeError):
        _ = LDAPReference(client, [0])
    with pytest.raises(ValueError):
        _ = LDAPReference(client, ["asd", LDAPURL("ldap://b")])


def test_client_prop(host_url):
    """ Testing client property. """
    client = LDAPClient(host_url)
    ref = LDAPReference(client, [])
    assert ref.client == client
    with pytest.raises(TypeError):
        ref.client = "b"

    ref.client = LDAPClient()
    assert ref.client != client


def test_references_prop(host_url):
    """ Testing references property. """
    client = LDAPClient(host_url)
    reflist = [LDAPURL("ldap://localhost"), host_url]
    ref = LDAPReference(client, reflist)
    assert ref.references == reflist
    with pytest.raises(ValueError):
        ref.references = None


@pytest.mark.skipif(
    sys.platform.startswith("win"), reason="Referrals are not set in AD."
)
def test_referral_chasing(host_url):
    """ Testing referral chasing option. """
    refdn = "o=admin-ref,ou=nerdherd,dc=bonsai,dc=test"
    client = LDAPClient(host_url)
    with client.connect() as conn:
        res = conn.search(refdn, 0)
        assert isinstance(res[0], bonsai.LDAPEntry)
    client.server_chase_referrals = False
    with client.connect() as conn:
        res = conn.search(refdn, 0)
        assert len(res) == 0
        res = conn.search("ou=nerdherd,dc=bonsai,dc=test", 1)
        refs = [item for item in res if isinstance(item, LDAPReference)]
        assert any(refs)
