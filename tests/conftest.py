import configparser
import os
import time
from contextlib import contextmanager

import pytest

from bonsai import LDAPClient


def get_config():
    """Load config parameters."""
    curdir = os.path.abspath(os.path.dirname(__file__))
    cfg = configparser.ConfigParser()
    cfg.read(os.path.join(curdir, "test.ini"))
    return cfg


@contextmanager
def network_delay(delay):
    import xmlrpc.client as rpc

    ipaddr = get_config()["SERVER"]["hostip"]
    proxy = rpc.ServerProxy("http://%s:%d/" % (ipaddr, 8000))
    proxy.set_delay(delay)
    time.sleep(2.0)
    try:
        yield proxy
    finally:
        proxy.remove_delay()


@pytest.fixture(scope="module")
def client():
    """Get an LDAPClient with simple authentication."""
    cfg = get_config()
    url = "ldap://%s:%s/%s??%s" % (
        cfg["SERVER"]["hostip"],
        cfg["SERVER"]["port"],
        cfg["SERVER"]["basedn"],
        cfg["SERVER"]["search_scope"],
    )
    cli = LDAPClient(url)
    cli.set_credentials(
        "SIMPLE", user=cfg["SIMPLEAUTH"]["user"], password=cfg["SIMPLEAUTH"]["password"]
    )
    return cli


@pytest.fixture(scope="module")
def basedn():
    """Get base DN."""
    cfg = get_config()
    return cfg["SERVER"]["basedn"]


@pytest.fixture(scope="module")
def cfg():
    """Get config."""
    return get_config()
