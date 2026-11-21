import configparser
import os
import time
import uuid
from contextlib import contextmanager

import pytest

import bonsai
from bonsai import LDAPClient
from bonsai.active_directory.acl import ACE, ACEFlag, ACEType
from bonsai.active_directory.sid import SID


from bonsai.ldapconnection import BaseLDAPConnection
from helpers import PausableTCPProxy

# Waiting for a response must not use the CPU. A busy loop would use ~1.0 s here.
MAX_IDLE_CPU = 0.4


def get_config() -> configparser.ConfigParser:
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


@contextmanager
def pausable_proxy():
    """Start a PausableProxy in front of the LDAP server of the test config."""
    cfg = get_config()

    with PausableTCPProxy(
        cfg["SERVER"]["hostip"], cfg.getint("SERVER", "port")
    ) as proxy:
        yield proxy


def new_client_with_simple_auth(
    host: str | None = None,
    port: int | None = None,
    conn_class: type[BaseLDAPConnection] | None = None,
):
    cfg = get_config()
    url = "ldap://%s:%s/%s??%s" % (
        host or cfg["SERVER"]["hostip"],
        port or cfg["SERVER"]["port"],
        cfg["SERVER"]["basedn"],
        cfg["SERVER"]["search_scope"],
    )
    cli = LDAPClient(url)
    cli.set_credentials(
        "SIMPLE", user=cfg["SIMPLEAUTH"]["user"], password=cfg["SIMPLEAUTH"]["password"]
    )
    if conn_class is not None:
        cli.set_async_connection_class(conn_class)
    return cli


@pytest.fixture(scope="module")
def client():
    """Get an LDAPClient with simple authentication."""
    return new_client_with_simple_auth()


@pytest.fixture(scope="module")
def basedn():
    """Get base DN."""
    cfg = get_config()
    return cfg["SERVER"]["basedn"]


@pytest.fixture(scope="module")
def cfg():
    """Get config."""
    return get_config()


@pytest.fixture
def test_ace() -> ACE:
    """Test ACE object"""
    return ACE(
        ACEType.ACCESS_ALLOWED,
        {ACEFlag.INHERITED},
        0x80000000,
        SID("S-1-1-0"),
        None,
        uuid.UUID("c975c901-6cea-4b6f-8319-d67f45449506"),
        b"",
    )


@pytest.fixture
def turn_async_conn():
    bonsai.set_connect_async(True)
    yield None
    bonsai.set_connect_async(False)


@pytest.fixture
def set_auto_page_acquire(monkeypatch):
    """Set automatic page acquisition for the duration of a test."""

    def set_value(client, enabled):
        monkeypatch.setattr(client, "auto_page_acquire", enabled)
        return client

    return set_value
