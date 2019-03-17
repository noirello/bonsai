import pytest

from bonsai import LDAPClient
from bonsai.pool import ConnectionPool


def test_init_pool():
    """ Test pool initialisation. """
    cli = LDAPClient("ldap://dummy.nfo")
    with pytest.raises(ValueError):
        _ = ConnectionPool(cli, minconn=-3)
    with pytest.raises(ValueError):
        _ = ConnectionPool(cli, minconn=5, maxconn=3)
    pool = ConnectionPool(cli, minconn=2, maxconn=5)
    assert pool.closed == True
    assert pool.empty == False
    assert pool.max_connection == 5
    assert pool.shared_connection == 0
    assert pool.idle_connection == 0
