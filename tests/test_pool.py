import pytest

from bonsai import LDAPClient
from bonsai.pool import (
    ClosedPool,
    ConnectionPool,
    EmptyPool,
    PoolError,
    ThreadedConnectionPool,
)

import math
import threading
import time


def test_init():
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


def test_open(client):
    """ Test opening the pool. """
    pool = ConnectionPool(client, minconn=5)
    pool.open()
    assert pool.closed != True
    assert pool.idle_connection == 5


def test_close(client):
    """ Test closing the connection. """
    pool = ConnectionPool(client, minconn=1)
    pool.open()
    conn = pool.get()
    pool.close()
    assert pool.closed == True
    assert pool.idle_connection == 0
    assert pool.shared_connection == 0
    assert conn.closed == True


def test_get(client):
    """ Test getting a connection from the pool. """
    pool = ConnectionPool(client, minconn=1, maxconn=2)
    with pytest.raises(ClosedPool):
        _ = pool.get()
    pool.open()
    assert pool.max_connection == 2
    assert pool.idle_connection == 1
    assert pool.shared_connection == 0
    conn1 = pool.get()
    assert conn1 is not None
    assert conn1.closed == False
    assert pool.idle_connection == 0
    assert pool.shared_connection == 1
    conn2 = pool.get()
    assert pool.idle_connection == 0
    assert pool.shared_connection == 2
    with pytest.raises(EmptyPool):
        _ = pool.get()
    assert pool.empty == True


def test_put(client):
    """ Test putting connection back into the pool. """
    pool = ConnectionPool(client, minconn=1, maxconn=1)
    with pytest.raises(ClosedPool):
        pool.put(None)
    pool.open()
    conn = pool.get()
    assert pool.idle_connection == 0
    pool.put(conn)
    assert pool.idle_connection == 1
    other_conn = client.connect()
    with pytest.raises(PoolError):
        pool.put(other_conn)


def test_put_closed(client):
    """ Test closed connections are not put back into the pool. """
    pool = ConnectionPool(client, minconn=1, maxconn=1)
    pool.open()
    conn = pool.get()
    assert pool.idle_connection == 0
    assert pool.shared_connection == 1
    conn.close()
    pool.put(conn)
    assert pool.idle_connection == 0
    assert pool.shared_connection == 0

    # The pool is below its minimum connection count, but this shouldn't cause
    # problems and get should create a new connection.
    conn = pool.get()
    assert pool.idle_connection == 0
    assert pool.shared_connection == 1
    pool.put(conn)
    pool.close()


def test_max_connection():
    """ Test max_connection property. """
    cli = LDAPClient("ldap://dummy.nfo")
    pool = ConnectionPool(cli, minconn=5, maxconn=5)
    assert pool.max_connection == 5
    with pytest.raises(ValueError):
        pool.max_connection = 4
    pool.max_connection = 10
    assert pool.max_connection == 10


def test_spawn(client):
    """ Test context manager. """
    pool = ConnectionPool(client, minconn=1, maxconn=1)
    assert pool.idle_connection == 0
    with pool.spawn() as conn:
        _ = conn.whoami()
    assert pool.idle_connection == 1
    assert pool.shared_connection == 0


def keep(pool, sleep):
    try:
        with pool.spawn() as conn:
            time.sleep(sleep)
            assert not conn.closed
    except ClosedPool:
        pass


def test_threaded_pool_block(client):
    """ Test threaded pool blocks when it's empty. """
    sleep = 5
    pool = ThreadedConnectionPool(client, minconn=1, maxconn=1)
    pool.open()
    t0 = threading.Thread(target=keep, args=(pool, sleep))
    conn = pool.get()
    t0.start()
    pool.put(conn)
    time.sleep(2)
    start = time.time()
    conn = pool.get()
    # Some assertation that it didn't happen immediately.
    assert math.ceil(time.time() - start) + 1.2 >= sleep / 2.0
    assert not conn.closed
    pool.put(conn)


def test_threaded_pool_raise(client):
    """ Test threaded pool blocks when it's empty. """
    sleep = 5
    pool = ThreadedConnectionPool(client, minconn=1, maxconn=1, block=False)
    t0 = threading.Thread(target=keep, args=(pool, sleep))
    t0.start()
    time.sleep(2)
    with pytest.raises(EmptyPool):
        _ = pool.get()
    time.sleep(sleep + 1.2)
    conn = pool.get()
    assert conn.closed == False


def test_threaded_pool_close(client):
    """ Test closing threaded pool. """
    sleep = 5
    pool = ThreadedConnectionPool(client, minconn=1, maxconn=1, block=False)
    t0 = threading.Thread(target=keep, args=(pool, sleep))
    t0.start()
    time.sleep(2)
    pool.close()
    assert pool.closed
    t0.join()
