import threading
from typing import Optional

from .ldapclient import LDAPClient


class PoolError(Exception):
    pass


class ClosedPool(PoolError):
    pass


class EmptyPool(PoolError):
    pass


class ConnectionPool:
    def __init__(self, client: LDAPClient, minconn: int = 1, maxconn: int = 10):
        if minconn < 0:
            raise AttributeError("The minconn must be positive.")
        if minconn > maxconn:
            raise AttributeError("The maxconn must be greater than minconn,")
        self._minconn = minconn
        self._maxconn = maxconn
        self._client = client
        self._closed = True
        self._idles = set()
        self._used = set()

    def open(self):
        for _ in range(self._minconn):
            self._idles.add(self._client.connect())
        self._closed = False

    def get(self):
        if self._closed:
            raise ClosedPool("The pool is closed.")
        try:
            conn = self._idles.pop()
        except KeyError:
            if len(self._used) < self._maxconn:
                conn = self._client.connect()
            else:
                raise EmptyPool("Pool is empty.") from None
        self._used.add(conn)
        return conn

    def put(self, conn):
        if self._closed:
            raise ClosedPool("The pool is closed.")
        try:
            self._used.remove(conn)
            self._idles.add(conn)
        except KeyError:
            raise PoolError("The %r is not managed by this pool." % conn) from None

    @property
    def empty(self):
        return len(self._idles) == 0 and len(self._used) == self._maxconn

    def close(self):
        for conn in self._idles:
            conn.close()
        for conn in self._used:
            conn.close()
        self._closed = True
        self._idles = set()
        self._used = set()


class ThreadedConnectionPool(ConnectionPool):
    def __init__(
        self,
        client: LDAPClient,
        minconn: int = 1,
        maxconn: int = 10,
        block: bool = True,
    ):
        super().__init__(client, minconn, maxconn)
        self._block = block
        self._lock = threading.Condition()

    def get(self, timeout: Optional[float] = None):
        self._lock.acquire()
        try:
            if self._block:
                self._lock.wait_for(lambda: not self.empty or self._closed, timeout)
            conn = super().get()
            self._lock.notify()
            return conn
        finally:
            self._lock.release()

    def put(self, conn):
        self._lock.acquire()
        try:
            super().put(conn)
            self._lock.notify()
        finally:
            self._lock.release()

    def close(self):
        self._lock.acquire()
        try:
            super().close()
            self._lock.notify_all()
        finally:
            self._lock.release()
