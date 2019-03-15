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
        self._closed = False
        self._idles = set()
        self._used = set()

    def open(self):
        for _ in range(self._minconn):
            self._idles.add(self._client.connect())

    def get(self):
        if self._closed:
            raise ClosedPool("The pool is closed.")
        try:
            conn = self._idles.pop()
        except IndexError:
            if len(self._used) < self._maxconn:
                conn = self._client.connect()
            else:
                raise EmptyPool("Pool is empty.")
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

    def close(self):
        for conn in self._idles:
            conn.close()
        for conn in self._used:
            conn.close()
        self._closed = True
