import threading
from contextlib import contextmanager
from typing import Optional, Any, Set, Generic, TypeVar, Generator

from .ldapconnection import BaseLDAPConnection, LDAPConnection

MYPY = False

if MYPY:
    from .ldapclient import LDAPClient


class PoolError(Exception):
    """Connection pool related errors."""

    pass


class ClosedPool(PoolError):
    """Raised, when the connection pool is closed."""

    pass


class EmptyPool(PoolError):
    """Raised, when the connection pool is empty."""

    pass


T = TypeVar("T", bound=BaseLDAPConnection)


class ConnectionPool(Generic[T]):
    """
    A connection pool object for managing multiple open connections.

    :param LDAPClient client: the :class:`bonsai.LDAPClient` that's used to create
                connections.
    :param int minconn: the minimum number of connections that's created
                after the pool is opened.
    :param int maxconn: the maximum number of connections in the pool.
    :param \\*\\*kwargs: additional keyword arguments that are passed to
                the :meth:`bonsai.LDAPClient.connect` method.
    :raises ValueError: when the minconn is negative or the maxconn is less
        than the minconn.
    """

    def __init__(
        self, client: "LDAPClient", minconn: int = 1, maxconn: int = 10, **kwargs: Any
    ) -> None:
        """Init method."""
        if minconn < 0:
            raise ValueError("The minconn must be positive.")
        if minconn > maxconn:
            raise ValueError("The maxconn must be greater than minconn.")
        self._minconn = minconn
        self._maxconn = maxconn
        self._client = client
        self._kwargs = kwargs
        self._closed = True
        self._idles: Set[T] = set()
        self._used: Set[T] = set()

    def open(self) -> None:
        """
        Open the connection pool by initialising the minimal number of
        connections.
        """
        for _ in range(self._minconn - self.idle_connection - self.shared_connection):
            self._idles.add(self._client.connect(**self._kwargs))
        self._closed = False

    def get(self) -> T:
        """
        Get a connection from the connection pool.

        :raises EmptyPool: when the pool is empty.
        :raises ClosedPool: when the method is called on a closed pool.
        :return: an LDAP connection object.
        """
        if self._closed:
            raise ClosedPool("The pool is closed.")
        try:
            conn = self._idles.pop()
        except KeyError:
            if len(self._used) < self._maxconn:
                conn = self._client.connect(**self._kwargs)
            else:
                raise EmptyPool("Pool is empty.") from None
        self._used.add(conn)
        return conn

    def put(self, conn: T) -> None:
        """
        Put back a connection to the connection pool. The caller is allowed to
        close the connection (if, for instance, it is in an error state), in
        which case it's not returned to the pool and a subsequent get will
        grow the pool if needed.

        :param LDAPConnection conn: the connection managed by the pool.
        :raises ClosedPool: when the method is called on a closed pool.
        :raises PoolError: when tying to put back an object that's not managed
                by this pool.
        """
        if self._closed:
            raise ClosedPool("The pool is closed.")
        try:
            self._used.remove(conn)
            if not conn.closed:
                self._idles.add(conn)
        except KeyError:
            raise PoolError("The %r is not managed by this pool." % conn) from None

    def close(self) -> None:
        """Close the pool and all of its managed connections."""
        for conn in self._idles:
            conn.close()
        for conn in self._used:
            conn.close()
        self._closed = True
        self._idles = set()
        self._used = set()

    @contextmanager
    def spawn(self, *args: Any, **kwargs: Any) -> Generator[T, None, None]:
        """
        Context manager method that acquires a connection from the pool
        and returns it on exit. It also opens the pool if it hasn't been
        opened before.

        :params \\*args: the positional arguments passed to
                :meth:`bonsai.pool.ConnectionPool.get`.
        :params \\*\\*kwargs: the keyword arguments passed to
                :meth:`bonsai.pool.ConnectionPool.get`.
        """
        conn = None
        try:
            if self._closed:
                self.open()
            conn = self.get(*args, **kwargs)
            yield conn
        finally:
            if conn:
                self.put(conn)

    @property
    def empty(self) -> bool:
        """
        Read-only property that will be True when the connection pool has
        no free connection to use.
        """
        return len(self._idles) == 0 and len(self._used) == self._maxconn

    @property
    def closed(self) -> bool:
        """
        Read-only property that will be True when the connection pool has
        been closed.
        """
        return self._closed

    @property
    def shared_connection(self) -> int:
        """The number of shared connections."""
        return len(self._used)

    @property
    def idle_connection(self) -> int:
        """the number of idle connection."""
        return len(self._idles)

    @property
    def max_connection(self) -> int:
        """The maximal number of connections that the pool can have."""
        return self._maxconn

    @max_connection.setter
    def max_connection(self, val: int) -> None:
        """The maximal number of connections that the pool can have."""
        if val < self._minconn:
            raise ValueError("The maxconn must be greater than minconn.")
        self._maxconn = val


class ThreadedConnectionPool(ConnectionPool[LDAPConnection]):
    """
    A connection pool that can be shared between threads. It's inherited from
    :class:`bonsai.pool.ConnectionPool`.

    :param LDAPClient client: the :class:`bonsai.LDAPClient` that's used to create
                connections.
    :param int minconn: the minimum number of connections that's created
                after the pool is opened.
    :param int maxconn: the maximum number of connections in the pool.
    :param bool block: when it's True, the get method will block when no
                connection is available in the pool.
    :param \\*\\*kwargs: additional keyword arguments that are passed to
                the :meth:`bonsai.LDAPClient.connect` method.
    :raises ValueError: when the minconn is negative or the maxconn is less
        than the minconn.
    """

    def __init__(
        self,
        client: "LDAPClient",
        minconn: int = 1,
        maxconn: int = 10,
        block: bool = True,
        **kwargs: Any
    ) -> None:
        """Init method."""
        super().__init__(client, minconn, maxconn, **kwargs)
        self._block = block
        self._lock = threading.Condition()

    def get(self, timeout: Optional[float] = None) -> LDAPConnection:
        """
        Get a connection from the connection pool.

        :param float timeout: a timeout until waiting for free connection.
        :raises EmptyPool: when the pool is empty.
        :raises ClosedPool: when the method is called on a closed pool.
        :return: an LDAP connection object.
        """
        with self._lock:
            if self._block:
                self._lock.wait_for(lambda: not self.empty or self._closed, timeout)
            conn = super().get()
            self._lock.notify()
            return conn

    def put(self, conn: LDAPConnection) -> None:
        with self._lock:
            super().put(conn)
            self._lock.notify()

    def close(self) -> None:
        with self._lock:
            super().close()
            self._lock.notify_all()

    def open(self) -> None:
        with self._lock:
            super().open()
