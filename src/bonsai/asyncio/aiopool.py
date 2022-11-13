import asyncio
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, Optional

from ..pool import ConnectionPool, ClosedPool, EmptyPool

from .aioconnection import AIOLDAPConnection

MYPY = False

if MYPY:
    from ..ldapclient import LDAPClient


class AIOConnectionPool(ConnectionPool[AIOLDAPConnection]):
    """
    A connection pool that can be used with asnycio tasks. It's inherited from
    :class:`bonsai.pool.ConnectionPool`.

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
        self,
        client: "LDAPClient",
        minconn: int = 1,
        maxconn: int = 10,
        loop: Optional[asyncio.AbstractEventLoop] = None,
        **kwargs: Any
    ):
        super().__init__(client, minconn, maxconn, **kwargs)
        self._loop = loop
        try:
            # The loop parameter is deprecated since 3.8, removed in 3.10
            # and it raises TypeError.
            self._lock = asyncio.Condition(loop=self._loop)
        except TypeError:
            self._lock = asyncio.Condition()

    async def open(self) -> None:
        async with self._lock:
            for _ in range(
                self._minconn - self.idle_connection - self.shared_connection
            ):
                conn = await self._client.connect(
                    is_async=True, loop=self._loop, **self._kwargs
                )
                self._idles.add(conn)
            self._closed = False

    async def get(self) -> AIOLDAPConnection:
        async with self._lock:
            if self._closed:
                raise ClosedPool("The pool is closed.")
            await self._lock.wait_for(lambda: not self.empty or self._closed)
            try:
                conn = self._idles.pop()
            except KeyError:
                if len(self._used) < self._maxconn:
                    conn = await self._client.connect(
                        is_async=True, loop=self._loop, **self._kwargs
                    )
                else:
                    raise EmptyPool("Pool is empty.") from None
            self._used.add(conn)
            self._lock.notify()
            return conn

    async def put(self, conn: AIOLDAPConnection) -> None:
        async with self._lock:
            super().put(conn)
            self._lock.notify()

    async def close(self) -> None:
        async with self._lock:
            super().close()
            self._lock.notify_all()

    @asynccontextmanager
    async def spawn(
        self, *args: Any, **kwargs: Any
    ) -> AsyncGenerator[AIOLDAPConnection, None]:
        conn = None
        try:
            if self._closed:
                await self.open()
            conn = await self.get(*args, **kwargs)
            yield conn
        finally:
            if conn:
                await self.put(conn)
