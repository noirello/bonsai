import asyncio

from ..pool import ConnectionPool, ClosedPool, EmptyPool

from .aioconnection import AIOLDAPConnection

MYPY = False

if MYPY:
    from ..ldapclient import LDAPClient


class AIOConnectionPool(ConnectionPool):
    def __init__(
        self,
        client: "LDAPClient",
        minconn: int = 1,
        maxconn: int = 10,
        loop=None,
        **kwargs
    ):
        super().__init__(client, minconn, maxconn, **kwargs)
        self._loop = loop
        self._lock = asyncio.Condition(loop=self._loop)

    @asyncio.coroutine
    def open(self):
        for _ in range(self._minconn):
            conn = yield from self._client.connect(
                is_async=True, loop=self._loop, **self._kwargs
            )
            self._idles.add(conn)
        self._closed = False

    @asyncio.coroutine
    def get(self) -> AIOLDAPConnection:
        with (yield from self._lock):
            if self._closed:
                raise ClosedPool("The pool is closed.")
            yield from self._lock.wait_for(lambda: not self.empty or self._closed)
            try:
                conn = self._idles.pop()
            except KeyError:
                if len(self._used) < self._maxconn:
                    conn = yield from self._client.connect(
                        is_async=True, loop=self._loop, **self._kwargs
                    )
                else:
                    raise EmptyPool("Pool is empty.") from None
            self._used.add(conn)
            self._lock.notify()
            return conn

    @asyncio.coroutine
    def put(self, conn: AIOLDAPConnection) -> None:
        with (yield from self._lock):
            super().put(conn)
            self._lock.notify()

    @asyncio.coroutine
    def close(self):
        with (yield from self._lock):
            super().close()
            self._lock.notify_all()
