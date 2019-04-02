import asyncio

from ..pool import ConnectionPool, ClosedPool, EmptyPool

from .aioconnection import AIOLDAPConnection

MYPY = False

if MYPY:
    from ..ldapclient import LDAPClient


class AIOPoolContextManager:
    def __init__(self, pool, *args, **kwargs):
        self.pool = pool
        self.__conn = None

    async def __aenter__(self):
        if self.pool.closed:
            await self.pool.open()
        self.__conn = await self.pool.get()
        return self.__conn

    async def __aexit__(self, *exc):
        await self.pool.put(self.__conn)

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

    async def open(self):
        for _ in range(self._minconn):
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

    async def close(self):
        async with self._lock:
            super().close()
            self._lock.notify_all()

    def spawn(self, *args, **kwargs):
        return AIOPoolContextManager(self, *args, **kwargs)
