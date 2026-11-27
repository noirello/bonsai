from asyncio.events import AbstractEventLoop
import asyncio
from typing import Any, Coroutine, Generator, TYPE_CHECKING, Awaitable

from ..ldapconnection import BaseLDAPConnection, LDAPSearchScope
from ..errors import NotAllowedOnNonleaf

if TYPE_CHECKING:
    from types import TracebackType
    from ..ldapclient import LDAPClient
    from ..ldapdn import LDAPDN


class AIOLDAPConnection(BaseLDAPConnection):
    """
    Asynchronous LDAP connection object that works with asyncio.
    It has the same methods and properties as :class:`bonsai.LDAPConnection`, but
    with the exception of :meth:`bonsai.LDAPConnection.close` and
    :meth:`bonsai.LDAPConnection.fileno` all of them are awaitable.

    :param LDAPClient client: a client object.
    :param loop: an asyncio IO loop. By default (None) every operation runs on
        the loop it is awaited on, setting it ties the connection to that single
        loop for every operation.
    """

    def __init__(
        self, client: "LDAPClient", loop: asyncio.AbstractEventLoop | None = None
    ):
        self._loop: AbstractEventLoop | None = loop
        self.__open_coro: Awaitable[AIOLDAPConnection] | None = None
        self.__auto_page_acquire = client.auto_page_acquire
        self.__watched_fd: int | None = None
        super().__init__(client, is_async=True)

    async def __aenter__(self) -> "AIOLDAPConnection":
        """Async context manager entry point."""
        return await self.__open_coro

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        tb: "TracebackType | None",
    ) -> None:
        """Async context manager exit point."""
        self.close()

    def __await__(self) -> Generator[Any, None, "AIOLDAPConnection"]:
        return self.__open_coro.__await__()  # Hack to avoid returning a coroutine.

    __iter__ = __await__

    def _watch(
        self, msg_id: int, loop: asyncio.AbstractEventLoop, fut: asyncio.Future
    ) -> None:
        fd = self.fileno()
        loop.add_reader(fd, self._ready, msg_id, loop, fut)
        if self._wants_write(msg_id):
            loop.add_writer(fd, self._ready, msg_id, loop, fut)
        self.__watched_fd = fd

    def _unwatch(self, loop: asyncio.AbstractEventLoop) -> None:
        fd, self.__watched_fd = self.__watched_fd, None
        if fd is not None and fd > -1:
            loop.remove_reader(fd)
            loop.remove_writer(fd)

    def _ready(
        self, msg_id: int, loop: asyncio.AbstractEventLoop, fut: asyncio.Future
    ) -> None:
        self._unwatch(loop)
        if fut.done():
            # The waiter is gone (timeout or cancellation), nothing to deliver.
            return
        try:
            res = super().get_result(msg_id)
            if res is None:
                self._watch(msg_id, loop, fut)
            else:
                fut.set_result(res)
        except Exception as exc:
            fut.set_exception(exc)

    async def _poll(self, msg_id: int, timeout: float | None = None) -> Awaitable[Any]:
        loop = self._loop or asyncio.get_running_loop()
        fut = loop.create_future()
        self._watch(msg_id, loop, fut)
        try:
            return await asyncio.wait_for(fut, timeout)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            # CancelledError is a BaseException, it has to be handled explicitly.
            raise
        finally:
            self._unwatch(loop)

    def _evaluate(self, msg_id, timeout=None) -> Awaitable[Any]:
        return self._poll(msg_id, timeout)

    def open(self, timeout=None) -> "AIOLDAPConnection":  # type: ignore[override]
        self.__open_coro = super().open(timeout)
        return self

    async def delete(  # type: ignore[override]
        self, dname: "str | LDAPDN", timeout: float | None = None, recursive: bool = False
    ) -> bool:
        try:
            return await super().delete(dname, timeout, recursive)
        except NotAllowedOnNonleaf as exc:
            if recursive:
                results = await self.search(
                    dname, LDAPSearchScope.ONELEVEL, attrlist=["1.1"], timeout=timeout
                )
                for res in results:
                    await self.delete(res.dn, timeout, True)
                return await self.delete(dname, timeout, False)
            else:
                raise exc

    async def _search_iter_anext(self, search_iter):
        while True:
            try:
                return next(search_iter)
            except StopIteration:
                pass
            if not self.__auto_page_acquire:
                raise StopAsyncIteration from None
            msgid = search_iter.acquire_next_page()
            if msgid is None:
                raise StopAsyncIteration from None
            search_iter = await self._evaluate(msgid, search_iter.timeout)

    async def get_result(self, msg_id: int, timeout: float | None = None) -> Any:
        return await self._evaluate(msg_id, timeout)
