import math
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any, cast

import trio

from ..ldapconnection import BaseLDAPConnection, LDAPSearchScope
from ..errors import NotAllowedOnNonleaf, TimeoutError
from ..ldapclient import LDAPClient
from ..ldapdn import LDAPDN

if TYPE_CHECKING:
    from types import TracebackType
    from bonsai._bonsai import ldapsearchiter


class TrioLDAPConnection(BaseLDAPConnection):
    """
    Asynchronous LDAP connection object that works with trio.
    It has the same methods and properties as :class:`bonsai.LDAPConnection`, but
    with the exception of :meth:`bonsai.LDAPConnection.close` and
    :meth:`bonsai.LDAPConnection.fileno` all of them are awaitable.

    :param LDAPClient client: a client object.
    """

    def __init__(self, client: LDAPClient) -> None:
        self.__open_coro: Any = None
        self.__auto_page_acquire = client.auto_page_acquire
        super().__init__(client, is_async=True)

    async def __aenter__(self) -> Any:
        """Async context manager entry point."""
        return await self.__open_coro

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        tb:"TracebackType | None",
    ) -> None:
        """Async context manager exit point."""
        self.close()

    def __await__(self) -> Any:
        return self.__open_coro.__await__()  # Hack to avoid returning a coroutine.

    def open(  # type: ignore[override]
        self, timeout: float | None = None
    ) -> "TrioLDAPConnection":
        self.__open_coro = super().open(timeout)
        return self

    async def _wait_io(self, msg_id: int) -> None:
        if not self._wants_write(msg_id):
            await trio.lowlevel.wait_readable(self)
            return

        async with trio.open_nursery() as nursery:

            async def wait_one(wait_fn: Callable[[Any], Awaitable[Any]]) -> None:
                await wait_fn(self)
                nursery.cancel_scope.cancel()

            nursery.start_soon(wait_one, trio.lowlevel.wait_readable)
            nursery.start_soon(wait_one, trio.lowlevel.wait_writable)

    async def _poll(self, msg_id: int, timeout: float | None = None) -> Any:
        tout_sec = timeout if timeout is not None else math.inf
        with trio.move_on_after(tout_sec):
            while True:
                await self._wait_io(msg_id)
                res = super().get_result(msg_id)
                if res is not None:
                    return res
        raise TimeoutError("Timeout is exceeded")

    def _evaluate(self, msg_id: int, timeout: float | None = None) -> Any:
        return self._poll(msg_id, timeout)

    async def delete(  # type: ignore[override]
        self, dname: str | LDAPDN, timeout: float | None = None, recursive: bool = False
    ) -> bool:
        try:
            return cast(bool, await super().delete(dname, timeout, recursive))
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

    async def _search_iter_anext(self, search_iter: "ldapsearchiter") -> Any:
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
