import math
import trio

from ..ldapconnection import BaseLDAPConnection, LDAPSearchScope
from ..errors import NotAllowedOnNonleaf, TimeoutError


class TrioLDAPConnection(BaseLDAPConnection):
    """
    Asynchronous LDAP connection object that works with trio.
    It has the same methods and properties as :class:`bonsai.LDAPConnection`, but
    with the exception of :meth:`bonsai.LDAPConnection.close` and
    :meth:`bonsai.LDAPConnection.fileno` all of them are awaitable.

    :param LDAPClient client: a client object.
    """

    def __init__(self, client):
        self.__open_coro = None
        super().__init__(client, is_async=True)

    async def __aenter__(self):
        """Async context manager entry point."""
        return await self.__open_coro

    async def __aexit__(self, type, value, traceback):
        """Async context manager exit point."""
        self.close()

    def __await__(self):
        return self.__open_coro.__await__()  # Hack to avoid returning a coroutine.

    def open(self, timeout=None):
        self.__open_coro = super().open(timeout)
        return self

    async def _poll(self, msg_id, timeout=None):
        tout_sec = timeout if timeout is not None else math.inf
        with trio.move_on_after(tout_sec):
            while True:
                await trio.lowlevel.wait_writable(self)
                await trio.lowlevel.wait_readable(self)
                res = super().get_result(msg_id)
                if res is not None:
                    return res
        raise TimeoutError("Timeout is exceeded")

    def _evaluate(self, msg_id, timeout=None):
        return self._poll(msg_id, timeout)

    async def delete(self, dname, timeout=None, recursive=False):
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
        try:
            return next(search_iter)
        except StopIteration:
            msgid = search_iter.acquire_next_page()
            if msgid is None:
                raise StopAsyncIteration from None
            search_iter = await self._evaluate(msgid)
            return next(search_iter)

    async def get_result(self, msg_id, timeout=None):
        return await self._evaluate(msg_id, timeout)
