import asyncio

from ..ldapconnection import BaseLDAPConnection, LDAPSearchScope
from ..errors import LDAPError, NotAllowedOnNonleaf


class AIOLDAPConnection(BaseLDAPConnection):
    """
    Asynchronous LDAP connection object that works with asyncio.
    It has the same methods and properties as :class:`bonsai.LDAPConnection`, but
    with the exception of :meth:`bonsai.LDAPConnection.close` and
    :meth:`bonsai.LDAPConnection.fileno` all of them are awaitable.

    :param LDAPClient client: a client object.
    :param loop: an asyncio IO loop.
    """

    def __init__(self, client, loop=None):
        self._loop = loop or asyncio.get_running_loop()
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

    __iter__ = __await__

    def _ready(self, msg_id, fut):
        self._loop.remove_reader(self.fileno())
        self._loop.remove_writer(self.fileno())
        try:
            res = super().get_result(msg_id)
            if res is not None:
                fut.set_result(res)
            else:
                self._loop.add_reader(self.fileno(), self._ready, msg_id, fut)
                self._loop.add_writer(self.fileno(), self._ready, msg_id, fut)
        except LDAPError as exc:
            fut.set_exception(exc)

    async def _poll(self, msg_id, timeout=None):
        fut = asyncio.Future()
        self._loop.add_reader(self.fileno(), self._ready, msg_id, fut)
        self._loop.add_writer(self.fileno(), self._ready, msg_id, fut)
        try:
            return await asyncio.wait_for(fut, timeout)
        except Exception as exc:
            if self.fileno() > -1:
                self._loop.remove_reader(self.fileno())
                self._loop.remove_writer(self.fileno())
            raise exc

    def _evaluate(self, msg_id, timeout=None):
        return self._poll(msg_id, timeout)

    def open(self, timeout=None):
        self.__open_coro = super().open(timeout)
        return self

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
