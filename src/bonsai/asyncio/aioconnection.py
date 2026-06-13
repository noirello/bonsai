import asyncio

from .._bonsai import ldapconnection
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
        self.__connect_future = None
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
        # Start the init thread (no network I/O) and get the message id, then
        # drive the connect in a coroutine that keeps the event loop responsive.
        if timeout is None:
            msg_id = ldapconnection.open(self)
        else:
            # Bound the connect worker thread with LDAP_OPT_NETWORK_TIMEOUT. The
            # 1s margin keeps it above the asyncio wait_for deadline so the
            # caller reliably sees asyncio.TimeoutError, not a connection error.
            msg_id = ldapconnection.open(self, int(timeout * 1000) + 1000)
        self.__open_coro = self._open(msg_id, timeout)
        return self

    @staticmethod
    def _set_future_result(fut):
        if not fut.done():
            fut.set_result(None)

    @staticmethod
    def _retrieve_connect_result(fut):
        # Retrieve the (possibly discarded) result/exception of the connect
        # worker so asyncio does not log it as never-retrieved.
        if not fut.cancelled():
            fut.exception()

    def _connect_step(self, msg_id):
        # Runs in a worker thread. The C extension releases the GIL during the
        # blocking DNS resolution and TCP connect, so the event loop stays free.
        # Do NOT pass a timeout to get_result: it sets self->timeout on the C
        # LDAPConnectIter, which would make the Phase 2 _ready callbacks block
        # the event loop waiting for the bind response. The timeout is enforced
        # by the asyncio wait_for wrapping this call.
        return super().get_result(msg_id)

    async def _open(self, msg_id, timeout=None):
        loop = self._loop
        deadline = None if timeout is None else loop.time() + timeout
        # Phase 1a: wait for the init thread to finish initialising the LDAP
        # struct. It pings the dummy socketpair when done; this does no network.
        init_done = loop.create_future()
        init_fd = self.fileno()
        loop.add_reader(init_fd, self._set_future_result, init_done)
        try:
            await asyncio.wait_for(init_done, timeout)
        finally:
            loop.remove_reader(init_fd)
        # Phase 1b: run the blocking connect (DNS + TCP connect + bind start) in
        # a worker thread, bounded by the remaining timeout. On timeout the
        # worker cannot be cancelled; it keeps running (until its own network
        # timeout). Shield it so wait_for's timeout does not mark the future
        # done while the worker is still using the LDAP handle -- close() relies
        # on this future to know when the handle is safe to unbind.
        remaining = None if deadline is None else max(0.0, deadline - loop.time())
        connect_future = loop.run_in_executor(None, self._connect_step, msg_id)
        self.__connect_future = connect_future
        connect_future.add_done_callback(self._retrieve_connect_result)
        res = await asyncio.wait_for(asyncio.shield(connect_future), remaining)
        if res is not None:
            return res
        # Phase 2: the socket is connected and the bind request is sent; drive
        # the rest of the bind exchange with the existing non-blocking polling.
        remaining = None if deadline is None else max(0.0, deadline - loop.time())
        return await self._poll(msg_id, remaining)

    def close(self, *args, **kwargs):
        connect_future = self.__connect_future
        if connect_future is not None and not connect_future.done():
            # A connect worker thread may still be using the LDAP handle; defer
            # the unbind until it finishes to avoid a use-after-free.
            self.__connect_future = None
            connect_future.add_done_callback(
                lambda _: ldapconnection.close(self, *args, **kwargs)
            )
            return
        super().close(*args, **kwargs)

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
