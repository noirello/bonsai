import asyncio
import sys

from ..ldapconnection import LDAPConnection, LDAPSearchScope
from ..errors import LDAPError, NotAllowedOnNonleaf

# Backwards compatibility from 3.5.
if sys.version_info.minor < 5:
    StopAsyncIteration = StopIteration

class AIOLDAPConnection(LDAPConnection):
    def __init__(self, client, loop=None):
        self._loop = loop or asyncio.get_event_loop()
        super().__init__(client, is_async=True)

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

    @asyncio.coroutine
    def _poll(self, msg_id, timeout=None):
        fut = asyncio.Future()
        self._loop.add_reader(self.fileno(), self._ready, msg_id, fut)
        self._loop.add_writer(self.fileno(), self._ready, msg_id, fut)
        try:
            res = yield from asyncio.wait_for(fut, timeout, loop=self._loop)
            return res
        except Exception as exc:
            self._loop.remove_reader(self.fileno())
            self._loop.remove_writer(self.fileno())
            raise exc

    def _evaluate(self, msg_id, timeout=None):
        return self._poll(msg_id, timeout)

    @asyncio.coroutine
    def delete(self, dname, timeout=None, recursive=False):
        try:
            res = yield from super().delete(dname, timeout, recursive)
            return res
        except NotAllowedOnNonleaf as exc:
            if recursive:
                results = yield from self.search(dname,
                                                 LDAPSearchScope.ONELEVEL,
                                                 attrlist=['1.1'],
                                                 timeout=timeout)
                for res in results:
                    yield from self.delete(res.dn, timeout, True)
                res = yield from self.delete(dname, timeout, False)
                return res
            else:
                raise exc

    @asyncio.coroutine
    def _search_iter_anext(self, search_iter):
        try:
            return next(search_iter)
        except StopIteration:
            msgid = search_iter.acquire_next_page()
            if msgid is None:
                raise StopAsyncIteration
            search_iter = yield from self._evaluate(msgid)
            return next(search_iter)
