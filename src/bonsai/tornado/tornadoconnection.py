from functools import partial

from tornado import gen
from tornado.ioloop import IOLoop
from tornado.concurrent import Future

from ..ldapconnection import BaseLDAPConnection, LDAPSearchScope
from ..errors import LDAPError, NotAllowedOnNonleaf


class TornadoLDAPConnection(BaseLDAPConnection):
    """
    Asynchronous LDAP connection object that works with Tornado.
    It has the same methods and properties as :class:`bonsai.LDAPConnection`.

    :param LDAPClient client: a client object.
    :param ioloop: a Tornado IO loop. By default (None) every operation runs on
        the loop it is awaited on, setting it ties the connection to that single
        loop for every operation.
    """

    def __init__(self, client, ioloop=None):
        super().__init__(client, is_async=True)
        self._ioloop = ioloop
        self._fileno = None
        self._timeout = None
        self.__auto_page_acquire = client.auto_page_acquire

    def _events(self, msg_id):
        if self._wants_write(msg_id):
            return IOLoop.WRITE | IOLoop.READ
        return IOLoop.READ

    def _clear_timeout(self, ioloop):
        if self._timeout is not None:
            ioloop.remove_timeout(self._timeout)
            self._timeout = None

    def _io_callback(self, msg_id, ioloop, fut, fd=None, events=None):
        try:
            ioloop.remove_handler(self._fileno)
            if fut.done():
                # Timed out already, nothing to deliver.
                return
            res = super().get_result(msg_id)
            if res is not None:
                self._clear_timeout(ioloop)
                fut.set_result(res)
            else:
                self._fileno = self.fileno()
                callback = partial(self._io_callback, msg_id, ioloop, fut)
                try:
                    ioloop.add_handler(self._fileno, callback, self._events(msg_id))
                except FileExistsError as exc:
                    if exc.errno != 17:
                        raise exc
        except LDAPError as exc:
            self._clear_timeout(ioloop)
            fut.set_exception(exc)

    def _timeout_callback(self, msg_id, ioloop, fut):
        if fut.done():
            return
        self._timeout = None
        ioloop.remove_handler(self._fileno)
        fut.set_exception(gen.TimeoutError())

    def _evaluate(self, msg_id, timeout=None):
        ioloop = self._ioloop or IOLoop.current()
        fut = Future()
        callback = partial(self._io_callback, msg_id, ioloop, fut)
        self._fileno = self.fileno()
        try:
            ioloop.add_handler(self._fileno, callback, self._events(msg_id))
            if timeout is not None:
                self._timeout = ioloop.call_later(
                    timeout, self._timeout_callback, msg_id, ioloop, fut
                )
        except FileExistsError as exc:
            # Avoid concurrency problems by registering with
            # the same fileno more than once.
            if exc.errno != 17:
                raise exc
        return fut

    @gen.coroutine
    def delete(self, dname, timeout=None, recursive=False):
        try:
            res = yield super().delete(dname, timeout, recursive)
            return res
        except NotAllowedOnNonleaf as exc:
            if recursive:
                results = yield self.search(
                    dname, LDAPSearchScope.ONELEVEL, attrlist=["1.1"], timeout=timeout
                )
                for res in results:
                    yield self.delete(res.dn, timeout, True)
                res = yield self.delete(dname, timeout, False)
                return res
            else:
                raise exc

    @gen.coroutine
    def _search_iter_anext(self, search_iter):
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
            search_iter = yield self._evaluate(msgid, search_iter.timeout)

    @gen.coroutine
    def get_result(self, msg_id, timeout=None):
        res = yield self._evaluate(msg_id, timeout)
        return res
