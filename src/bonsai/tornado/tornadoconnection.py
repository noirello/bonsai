from functools import partial

from tornado import gen
from tornado.ioloop import IOLoop
from tornado.concurrent import Future

from ..ldapconnection import BaseLDAPConnection, LDAPSearchScope
from ..errors import LDAPError, NotAllowedOnNonleaf


class TornadoLDAPConnection(BaseLDAPConnection):
    """
    Asynchronous LDAP connection object that works with Torando.
    It has the same methods and properties as :class:`bonsai.LDAPConnection`.

    :param LDAPClient client: a client object.
    :param ioloop: a Tornado IO loop.
    """

    def __init__(self, client, ioloop=None):
        super().__init__(client, is_async=True)
        self._ioloop = ioloop or IOLoop.instance()
        self._fileno = None
        self._timeout = None

    def _io_callback(self, fut, msg_id, fd=None, events=None):
        try:
            self._ioloop.remove_handler(self._fileno)
            res = super().get_result(msg_id)
            if res is not None:
                fut.set_result(res)
                if self._timeout is not None:
                    self._ioloop.remove_timeout(self._timeout)
            else:
                self._fileno = self.fileno()
                callback = partial(self._io_callback, fut, msg_id)
                try:
                    self._ioloop.add_handler(
                        self._fileno, callback, IOLoop.WRITE | IOLoop.READ
                    )
                except FileExistsError as exc:
                    if exc.errno != 17:
                        raise exc
        except LDAPError as exc:
            fut.set_exception(exc)

    def _timeout_callback(self, fut):
        self._ioloop.remove_handler(self._fileno)
        fut.set_exception(gen.TimeoutError())

    def _evaluate(self, msg_id, timeout=None):
        fut = Future()
        callback = partial(self._io_callback, fut, msg_id)
        self._fileno = self.fileno()
        try:
            self._ioloop.add_handler(self._fileno, callback, IOLoop.WRITE | IOLoop.READ)
            if timeout is not None:
                self._timeout = self._ioloop.call_later(
                    timeout, self._timeout_callback, fut
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
        try:
            return next(search_iter)
        except StopIteration:
            msgid = search_iter.acquire_next_page()
            if msgid is None:
                raise StopAsyncIteration from None
            search_iter = yield self._evaluate(msgid)
            return next(search_iter)

    @gen.coroutine
    def get_result(self, msg_id, timeout=None):
        res = yield self._evaluate(msg_id, timeout)
        return res

