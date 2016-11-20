from gevent.socket import wait_readwrite

from ..ldapconnection import LDAPConnection, LDAPSearchScope
from ..errors import NotAllowedOnNonleaf

class GeventLDAPConnection(LDAPConnection):
    def __init__(self, client):
        super().__init__(client, is_async=True)

    def _poll(self, msg_id, timeout=None):
        while True:
            res = self.get_result(msg_id)
            if res is not None:
                return res
            wait_readwrite(self.fileno(), timeout=timeout)

    def _evaluate(self, msg_id, timeout=None):
        return self._poll(msg_id, timeout)

    def delete(self, dname, timeout=None, recursive=False):
        try:
            return super().delete(dname, timeout, recursive)
        except NotAllowedOnNonleaf as exc:
            if recursive:
                results = self.search(dname, LDAPSearchScope.ONELEVEL,
                                      attrlist=['1.1'], timeout=timeout)
                for res in results:
                    self.delete(res.dn, timeout, True)
                return self.delete(dname, timeout, False)
            else:
                raise exc
