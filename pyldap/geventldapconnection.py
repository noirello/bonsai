from gevent.socket import wait_readwrite

from pyldap import LDAPConnection

class GeventLDAPConnection(LDAPConnection):
    def __init__(self, client):
        super().__init__(client, is_async=True)
    
    def _poll(self, msg_id, timeout=None):
        while True:
            res = self.get_result(msg_id, False)
            if res is not None:
                return res
            wait_readwrite(self.fileno(), timeout=timeout)

    def _evaluate(self, msg_id, timeout=None):
        return self._poll(msg_id, timeout)
    
    def search(self, base=None, scope=None, filter=None, attrlist=None,
               timeout=0, sizelimit=0, attrsonly=False):
        msg_id = super().search(base, scope, filter, attrlist, timeout,
                                sizelimit, attrsonly)
        return list(self._poll(msg_id))