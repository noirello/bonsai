from pyldap._cpyldap import _LDAPConnection

class LDAPConnection(_LDAPConnection):
    def __init__(self,  client, async=False):
        super().__init__(client)
        self.__client = client
        self.__async = async
        
    def __enter__(self):
        return self
    
    def __exit__(self, *exc):
        self.close()
        
    def _poll(self, msg_id):
        while True:
            result = self.get_result(msg_id)
            if result is not None:
                return result
            yield
            
    def add(self, entry):
        msg_id = super().add(entry)
        if self.__async:
            return self._poll(msg_id)
        else:
            return self.get_result(msg_id, True)
        
    def delete(self, dnstr):
        msg_id = super().delete(dnstr)
        if self.__async:
            return self._poll(msg_id)
        else:
            return self.get_result(msg_id, True)
    
    @property
    def async(self):
        return self.__async    
    
    def search(self,  base=None, scope=None, filter=None, attrlist=None,
               timeout=0, sizelimit=0, attrsonly=False):
        _base = str(base) if base is not None else str(self.__client.url.basedn)
        _scope = scope if scope is not None else self.__client.url.scope_num
        _filter = filter if filter is not None else self.__client.url.filter
        _attrlist = attrlist if attrlist is not None else self.__client.url.attributes
        msg_id = super().search(_base, _scope, _filter, _attrlist,
                                timeout, sizelimit, attrsonly)
        if self.__async:
            return self._poll(msg_id)
        else:
            if self.__client._LDAPClient__page_size > 1:
                return self.__paged_search(self.get_result(msg_id, True))
            return list(self.get_result(msg_id, True))
        
    def __paged_search(self, res):
        while True:
            yield from res
            msg_id = res.acquire_next_page()
            if msg_id is None:
                break
            res = self.get_result(msg_id, True)
        
    def whoami(self):
        msg_id = super().whoami()
        if self.__async:
            return self._poll(msg_id)
        else:
            return self.get_result(msg_id, True)
