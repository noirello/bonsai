from pyldap._cpyldap import _LDAPConnection
from pyldap.ldapdn import LDAPDN

class LDAPConnection(_LDAPConnection):
    def __init__(self, client, async=False):
        self.__client = client
        self.__async = async
        self.__page_size = 0
        self.__sort_attrs = []
        super().__init__(client)

    def __enter__(self):
        """ Context manager entry point. """
        return self

    def __exit__(self, *exc):
        """ Context manager exit point. """
        self.close()

    def _poll(self, msg_id):
        """
        Generator function to poll the result of an LDAP operation.

        :param int msg_id: the ID of the LDAP operation.
        :return: the result of the operation.
        :rtype: list, bool or iterator, depending on the operation.
         """
        while True:
            result = self.get_result(msg_id)
            if result is not None:
                return result
            yield

    def _result(self, msg_id):
        """
        Depending on the connection's type (asynchronous or synchronous),
        it returns a generator object or the result of the LDAP operation.

        :param int msg_id: the ID of the LDAP operation.
        :return: generator if the connection async, otherwise the result of the operation.
        """
        if self.__async:
            return self._poll(msg_id)
        else:
            return self.get_result(msg_id, True)

    def add(self, entry):
        """
        Add new entry to the directory server.

        :param LDAPEntry entry: the new entry.
        :return: True, if the operation is finished.
        :rtype: bool
        """
        return self._result(super().add(entry))

    def delete(self, dnstr):
        """
        Remove entry from the directory server.

        :param str dnstr: the string format of the entry's DN.
        :return: True, if the operation is finished.
        :rtype: bool
        """
        if type(dnstr) == LDAPDN:
            dnstr = str(dnstr)
        return self._result(super().delete(dnstr))

    def search(self, base=None, scope=None, filter=None, attrlist=None,
               timeout=0, sizelimit=0, attrsonly=False):
        # Documentation in the docs/api.rst with detailed examples.
        # Load values from the LDAPURL, if it is not present on the
        # parameter list.
        _base = str(base) if base is not None else str(self.__client.url.basedn)
        _scope = scope if scope is not None else self.__client.url.scope_num
        _filter = filter if filter is not None else self.__client.url.filter
        _attrlist = attrlist if attrlist is not None else self.__client.url.attributes
        msg_id = super().search(_base, _scope, _filter, _attrlist,
                                timeout, sizelimit, attrsonly)
        if self.__async:
            return self._poll(msg_id)
        else:
            if self.__page_size > 1:
                return self.__paged_search(self.get_result(msg_id, True))
            return list(self.get_result(msg_id, True))

    def set_page_size(self, page_size):
        """
        Set how many entry will be on a page of a search result. Setting the
        page size will affect the search to use LDAP paged results.
        :meth:`LDAPConnection.search` will return an iterator instead of a
        list of entries.

        :param int page_size:
        :raises ValueError: if the parameter is not an integer, or lesser \
        than 2.
        """
        if type(page_size) != int or page_size < 2:
            raise ValueError("The page_size parameter must be an integer greater, than 1.")
        self.__page_size = page_size

    def __paged_search(self, res):
        while True:
            yield from res
            msg_id = res.acquire_next_page()
            if msg_id is None:
                break
            res = self.get_result(msg_id, True)

    def set_sort_order(self, sort_list):
        """
        Set a list of attribute names to sort entries in a search result. For
        reverse order set '-' before to the attribute name.

        :param list sort_list: List of attribute names.
        :raises ValueError: if any element of the list is not a string or an \
        empty string, and if any of the attributes is in the list more then \
        once.
        """
        sort_attrs = []
        for attr in sort_list:
            if type(attr) != str or len(attr) == 0:
                raise ValueError("All element of sort_list must be a non empty string.")
            if attr[0] == '-':
                sort_attrs.append((attr[1:], True))
            else:
                sort_attrs.append((attr, False))
        if len(sort_list) > len(set(map(lambda x: x[0].lower, sort_attrs))):
            raise ValueError("Attribute names must be different from each other.")
        self.__sort_attrs = sort_attrs

    def whoami(self):
        """
        This method can be used to obtain authorization identity.

        :return: the authorization ID.
        :rtype: str
         """
        return self._result(super().whoami())

