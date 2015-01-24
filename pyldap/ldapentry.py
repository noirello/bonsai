from pyldap._cpyldap import _LDAPEntry

class LDAPEntry(_LDAPEntry):
    def __init__(self, dn, conn=None):
        super().__init__(str(dn), conn)

    def delete(self):
        """
        Remove LDAP entry from the dictionary server.

        :return: True, if the operation is finished.
        :rtype: bool
        """
        return self.connection._result(super().delete())

    def modify(self):
        """
        Send entry's modifications to the dictionary server.

        :return: True, if the operation is finished.
        :rtype: bool
        """
        return self.connection._result(super().modify())

    def rename(self, newdn):
        """
        Change the entry's distinguished name.

        :param str newdn: the new DN of the entry.
        :return: True, if the operation is finished.
        :rtype: bool
        """
        return self.connection._result(super().rename(newdn))

    def update(self, *args, **kwds):
        """
        Update the LDAPEntry with the key/value pairs from other, overwriting existing keys.
        (Same as dict's update method.)
        """
        if args:
            if hasattr(args[0], "keys"):
                # Working with a dict on the parameter list.
                for key, value in args[0].items():
                    self.__setitem__(key, value)
            else:
                # Working with a sequence.
                for tup in args[0]:
                    if len(tup) != 2:
                        raise ValueError("Sequence element has more then 2 element.")
                    self.__setitem__(tup[0], tup[1])
        if kwds:
            # Key/value pairs are listed on the parameter list.
            for key, value in kwds.items():
                self.__setitem__(key, value)