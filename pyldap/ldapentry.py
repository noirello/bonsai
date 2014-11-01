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
