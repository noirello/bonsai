from pyldap._cpyldap import _LDAPEntry

class LDAPEntry(_LDAPEntry):
    def __init__(self, dn, conn=None):
        super().__init__(str(dn), conn)
        
    def modify(self):
        return self.connection._result(super().modify())
    
    def delete(self):
        return self.connection._result(super().delete())
        
    def rename(self, newdn):
        return self.connection._result(super().rename(newdn))
