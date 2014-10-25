from pyldap._cpyldap import _LDAPEntry

class LDAPEntry(_LDAPEntry):
    def __init__(self, dn, conn=None):
        super().__init__(str(dn), conn)
        
    def modify(self):
        msg_id = super().modify()
        if self.connection.async:
            return self.connection._poll(msg_id)
        else:
            return self.connection.get_result(msg_id, True)
    
    def delete(self):
        msg_id = super().delete()
        if self.connection.async:
            return self.connection._poll(msg_id)
        else:
            return self.connection.get_result(msg_id, True)
        
    def rename(self, newdn):
        msg_id = super().rename(newdn)
        if self.connection.async:
            return self.connection._poll(msg_id)
        else:
            return self.connection.get_result(msg_id, True)
    