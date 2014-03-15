class LDAPError(Exception):
    """General LDAP error."""

class InvalidDN(LDAPError):
    """Raised, when dn string is not a valid distinguished name."""

class ConnectionError(LDAPError):
    """Raised, when client is not able to connect to the server."""

class AuthenticationError(LDAPError):
    """Raised, when authentication is failed with the server."""
    
class ObjectClassViolation(LDAPError):
    """Raised, when try to add or modify an LDAP entry and it violates the 
    object class rules.""" 
    
class AlreadyExists(LDAPError):
    """Raised, when try to add an entry and it already exists in the 
    dictionary"""            

def __get_error(code):
    """ Return an error by code number. """
    if code == -1:
        return ConnectionError
    elif code == 0x22:
        return InvalidDN
    elif code == 0x31:
        return AuthenticationError
    elif code == 0x41:
        return ObjectClassViolation
    elif code == 0x44:
        return AlreadyExists
    else:
        return LDAPError
