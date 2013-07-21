class LDAPError(Exception):
    """General LDAP error."""

class NotConnected(LDAPError):
    """Raised, when an operation needs an open LDAP connection."""
    
class InvalidDN(LDAPError):
    """Raisef, when dn string is not a valid distinguished name."""