class LDAPError(Exception):
    """General LDAP error."""

class NotConnected(LDAPError):
    """Raised, when an operation needs an open LDAP connection."""