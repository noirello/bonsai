import re
import urllib.parse
from pyldap.ldapdn import LDAPDN

class LDAPURL(object):
    """
    LDAP URL object for handling LDAP connection informations, such as
    hostname, port, LDAP bind DN, search attributes, scope (base,sub or
    one) filter, and extensions. If `strurl` is None, then the default
    url is `ldap://localhost:389`.

    :param str strurl: string representation of a valid LDAP URL. Must \
    be started with `ldap://` or `ldaps://`.

    :raises ValueError: if the string parameter is not a valid LDAP URL.
    """
    __slots__ = ("__hostinfo", "__searchinfo", "__extensions")

    def __init__(self, strurl=None):
        """ init method. """
        self.__hostinfo = ['ldap', 'localhost', 389]
        # Default values to the search parameters.
        self.__searchinfo = ["", [], "", ""]
        self.__extensions = None
        if strurl:
            self.__str2url(strurl)

    def __delattr__(self, attr):
        """ None of the attributions can be deleted. """
        raise AttributeError("%s cannot be deleted." % attr)

    def __str2url(self, strurl):
        """ Parsing string url to LDAPURL."""
        # RegExp for [ldap|ldaps]://[host]:[port]/[basedn]?[attrs]?[scope]
        # ?[filter]?[exts]
        valid = re.compile(r"^(ldap|ldaps)://((([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9]))?([:][1-9][0-9]{0,4})?(/.*)?$", re.IGNORECASE)
        match = valid.match(strurl)
        if match:
            self.__hostinfo[0] = match.group(1).lower()
            if self.__hostinfo[0] == "ldaps":
                self.__hostinfo[2] = 636
            # The full hostname
            if match.group(2):
                self.__hostinfo[1] = match.group(2)
            # The portnumber
            if match.group(6):
                self.__hostinfo[2] = int(match.group(6)[1:])
            # The rest of the LDAP URL.
            if match.group(7):
                rest = match.group(7)[1:].split("?")
                # Bind DN
                self.__searchinfo[0] = LDAPDN(urllib.parse.unquote(rest[0]))
                if len(rest) > 1:
                    # Attributes
                    if len(rest[1]) != 0:
                        self.__searchinfo[1] = rest[1].split(',')
                if len(rest) > 2:
                    # Scope (base/one/sub)
                    scope = rest[2].lower()
                    if scope != "base" and scope != "one" and scope != "sub":
                        raise ValueError("Invalid scope type.")
                    self.__searchinfo[2] = scope
                if len(rest) > 3:
                    # Filter
                    self.__searchinfo[3] = urllib.parse.unquote(rest[3])
                if len(rest) > 4:
                    # Extensions
                    self.__extensions = rest[4].split(',')
        else:
            raise ValueError("'%s' is not a valid LDAP URL." % strurl)

    @property
    def host(self):
        """ The hostname. """
        return self.__hostinfo[1]

    @staticmethod
    def is_valid_hostname(hostname):
        """"
        Validate a hostname.
        Source:
        http://stackoverflow.com/questions/2532053/validate-a-hostname-string
        """
        if len(hostname) > 255:
            return False
        if hostname[-1] == ".":
            # Strip exactly one dot from the right, if present
            hostname = hostname[:-1]
        allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$",
            re.IGNORECASE)
        return all(allowed.match(x) for x in hostname.split("."))

    @host.setter
    def host(self, value):
        """ Setter for hostname. """
        # RegExp for valid hostname.
        if not self.is_valid_hostname(value):
            raise ValueError("'%s' is not a valid host name." % value)
        else:
            self.__hostinfo[1] = value

    @property
    def port(self):
        """ The portnumber. """
        return self.__hostinfo[2]

    @port.setter
    def port(self, value):
        """ Setter for portnumber. """
        if type(value) == int and (value > 0 and value < 65535):
            self.__hostinfo[2] = value
        else:
            raise ValueError("Port must be an int between 1 and 65535.")

    @property
    def scheme(self):
        """ The URL scheme."""
        return self.__hostinfo[0]

    @scheme.setter
    def scheme(self, value):
        """ Setter for URL scheme."""
        # It must be ldap or ldaps
        if type(value) == str and value.lower() == 'ldap' \
            or value.lower() == 'ldaps':
            self.__hostinfo[0] = value.lower()
        else:
            raise ValueError("Scheme only be 'ldap' or 'ldaps'.")

    @property
    def basedn(self):
        """ The LDAP distinguished name for binding. """
        return self.__searchinfo[0]

    @basedn.setter
    def basedn(self, value):
        """ Setter for LDAP distinguished name for binding. """
        if type(value) == LDAPDN:
            self.__searchinfo[0] = value
        else:
            raise ValueError("Bind DN must be a type of LDAPDN.")

    @property
    def attributes(self):
        """ The searching attributes. """
        return self.__searchinfo[1]

    @property
    def scope(self):
        """ The searching scope. """
        return self.__searchinfo[2]

    @scope.setter
    def scope(self, value):
        """ Setter for searching scope. """
        if type(value) == str:
            if value.lower() == "base" or value.lower() == "one" \
                or value.lower() == "sub":
                self.__searchinfo[2] = value
            else:
                raise ValueError("""Scope must be one of these:
                            'base', 'one', 'sub'.""")
        else:
            raise ValueError("Scope must be a string.")

    @property
    def scope_num(self):
        """ Return the searching scope number. """
        if self.scope == "base":
            return 0
        if self.scope == "one":
            return 1
        if self.scope == "sub":
            return 2
        else:
            return -1

    @property
    def filter(self):
        """ The searching filter. """
        return self.__searchinfo[3]

    def get_address(self):
        """
        Return the full address of the host.
        """
        return "%s://%s:%d" % tuple(self.__hostinfo)

    def __str__(self):
        """ Returns the full format of LDAP URL. """
        strurl = self.get_address()
        strattrs = ""
        strexts = ""
        if self.__searchinfo[1]:
            strattrs = ",".join(self.__searchinfo[1])
        if self.__extensions:
            strexts = ",".join(self.__extensions)
        strbind = "?".join((str(self.__searchinfo[0]), strattrs,
                            self.__searchinfo[2], self.__searchinfo[3],
                            strexts))
        # Remove unneccesary question marks at the end of the string.
        while strbind[-1] == '?':
            strbind = strbind[:-1]
            if len(strbind) == 0:
                break
        if len(strbind) != 0:
            strurl = "%s/%s" % (strurl, strbind)
        return strurl

    def __repr__(self):
        """ The LDAPURL representation. """
        return "<LDAPURL %s>" % str(self)
