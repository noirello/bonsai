from ipaddress import IPv6Address
from typing import Any, List, Union, Tuple, Optional

import re
import urllib.parse
from .ldapdn import LDAPDN


class LDAPURL:
    """
    LDAP URL object for handling LDAP connection informations, such as
    hostname, port, LDAP bind DN, search attributes, scope (base,sub or
    one) filter, and extensions. If `strurl` is None, then the default
    url is `ldap://localhost:389`.

    :param str strurl: string representation of a valid LDAP URL. Must \
    be started with `ldap://`, `ldaps://` or `ldapi://`.

    :raises ValueError: if the string parameter is not a valid LDAP URL.
    """

    __slots__ = ("__hostinfo", "__searchinfo", "__extensions", "__ipv6")

    def __init__(self, strurl: Optional[str] = None) -> None:
        """Init method."""
        self.__hostinfo = ("ldap", "localhost", 389)  # type: Tuple[str, str, int]
        # Default values to the search parameters.
        self.__searchinfo = (
            LDAPDN(""),
            [],
            "",
            "",
        )  # type: Tuple[LDAPDN, List[str], str, str]
        self.__extensions = []  # type: List[str]
        self.__ipv6 = False
        if strurl:
            self.__str2url(strurl)

    def __delattr__(self, attr: str) -> None:
        """None of the attributes can be deleted."""
        raise AttributeError("%s cannot be deleted." % attr)

    def __str2url(self, strurl: str) -> None:
        """Parsing string url to LDAPURL."""
        # Form: [scheme]://[host]:[port]/[basedn]?[attrs]?[scope]?[filter]?[exts]
        scheme, host, port = self.__hostinfo
        binddn, attrlist, scope, filter_exp = self.__searchinfo
        parsed_url = urllib.parse.urlparse(strurl)
        scheme = parsed_url.scheme
        if scheme not in ("ldap", "ldaps", "ldapi"):
            raise ValueError(f"'{strurl}' is not a valid LDAP URL")
        if scheme == "ldaps":
            port = 636
        elif scheme == "ldapi":
            port = 0
        if parsed_url.hostname:
            host = parsed_url.hostname
        if parsed_url.scheme != "ldapi":
            valid, self.__ipv6 = self.is_valid_hostname(host)
            if not valid:
                raise ValueError(f"'{strurl}' has an invalid hostname")
        if parsed_url.port:
            port = parsed_url.port
        binddn = LDAPDN(urllib.parse.unquote(parsed_url.path[1:]))
        params = parsed_url.query.split("?")
        # Attribute
        if len(params) > 0 and len(params[0]) > 0:
            attrlist = params[0].split(",")
        # Scope (base/one/sub)
        if len(params) > 1:
            _scope = params[1].lower()
            if _scope not in ("base", "one", "sub"):
                raise ValueError("Invalid scope type.")
            scope = _scope
        # Filter
        if len(params) > 2:
            filter_exp = urllib.parse.unquote(params[2])
        # Extensions
        if len(params) > 3:
            self.__extensions = params[3].split(",")
        self.__hostinfo = (scheme, host, port)
        self.__searchinfo = (binddn, attrlist, scope, filter_exp)

    @staticmethod
    def is_valid_hostname(hostname: str) -> Tuple[bool, bool]:
        """Validate a hostname."""
        hostname_regex = re.compile(
            r"^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]"
            r"*[a-zA-Z0-9])\.)*([A-Za-z0-9]|"
            r"[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$"
        )
        try:
            # Try parsing IPv6 address.
            IPv6Address(hostname)
            return (True, True)
        except ValueError:
            # Try IPv4 and standard hostname.
            if hostname_regex.match(hostname):
                return (True, False)
            return (False, False)

    @property
    def host(self) -> str:
        """The hostname."""
        return self.__hostinfo[1]

    @host.setter
    def host(self, value: str) -> None:
        """Setter for hostname."""
        # RegExp for valid hostname.
        valid, ipv6 = self.is_valid_hostname(value)
        if not valid:
            raise ValueError("'%s' is not a valid host name." % value)
        else:
            self.__hostinfo = (self.__hostinfo[0], value, self.__hostinfo[2])
            self.__ipv6 = ipv6

    @property
    def port(self) -> int:
        """The portnumber."""
        return self.__hostinfo[2]

    @port.setter
    def port(self, value: int) -> None:
        """Setter for portnumber."""
        if isinstance(value, int) and (value > 0 and value < 65535):
            self.__hostinfo = (self.__hostinfo[0], self.__hostinfo[1], value)
        else:
            raise ValueError("Port must be an int between 1 and 65535.")

    @property
    def scheme(self) -> str:
        """The URL scheme."""
        return self.__hostinfo[0]

    @scheme.setter
    def scheme(self, value: str) -> None:
        """Setter for URL scheme."""
        # It must be ldap, ldaps or ldapi
        if isinstance(value, str) and value.lower() in ("ldap", "ldaps", "ldapi"):
            self.__hostinfo = (value.lower(), self.__hostinfo[1], self.__hostinfo[2])
        else:
            raise ValueError("Scheme only be 'ldap', 'ldaps' or 'ldapi'.")

    @property
    def basedn(self) -> LDAPDN:
        """The LDAP distinguished name for binding."""
        return self.__searchinfo[0]

    @basedn.setter
    def basedn(self, value: Union[LDAPDN, str]) -> None:
        """Setter for LDAP distinguished name for binding."""
        self.__searchinfo = (
            LDAPDN(str(value)),
            self.__searchinfo[1],
            self.__searchinfo[2],
            self.__searchinfo[3],
        )

    @property
    def attributes(self) -> List[str]:
        """The searching attributes."""
        return self.__searchinfo[1]

    @property
    def scope(self) -> str:
        """The searching scope."""
        return self.__searchinfo[2]

    @scope.setter
    def scope(self, value: str) -> None:
        """Setter for searching scope."""
        if isinstance(value, str):
            if value.lower() in ("base", "one", "sub"):
                self.__searchinfo = (
                    self.__searchinfo[0],
                    self.__searchinfo[1],
                    value,
                    self.__searchinfo[3],
                )
            else:
                raise ValueError(
                    """Scope must be one of these:
                            'base', 'one', 'sub'."""
                )
        else:
            raise TypeError("Scope must be a string.")

    @property
    def scope_num(self) -> int:
        """Return the searching scope number."""
        if self.scope == "base":
            return 0
        if self.scope == "one":
            return 1
        if self.scope == "sub":
            return 2
        else:
            return -1

    @property
    def filter_exp(self) -> str:
        """The searching filter expression."""
        return self.__searchinfo[3]

    def get_address(self) -> str:
        """
        Return the full address of the host.
        """
        if self.scheme == "ldapi":
            return f"{self.__hostinfo[0]}://{self.__hostinfo[1]}"
        if self.__ipv6:
            return (
                f"{self.__hostinfo[0]}://[{self.__hostinfo[1]}]:{self.__hostinfo[2]:d}"
            )
        else:
            return f"{self.__hostinfo[0]}://{self.__hostinfo[1]}:{self.__hostinfo[2]:d}"

    def __eq__(self, other: object) -> bool:
        """
        Check equality of two LDAPURL or an LDAPURL and a string.
        """
        if isinstance(other, LDAPURL):
            return (
                self.scheme == other.scheme
                and self.host == other.host
                and self.port == other.port
                and self.basedn == other.basedn
                and self.scope == other.scope
                and self.filter_exp == other.filter_exp
                and self.attributes == other.attributes
            )
        elif isinstance(other, str):
            try:
                other = LDAPURL(other)
            except ValueError:
                return False
            return self == other
        else:
            return NotImplemented

    def __str__(self) -> str:
        """Returns the full format of LDAP URL."""
        strurl = self.get_address()
        strattrs = ""
        strexts = ""
        if self.__searchinfo[1]:
            strattrs = ",".join(self.__searchinfo[1])
        if self.__extensions:
            strexts = ",".join(self.__extensions)
        strbind = "?".join(
            (
                urllib.parse.quote(str(self.__searchinfo[0]), safe="=,"),
                strattrs,
                self.__searchinfo[2],
                urllib.parse.quote(self.__searchinfo[3], safe="=,()*"),
                strexts,
            )
        )
        # Remove unnecessary question marks at the end of the string.
        while strbind[-1] == "?":
            strbind = strbind[:-1]
            if not strbind:
                break
        if strbind:
            strurl = "%s/%s" % (strurl, strbind)
        return strurl

    def __repr__(self) -> str:
        """The LDAPURL representation."""
        return "<LDAPURL %s>" % str(self)
