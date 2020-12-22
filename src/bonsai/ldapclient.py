"""
.. module:: LDAPClient
   :platform: Unix, Windows
   :synopsis: For managing LDAP connections.

"""
import socket
import sys
from typing import Any, Union, List, Tuple, Optional, Dict, TypeVar

from .ldapurl import LDAPURL
from .ldapconnection import BaseLDAPConnection, LDAPConnection
from .ldapconnection import LDAPSearchScope
from .ldapentry import LDAPEntry

# XXX: The following Python 3.4 guard should be removed in next release.
if sys.version_info >= (3, 5):
    from .asyncio import AIOLDAPConnection
else:
    import warnings
    warnings.warn(
        "Python 3.4 (and earlier) is unsupported, asyncio based AIOLDAPConnection cannot be used.",
        DeprecationWarning
    )
    AIOLDAPConnection = None

CT = TypeVar("CT", bound=BaseLDAPConnection)


class LDAPClient:
    """
    A class for configuring the connection to the directory server.

    :param str|LDAPURL url: an LDAP URL.
    :param bool tls: Set `True` to use TLS connection.
    :raises TypeError: if the `url` parameter is not string \
    or not a valid LDAP URL.
    """

    def __init__(self, url: Union[LDAPURL, str] = "ldap://", tls: bool = False) -> None:
        """ init method. """
        self.__tls = tls
        self.set_url(url)
        self.__credentials = None  # type: Optional[Dict[str, Optional[str]]]
        self.__raw_list = []  # type: List[str]
        self.__mechanism = "SIMPLE"
        self.__cert_policy = -1
        self.__ca_cert = ""  # type: Optional[str]
        self.__ca_cert_dir = ""  # type: Optional[str]
        self.__client_cert = ""  # type: Optional[str]
        self.__client_key = ""  # type: Optional[str]
        self.__async_conn = AIOLDAPConnection
        self.__ppolicy_ctrl = False
        self.__ext_dn = None  # type: Optional[int]
        self.__auto_acquire = True
        self.__chase_referrals = True
        self.__managedsait_ctrl = False

    @staticmethod
    def _create_socketpair() -> Tuple[socket.socket, socket.socket]:
        """
        Create a socketpair that will be used for signaling to select() during
        the initialisation procedure (and binding on MS Windows).
        """
        if hasattr(socket, "socketpair"):
            return socket.socketpair()
        # Backward compatibility on Windows from Python 3.5.
        # Origin: https://gist.github.com/4325783, by Geert Jansen. Public domain.
        def socketpair(
            family: Any = socket.AF_INET, type: Any = socket.SOCK_STREAM, proto: int = 0
        ) -> Tuple[socket.socket, socket.socket]:
            import errno

            # We create a connected TCP socket. Note the trick with setblocking(0)
            # that prevents us from having to create a thread.
            lsock = socket.socket(family, type, proto)
            lsock.bind(("localhost", 0))
            lsock.listen(1)
            addr, port = lsock.getsockname()
            csock = socket.socket(family, type, proto)
            csock.setblocking(0)
            try:
                csock.connect((addr, port))
            except socket.error as serr:
                if serr.errno != errno.WSAEWOULDBLOCK:
                    raise
            ssock, addr = lsock.accept()
            csock.setblocking(1)
            lsock.close()
            return (ssock, csock)

        return socketpair()

    def set_raw_attributes(self, raw_list: List[str]) -> None:
        """
        By default the values of the LDAPEntry are in string format. The
        values of the listed LDAP attribute's names in `raw_list` will be
        kept in bytearray format.

        :param list raw_list: a list of LDAP attribute's names. \
        The elements must be string and unique.

        :raises TypeError: if any of the list's element is not a \
        string.
        :raises ValueError: if the item in the lit is not a unique \
        element.
        """
        for elem in raw_list:
            if not isinstance(elem, str):
                raise TypeError("All element of raw_list must be string.")
        if len(raw_list) > len(set(map(str.lower, raw_list))):
            raise ValueError("Attribute names must be different from each other.")
        self.__raw_list = raw_list

    def set_credentials(
        self,
        mechanism: str,
        user: Optional[str] = None,
        password: Optional[str] = None,
        realm: Optional[str] = None,
        authz_id: Optional[str] = None,
        keytab: Optional[str] = None,
    ) -> None:
        """
        Set binding mechanism and credential information. All parameters \
        are optional except the `mechanism`. Different mechanism applies \
        different credential information and ignores the rest. For example:

            * *SIMPLE* uses the `user` (as bind DN) and `password`.
            * *EXTERNAL* only uses the `authz_id` as authorization ID.

        For other use-cases see this section about \
        :ref:`authentication mechanisms <auth-mechs>`.

        :param str mechanism: the name of the binding mechanism.
        :param str user: the identification of the binding user.
        :param str password: the password of the user.
        :param str realm: the (Kerberos) realm of the user.
        :param str authz_id: the authorization ID for the user.
        :param str keytab: path to a Kerberos keytab for authentication.
        :raises TypeError: if mechanism is not string, or any of the other \
        parameters are not string or None.
        """
        if not isinstance(mechanism, str):
            raise TypeError("The mechanism must be a string.")
        mechanism = mechanism.upper()
        creds = {
            "user": user,
            "password": password,
            "realm": realm,
            "authz_id": authz_id,
            "keytab": keytab,
        }
        if (
            list(filter(lambda x: not isinstance(x, (str, type(None))), creds.values()))
            != []
        ):
            raise TypeError("Every parameter must be a string or None.")
        self.__mechanism = mechanism.upper()
        self.__credentials = creds

    def set_cert_policy(self, policy: str) -> None:
        """
        Set policy about server certification.

        :param str policy: the cert policy could be one of the following \
        strings:

            - `try` or `demand`: the server cert will be verified, and if it \
            fail, then the :meth:`LDAPClient.connect` will raise an error.
            - `never` or `allow`: the server cert will be used without any \
            verification.

        :raises TypeError: if the `policy` parameter is not a string.
        :raises ValueError: if the `policy` not one of the four above.

        .. warning::
           Set off the cert verification is dangerous. Without verification \
           there is a chance of man-in-the-middle attack.
        """
        tls_options = {"never": 0, "demand": 2, "allow": 3, "try": 4}
        if not isinstance(policy, str):
            raise TypeError("Policy parameter must be string.")
        policy = policy.lower()
        if policy not in tls_options.keys():
            raise ValueError("'%s' is an invalid policy.", policy)
        self.__cert_policy = tls_options[policy]

    def set_ca_cert(self, name: Optional[str]) -> None:
        """
        Set the name of CA certificate. If the underlying libldap library \
        uses the Mozilla NSS as TLS library the `name` should be the same \
        one in the cert/key database (that specified with \
        :meth:`LDAPClient.set_ca_cert_dir`), otherwise it can be the name \
        of the CA cert file.

        .. note::
           This method has no effect on MS Windows, because WinLDAP \
           searches for the corresponding CA certificate in the cert \
           store. This means that the necessary certificates have to be \
           installed manually in to the cert store.

        :param str name: the name of the CA cert.
        :raises TypeError: if `name` parameter is not a string or not None.
        """
        if name is not None and not isinstance(name, str):
            raise TypeError("Name parameter must be string or None.")
        self.__ca_cert = name

    def set_ca_cert_dir(self, path: Optional[str]) -> None:
        """
        Set the directory of the CA cert. If the underlying libldap library \
        uses the Mozilla NSS as TLS library the `path` should be the path to \
        the existing cert/key database, otherwise it can be the path of the \
        CA cert file.

        .. note::
           This method has no effect on MS Windows, because WinLDAP \
           searches for the corresponding CA certificate in the cert \
           store. This means that the necessary certifications have to be \
           installed manually in to the cert store.

        :param str path: the path to the CA directory.
        :raises TypeError: if `path` parameter is not a string or not None.
        """
        if path is not None and not isinstance(path, str):
            raise TypeError("Path parameter must be string or None.")
        self.__ca_cert_dir = path

    def set_client_cert(self, name: Optional[str]) -> None:
        """
        Set the name of client certificate. If the underlying libldap library \
        uses the Mozilla NSS as TLS library the `name` should be the same one \
        in the cert/key database (that specified with \
        :meth:`LDAPClient.set_ca_cert_dir`), otherwise it can be the name \
        of the client certificate file.

        .. note::
           This method has no effect on MS Windows, because WinLDAP \
           searches for the corresponding client certificate based on \
           the servert's CA cert in the cert store. This means that the \
           necessary certificates have to be installed manually in to \
           the cert store.

        :param str name: the name of the client cert.
        :raises TypeError: if `name` parameter is not a string or not None.
        """
        if name is not None and not isinstance(name, str):
            raise TypeError("Name parameter must be string or None.")
        self.__client_cert = name

    def set_client_key(self, name: Optional[str]) -> None:
        """
        Set the file that contains the private key that matches the \
        certificate of the client that specified with \
        :meth:`LDAPClient.set_client_cert`).

        .. note::
           This method has no effect on MS Windows, because WinLDAP \
           searches for the corresponding client certificate based on \
           the servert's CA cert in the cert store. This means that the \
           necessary certificates have to be installed manually in to \
           the cert store.

        :param str name: the name of the CA cert.
        :raises TypeError: if `name` parameter is not a string or not None.
        """
        if name is not None and not isinstance(name, str):
            raise TypeError("Name parameter must be string or None.")
        self.__client_key = name

    def set_async_connection_class(self, conn: BaseLDAPConnection) -> None:
        """
        Set the LDAP connection class for asynchronous connection. The \
        default connection class is :class:`bonsai.asyncio.AIOLDAPConnection`
        that uses the asyncio event loop.

        :param BaseLDAPConnection conn: the new asynchronous connection class \
        that is a subclass of LDAPConnection.
        :raises TypeError: if `conn` parameter is not a subclass \
        of :class:`BaseLDAPConnection`.
        """
        if not issubclass(conn, BaseLDAPConnection):
            raise TypeError("Class must be a subclass of BaseLDAPConnection. ")
        self.__async_conn = conn

    def set_password_policy(self, ppolicy: bool) -> None:
        """
        Enable password policy control, if it is provided by the directory \
        server. Setting it `True` will change the return value of \
        :meth:`LDAPClient.connect` and :meth:`LDAPConnection.open` to a \
        tuple of `(conn, ctrl)` where the `conn` is an \
        :class:`LDAPConnection`, the `ctrl` is a dict of returned password \
        policy control response that contains the oid, the remaining seconds \
        of password expiration, and the number of remaining grace logins. \
        If the password policy control is not available on the server or not \
        supported by the platform the second item in the returned tuple is \
        `None`, instead of a dictionary.

        By enabling the password policy control the server can send \
        additional error messages related to the user's account and \
        password during conneting to the server and changing entries.

        :param bool ppolicy: enabling/disabling password policy control.
        :raises TypeError: If the parameter is not a bool type.
        """
        if not isinstance(ppolicy, bool):
            raise TypeError("Parameter must be bool.")
        self.__ppolicy_ctrl = ppolicy

    def set_extended_dn(self, extdn_format: Optional[int]) -> None:
        """
        Set the format of extended distinguished name for \
        LDAP_SERVER_EXTENDED_DN_OID control which extends the entries'
        distingushed name with GUID and SID attributes. If the server
        supports the control, the LDAPEntry objects' `extended_dn` attribute
        will be set (as a string) and the `dn` attribute will be kept in
        the simple format.

        Setting 0 specifies that the GUID and SID values be returned in \
        hexadecimal string format, while setting 1 will return the GUID and \
        SID values in standard string format. Passing `None` will remove the \
        control in a format of `<GUID=xxxx>;<SID=yyyy>;distinguishedName`.

        :param int extdn_format: the format of the extended dn. It can be 0, \
        1 or `None`.
        :raises TypeError: if the parameter is not int or None.
        :raises ValueError: if the parameter is not 0, 1 or None.
        """
        if extdn_format is not None and not isinstance(extdn_format, int):
            raise TypeError("Parameter's type must be int or None.")
        if extdn_format not in (0, 1, None):
            raise ValueError("Parameter must be 0, 1 or None.")
        self.__ext_dn = extdn_format

    def set_auto_page_acquire(self, val: bool) -> None:
        """
        Turn on or off the automatic page acquiring during a paged
        LDAP search. By turning automatic page acquiring on, it is
        unnecessary to call :meth:`ldapsearchiter.acquire_next_page`.
        It will be implicitly called during iteration.

        :param bool val: enabling/disabling auto page acquiring.
        :raises TypeError: If the parameter is not a bool type.
        """
        if not isinstance(val, bool):
            raise TypeError("Parameter's type must be bool.")
        self.__auto_acquire = val

    def set_server_chase_referrals(self, val: bool) -> None:
        """
        Turn on or off chasing LDAP referrals by the server. By turning
        off server-side referral chasing search result can contain
        :class:`LDAPReference` objects along with :class:`LDAPEntry`
        objects.

        :param bool val: enabling/disabling LDAP referrals chasing.
        :raises TypeError: If the parameter is not a bool type.
        """
        if not isinstance(val, bool):
            raise TypeError("Parameter's type must be bool.")
        self.__chase_referrals = val

    def set_managedsait(self, val: bool) -> None:
        """
        Set ManageDsaIT control for LDAP operations. With ManageDsaIT an
        LDAP referral can be searched, added and modified as a common
        LDAP entry.

        :param bool val: enabling/disabling ManageDsaIT control.
        :raises TypeError: If the parameter is not a bool type.
        """
        if not isinstance(val, bool):
            raise TypeError("Parameter's type must be bool.")
        self.__managedsait_ctrl = val

    def set_url(self, url: Union[LDAPURL, str]) -> None:
        """
        Set LDAP url for the client.

        :param LDAPURL|str url: the LDAP url.
        """
        if isinstance(url, str):
            self.__url = LDAPURL(url)
        elif isinstance(url, LDAPURL):
            self.__url = url
        else:
            raise TypeError("The url parameter must be string or an LDAPURL.")
        if self.__url.scheme != "ldaps" and self.__tls:
            self.__tls = True
        else:
            self.__tls = False

    @property
    def url(self) -> LDAPURL:
        """ The URL of the directory server. """
        return self.__url

    @url.setter
    def url(self, value: Union[LDAPURL, str]) -> None:
        self.set_url(value)

    @property
    def mechanism(self) -> str:
        """ The chosen mechanism for authentication. It cannot be set. """
        return self.__mechanism

    @mechanism.setter
    def mechanism(self, value: Any = None) -> None:
        raise ValueError("Mechanism attribute cannot be set.")

    @property
    def credentials(self) -> Optional[Dict[str, Optional[str]]]:
        """ A dict with the credential information. It cannot be set. """
        return self.__credentials

    @credentials.setter
    def credentials(self, value: Any = None) -> None:
        raise ValueError("Credentials attribute cannot be set.")

    @property
    def tls(self) -> bool:
        """ A bool about TLS connection is required. It cannot be set."""
        return self.__tls

    @tls.setter
    def tls(self, value: Any = None) -> None:
        raise ValueError("TlS attribute cannot be set.")

    @property
    def cert_policy(self) -> int:
        """ The certification policy. """
        return self.__cert_policy

    @cert_policy.setter
    def cert_policy(self, value: str) -> None:
        self.set_cert_policy(value)

    @property
    def ca_cert(self) -> Optional[str]:
        """ The name of the CA certificate. """
        return self.__ca_cert

    @ca_cert.setter
    def ca_cert(self, value: Optional[str] = None) -> None:
        self.set_ca_cert(value)

    @property
    def ca_cert_dir(self) -> Optional[str]:
        """ The path to the CA certificate. """
        return self.__ca_cert_dir

    @ca_cert_dir.setter
    def ca_cert_dir(self, value: Optional[str]) -> None:
        self.set_ca_cert_dir(value)

    @property
    def client_cert(self) -> Optional[str]:
        """ The name of the client certificate. """
        return self.__client_cert

    @client_cert.setter
    def client_cert(self, value: Optional[str]) -> None:
        self.set_client_cert(value)

    @property
    def client_key(self) -> Optional[str]:
        """ The key file to the client's certificate. """
        return self.__client_key

    @client_key.setter
    def client_key(self, value: Optional[str]) -> None:
        self.set_client_key(value)

    @property
    def raw_attributes(self) -> List[str]:
        """ A list of attributes that should be kept in byte format. """
        return self.__raw_list

    @raw_attributes.setter
    def raw_attributes(self, value: List[str]) -> None:
        self.set_raw_attributes(value)

    @property
    def password_policy(self) -> bool:
        """ The status of using password policy. """
        return self.__ppolicy_ctrl

    @password_policy.setter
    def password_policy(self, value: bool) -> None:
        self.set_password_policy(value)

    @property
    def extended_dn_format(self) -> Optional[int]:
        """
        Format of the extended distinguished name. 0 means hexadecimal string
        format, 1 standard string format. If it is `None`, then it's not set.
        """
        return self.__ext_dn

    @extended_dn_format.setter
    def extended_dn_format(self, value: Optional[int]) -> None:
        self.set_extended_dn(value)

    @property
    def auto_page_acquire(self) -> bool:
        """ The status of automatic page acquiring. """
        return self.__auto_acquire

    @auto_page_acquire.setter
    def auto_page_acquire(self, value: bool) -> None:
        self.set_auto_page_acquire(value)

    @property
    def server_chase_referrals(self) -> bool:
        """ The status of chasing referrals by the server. """
        return self.__chase_referrals

    @server_chase_referrals.setter
    def server_chase_referrals(self, value: bool) -> None:
        self.set_server_chase_referrals(value)

    @property
    def managedsait(self) -> bool:
        """ The status of using ManageDsaIT control. """
        return self.__managedsait_ctrl

    @managedsait.setter
    def managedsait(self, value: bool) -> None:
        self.set_managedsait(value)

    def get_rootDSE(self) -> Optional[LDAPEntry]:
        """
        Returns the server's root DSE entry. The root DSE may contain
        information about the vendor, the naming contexts, the request
        controls the server supports, the supported SASL mechanisms,
        features, schema location, and other information.

        :return: the root DSE entry.
        :rtype: :class:`LDAPEntry`
        """
        attrs = [
            "namingContexts",
            "altServer",
            "supportedExtension",
            "supportedControl",
            "supportedSASLMechanisms",
            "supportedLDAPVersion",
        ]
        tls_options = {0: "never", 2: "demand", 3: "allow", 4: "try", -1: None}
        this = self.__class__(self.url, self.tls)
        cert_policy = tls_options[self.cert_policy]
        if cert_policy is not None:
            this.cert_policy = cert_policy
        this.ca_cert = self.ca_cert
        this.ca_cert_dir = self.ca_cert_dir
        this.client_cert = self.client_cert
        this.client_key = self.client_key
        with LDAPConnection(this).open() as conn:
            try:
                root_dse = conn.search(
                    "", LDAPSearchScope.BASE, "(objectclass=*)", attrs, None, False
                )[0]
                return root_dse
            except IndexError:
                return None

    def connect(
        self,
        is_async: bool = False,
        timeout: Optional[float] = None,
        **kwargs: Dict[str, Any]
    ) -> CT:
        """
        Open a connection to the LDAP server.

        :param bool is_async: Set `True` to use asynchronous connection.
        :param float timeout: time limit in seconds for the operation.
        :param \\*\\*kwargs: additional keyword arguments that are passed to
                         the async connection object (e.g. an eventloop
                         object as `loop` parameter).
        :return: an LDAP connection.
        :rtype: :class:`LDAPConnection`
        """
        if is_async:
            return self.__async_conn(self, **kwargs).open(timeout)
        else:
            return LDAPConnection(self).open(timeout)

