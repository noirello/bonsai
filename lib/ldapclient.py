"""
.. module:: LDAPClient
   :platform: Unix, Windows
   :synopsis: For management LDAP connections.

"""
import socket

from .ldapurl import LDAPURL
from .errors import LDAPError
from .ldapconnection import LDAPConnection
from .asyncio import AIOLDAPConnection

class LDAPClient:
    """
    This class is for managing LDAP connections.

    :param str|LDAPURL url: an LDAP URL.
    :param bool tls: Set `True` to use TLS connection.
    :raises ValueError: if the `url` parameter is not string \
    or not a valid LDAP URL.
    """
    def __init__(self, url="ldap://", tls=False):
        """ init method. """
        if type(url) == str:
            self.__url = LDAPURL(url)
        elif type(url) == LDAPURL:
            self.__url = url
        else:
            raise ValueError("The url parameter must be string or an LDAPURL.")
        if self.__url.scheme != "ldaps" and tls:
            self.__tls = True
        else:
            self.__tls = False
        self.__credentials = None
        self.__raw_list = []
        self.__mechanism = "SIMPLE"
        self.__cert_policy = -1
        self.__ca_cert = ""
        self.__ca_cert_dir = ""
        self.__client_cert = ""
        self.__client_key = ""
        self.__async_conn = AIOLDAPConnection

    @staticmethod
    def _create_socketpair():
        """
        Create a socketpair that will be used for signaling to select() during
        the initialisation procedure (and binding on MS Windows).
        """
        if hasattr(socket, "socketpair"):
            return socket.socketpair()
        # Backward compatibility on Windows from Python 3.5.
        # Origin: https://gist.github.com/4325783, by Geert Jansen.  Public domain.
        def socketpair(family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0):
            import errno
            # We create a connected TCP socket. Note the trick with setblocking(0)
            # that prevents us from having to create a thread.
            lsock = socket.socket(family, type, proto)
            lsock.bind(('localhost', 0))
            lsock.listen(1)
            addr, port = lsock.getsockname()
            csock = socket.socket(family, type, proto)
            csock.setblocking(0)
            try:
                csock.connect((addr, port))
            except socket.error as e:
                if e.errno != errno.WSAEWOULDBLOCK:
                    raise
            ssock, addr = lsock.accept()
            csock.setblocking(1)
            lsock.close()
            return (ssock, csock)
        return socketpair()

    def set_raw_attributes(self, raw_list):
        """
        By default the values of the LDAPEntry are in string format. The
        values of the listed LDAP attribute's names in `raw_list` will be
        kept in bytearray format.

        :param list raw_list: a list of LDAP attributum's names. \
        The elements must be string and unique.

        :raises ValueError: if any of the list's element is not a \
        string or not a unique element.
        """
        for elem in raw_list:
            if type(elem) != str:
                raise ValueError("All element of raw_list must be string.")
        if len(raw_list) > len(set(map(str.lower, raw_list))):
            raise ValueError("Attribute names must be different from each other.")
        self.__raw_list = raw_list

    def set_credentials(self, mechanism, creds):
        """
        Set binding mechanism and credential information. The credential
        information must be in a tuple. If the binding mechanism is ``SIMPLE``,
        then the tuple must have two elements: (binddn, password), if \
        ``EXTERNAL`` then only one element is needed: (authzid,). Every other
        case: (username, password, realm, authzid). If there is no need to \
        specify realm or authorization ID then use None for these elements.

        :param str mechanism: the name of the binding mechanism:
        :param tuple creds: the credential information.
        :raises ValueError: if the `mechanism` parameter is not a string, or \
        the `creds` is not a tuple, or the tuple has wrong length.
        """
        if type(mechanism) != str:
            raise ValueError("The mechanism must be a string.")
        self.__mechanism = mechanism.upper()
        if type(creds) != tuple:
            raise ValueError("The credential information must be in a tuple.")
        if list(filter(lambda x: type(x) != str and x != None, creds)) != []:
            raise ValueError("All element must be a string or None in the"
                             " tuple.")
        if self.__mechanism == "EXTERNAL":
            if len(creds) != 1:
                raise ValueError("External mechanism needs only one credential"
                                 " information in a tuple: (authzid,)")
            # Supplement the tuple with Nones.
            creds = (None, None, None, creds[0])
        if self.__mechanism == "SIMPLE" and len(creds) != 2:
            raise ValueError("Simple mechanism needs 2 "
                             "credential information: (binddn, password).")
        if self.__mechanism != "SIMPLE" and len(creds) != 4:
            raise ValueError("%s mechanism needs 4 "
                             "credential information: (username, password, "
                             "realm, authzid)." % self.__mechanism)
        self.__credentials = creds

    def set_cert_policy(self, policy):
        """
        Set policy about server certification.

        :param str policy: the cert policy could be one of the following \
        strings:

            - `try` or `demand`: the server cert will be verified, and if it \
            fail, then the :meth:`LDAPClient.connect` will raise an error.
            - `never` or `allow`: the server cert will be used without any \
            verification.

        :raises ValueError: if the `policy` parameter is not a string, or not \
        one of the four above.

        .. warning::
           Set off the cert verification is dangerous. Without verification \
           there is a chance of man-in-the-middle attack.
        """
        tls_options = {'never' : 0, 'demand' : 2, 'allow': 3, 'try' : 4}
        if type(policy) != str:
            raise ValueError("Policy parameter must be string.")
        policy = policy.lower()
        if policy not in tls_options.keys():
            raise ValueError("'%s' is an invalid policy.", policy)
        self.__cert_policy = tls_options[policy]

    def set_ca_cert(self, name):
        """
        Set the name of CA certificate. If the underlying libldap library \
        uses the Mozilla NSS as TLS implementation library the `name` \
        should be the same one in the cert/key database (that specified with \
        :meth:`LDAPClient.set_ca_cert_dir`), otherwise it can be the name \
        of the CA cert file.
        
        .. note::
           This method has no effect on MS Windows, because WinLDAP \
           searches for the corresponding CA certificate in the cert \
           store. This means that the necessery certificates have to be \
           installed manually in to the cert store.  

        :param str name: the name of the CA cert.
        :raises ValueError: if `name` parameter is not a string or not None.
        """
        if name is not None and type(name) != str:
            raise ValueError("Name parameter must be string or None.")
        self.__ca_cert = name

    def set_ca_cert_dir(self, path):
        """
        Set the directory of the CA cert. If the underlying libldap library \
        uses the Mozilla NSS as TLS implementation library the `path` \
        should be the path to the existing cert/key database, otherwise it \
        can be the path of the CA cert file.
        
        .. note::
           This method has no effect on MS Windows, because WinLDAP \
           searches for the corresponding CA certificate in the cert \
           store. This means that the necessery certifications have to be \
           installed manually in to the cert store.            

        :param str path: the path to the CA directory.
        :raises ValueError: if `path` parameter is not a string or not None.
        """
        if path is not None and type(path) != str:
            raise ValueError("Path parameter must be string or None.")
        self.__ca_cert_dir = path

    def set_client_cert(self, name):
        """
        Set the name of client certificate. If the underlying libldap library \
        uses the Mozilla NSS as TLS implementation library the `name` \
        should be the same one in the cert/key database (that specified with \
        :meth:`LDAPClient.set_ca_cert_dir`), otherwise it can be the name \
        of the client certificate file.
        
        .. note::
           This method has no effect on MS Windows, because WinLDAP \
           searches for the corresponding client certificate based on \
           the servert's CA cert in the cert store. This means that the \
           necessery certificates have to be installed manually in to \
           the cert store.  

        :param str name: the name of the client cert.
        :raises ValueError: if `name` parameter is not a string or not None.
        """
        if name is not None and type(name) != str:
            raise ValueError("Name parameter must be string or None.")
        self.__client_cert = name

    def set_client_key(self, name):
        """
        Set the file that contains the private key that matches the \
        certificate of the client that specified with \
        :meth:`LDAPClient.set_client_cert`).
        
        .. note::
           This method has no effect on MS Windows, because WinLDAP \
           searches for the corresponding client certificate based on \
           the servert's CA cert in the cert store. This means that the \
           necessery certificates have to be installed manually in to \
           the cert store.  

        :param str name: the name of the CA cert.
        :raises ValueError: if `name` parameter is not a string or not None.
        """
        if name is not None and type(name) != str:
            raise ValueError("Name parameter must be string or None.")
        self.__client_key = name

    def set_async_connection_class(self, conn):
        """
        Set the LDAP connection class for asynchronous connection. The \
        default connection class is `AIOLDAPConnection` that uses the
        asyncio event loop.
        
        :param class conn:
        :raises ValueError: if `conn` parameter is not a subclass \
        of :class:`LDAPConnection`.
        """
        if not issubclass(conn, LDAPConnection):
            raise ValueError("Class must be a subclass of LDAPConnection. ")
        self.__async_conn = conn

    def get_rootDSE(self):
        """
        Returns the server's root DSE entry. The root DSE may contain
        information about the vendor, the naming contexts, the request
        controls the server supports, the supported SASL mechanisms,
        features, schema location, and other information.

        :return: the root DSE entry.
        :rtype: :class:`LDAPEntry`
        """
        attrs = ["namingContexts", "altServer", "supportedExtension",
                 "supportedControl", "supportedSASLMechanisms",
                 "supportedLDAPVersion"]
        conn = LDAPConnection(self, False).open()
        try:
            # Convert to list to avoid possible LDAPSearchIter object.
            root_dse = list(conn.search("", 0, "(objectclass=*)", attrs, 0, False))[0]
        except IndexError:
            return None
        finally:
            conn.close()
            return root_dse

    @property
    def url(self):
        """ The URL of the directoty server. It cannot be set. """
        return self.__url

    @url.setter
    def url(self, value=None):
        raise ValueError("URL attribute cannot be set.")

    @property
    def mechanism(self):
        """ The choosen mechanism for authentication. It cannot be set. """
        return self.__mechanism

    @mechanism.setter
    def mechanism(self, value=None):
        raise ValueError("Mechanism attribute cannot be set.")

    @property
    def credentials(self):
        """ A tuple with the credential information. It cannot be set. """
        return self.__credentials

    @credentials.setter
    def credentials(self, value=None):
        raise ValueError("Credentials attribute cannot be set.")

    @property
    def tls(self):
        """ A bool about TLS connection is required. It cannot be set."""
        return self.__tls

    @tls.setter
    def tls(self, value=None):
        raise ValueError("Tls attribute cannot be set.")

    @property
    def cert_policy(self):
        """ The certification policy. """
        return self.__cert_policy

    @cert_policy.setter
    def cert_policy(self, value=None):
        self.set_cert_policy(value)

    @property
    def ca_cert(self):
        """ The name of the CA certificate. """
        return self.__ca_cert

    @ca_cert.setter
    def ca_cert(self, value):
        self.set_ca_cert(value)

    @property
    def ca_cert_dir(self):
        """ The path to the CA certificate. """ 
        return self.__ca_cert_dir

    @ca_cert_dir.setter
    def ca_cert_dir(self, value):
        self.set_ca_cert_dir(value)

    @property
    def client_cert(self):
        """ The name of the client certificate. """
        return self.__client_cert

    @client_cert.setter
    def client_cert(self, value):
        self.set_client_cert(value)

    @property
    def client_key(self):
        """ The key file to the client's certificate. """
        return self.__client_key

    @client_key.setter
    def client_key(self, value):
        self.set_client_key(value)

    @property
    def raw_attributes(self):
        """ A list of attributes that should be kept in byte format. """
        return self.__raw_list

    @raw_attributes.setter
    def raw_attributes(self, value=None):
        self.set_raw_attributes(value)

    def connect(self, async=False, **kwargs):
        """
        Open a connection to the LDAP server.

        :param bool async: Set `True` to use asynchronous connection.
        :return: an LDAP connection.
        :rtype: :class:`LDAPConnection`
        """
        if async:
            return self.__async_conn(self, **kwargs).open()
        else:
            return LDAPConnection(self, async).open()
