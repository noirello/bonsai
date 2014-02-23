"""
.. module:: LDAPClient
   :platform: Unix, Windows
   :synopsis: For management LDAP connections.

"""
from pyldap import LDAPConnection

from pyldap.ldapurl import LDAPURL

class LDAPClient:
    """
    This class is for managing LDAP connections.
    
    :param str url: an LDAP URL.
    :param bool tls: Set `True` to use TLS connection. 
    """
    def __init__(self, url="ldap://", tls=False):
        """ init method. """
        self.__url = LDAPURL(url)
        if self.__url.scheme != "ldaps" and tls:
            self.__tls = True
        else:
            self.__tls = False
        self.__page_size = 0
        self.__auth_dict = None
        self.__raw_list = []
        self.__mechanism = "SIMPLE"
    
    def set_raw_attributes(self, raw_list):
        """
        By default the values of the LDAPEntry are in string format. The
        values of the listed LDAP attribute's names in the `raw_list` will be
        keep in bytearray format.
        
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
        
    def set_page_result(self, page_size):
        """
        To use LDAP page result control set a number how many entry will be on a
        page.  
        
        :param int page_size:
        :raises ValueError: if the parameter is not an integer, or lesser than 2.
        """
        if type(page_size) != int or page_size < 2:
            raise ValueError("The page_size parameter must be an integer greater, than 1.")
        self.__page_size = page_size
        
    def set_credentials(self, mechanism, auth_dict):
        """
        Set binding mechanism and credential information.
        
        :param str mechanism: the name of the binding mechanism:
        :param dict auth_dict: the credential information.
        :raises ValueError: if the `mechanism` parameter is not a string.
        """
        if type(mechanism) != str:
            raise ValueError("The mechanism must be a string.")
        self.__mechanism = mechanism.upper()
        self.__auth_dict = auth_dict
        
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
        conn = LDAPConnection(self, False)
        root_dse = conn.search("", 0, "(objectclass=*)", attrs, 0, False)[0];
        conn.close()
        return root_dse
    
    def connect(self, async=False):
        """
        Open a connection to the LDAP server.
        
        :param bool async: Set `True` to use asyncronous connection.
        :return: an LDAP connection.
        :rtype: :class:`LDAPConnection` 
        """
        return LDAPConnection(self, async)
