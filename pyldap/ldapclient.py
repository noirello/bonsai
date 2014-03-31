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
    
    :param str|LDAPURL url: an LDAP URL.
    :param bool tls: Set `True` to use TLS connection.
    :raises ValueError: if the `url` parameter is not string or not a valid LDAP URL.
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
        self.__page_size = 0
        self.__credentials = None
        self.__raw_list = []
        self.__mechanism = "SIMPLE"
        self.__cert_policy = -1
        self.__sort_attrs = []
    
    def set_raw_attributes(self, raw_list):
        """
        By default the values of the LDAPEntry are in string format. The
        values of the listed LDAP attribute's names in the `raw_list` will be
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
        
    def set_page_size(self, page_size):
        """
        Set how many entry will be on a page of a search result. Setting the page size
        will affect the search to use LDAP paged results. :meth:`LDAPConnection.search`
        will return an iterator instead of a list of entries.    
        
        :param int page_size:
        :raises ValueError: if the parameter is not an integer, or lesser than 2.
        """
        if type(page_size) != int or page_size < 2:
            raise ValueError("The page_size parameter must be an integer greater, than 1.")
        self.__page_size = page_size
        
    def set_sort_order(self, sort_list):
        """
        Set a list of attribute names to sort entries in a search result. For reverse
        order set '-' before to the attribute name.
        
        :param list sort_list: List of attribute names.
        :raises ValueError: if any element of the list is not a string or an \
        empty string, and if any of the attributes is in the list more then once.  
        """
        sort_attrs = []
        for attr in sort_list:
            if type(attr) != str or len(attr) == 0:
                raise ValueError("All element of sort_list must be a non empty string.")
        for attr in sort_list:    
            if attr[0] == '-':
                sort_attrs.append((attr[1:], True))
            else:
                sort_attrs.append((attr, False))
        if len(sort_list) > len(set(map(lambda x: x[0].lower, sort_attrs))):
            raise ValueError("Attribute names must be different from each other.")
        self.__sort_attrs = sort_attrs
        
        
    def set_credentials(self, mechanism, creds):
        """
        Set binding mechanism and credential information. The credential information
        must be in a tuple. If the binding mechanism is ``SIMPLE``, then the tuple
        must have two elements: (binddn, password), every other case: 
        (username, password, realm). If there is no need to specify realm use None for 
        the third element.
         
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
            raise ValueError("All element must be a string in the tuple.")
        if self.__mechanism == "SIMPLE" and len(creds) != 2:
            raise ValueError("""Simple mechanism needs 2 \
credential information: (binddn, password).""")
        if self.__mechanism != "SIMPLE" and len(creds) != 3:
            raise ValueError("""Simple mechanism needs 3 \
credential information: (username, password, realm).""")
        self.__credentials = creds
        
    def set_cert_policy(self, policy):
        """
        Set policy about server certification.
        
        :param str policy: the cert policy could be one of the following strings:
        
            - `try` or `demand`: the server cert will be verified, and if it fail, then \
                the :meth:`LDAPClient.connect` will raise an error.
            - `never` or `allow`: the server cert will be used without any verification. 
        
        :raises ValueError: if the `policy` parameter is not a string, or not one of the \
        four above.
            
        .. warning::
           Set off the cert verification is dangerous. Without verification there is a chance \
           of man-in-the-middle attack. 
        
        """
        tls_options = {'never' : 0, 'demand' : 2, 'allow': 3, 'try' : 4}
        if type(policy) != str:
            raise ValueError("Policy parameter must be string")
        if policy.lower() not in tls_options.keys():
            raise ValueError("'%s' is an invalid policy.", policy)
        self.__cert_policy = tls_options[policy]  
        
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
        root_dse = list(conn.search("", 0, "(objectclass=*)", attrs, 0, False))[0];
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
