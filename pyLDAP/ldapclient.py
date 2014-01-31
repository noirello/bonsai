from pyLDAP import LDAPConnection

from pyLDAP.ldapurl import LDAPURL

class LDAPClient:
    def __init__(self, url="ldap://", tls=False):
        self.__url = LDAPURL(url)
        if self.__url.scheme != "ldaps" and tls:
            self.__tls = True
        else:
            self.__tls = False
        self.__page_size = 0
        self.__auth_dict = None
        self.__raw_list = []
        self.__mechanism = "SIMPLE"
    
    def set_raw_attibutes(self, raw_list):
        for elem in raw_list:
            if type(elem) != str:
                raise ValueError("All element of raw_list must be string.")
        self.__raw_list = raw_list
        
    def set_page_control(self, page_size):
        if type(page_size) != int or page_size < 1:
            raise ValueError("The page_size parameter must be an integer greater, than 0.")
        self.__page_size = page_size
        
    def set_credentials(self, mechanism, auth_dict):
        self.__mechanism = mechanism
        self.__auth_dict = auth_dict
        
    def get_rootDSE(self):
        attrs = ["namingContexts", "altServer", "supportedExtension", 
                 "supportedControl", "supportedSASLMechanisms", 
                 "supportedLDAPVersion"]
        return LDAPConnection(self, False).search("", 0, "(objectclass=*)", 
                                                  attrs, 0, False)[0];
    
    def connect(self, async=False):
        return LDAPConnection(self, async)