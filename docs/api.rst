API documentation
=================

.. automodule:: pyldap

:class:`LDAPClient`
-------------------
LDAPClient class is for configurate the connection to the directory server. 

.. autoclass:: LDAPClient
.. automethod:: LDAPClient.connect

.. warning::
   Asynchronous connection is not supported at the moment.

.. automethod:: LDAPClient.get_rootDSE
.. automethod:: LDAPClient.set_credentials
.. automethod:: LDAPClient.set_raw_attributes
.. automethod:: LDAPClient.set_page_size
        
:class:`LDAPConnection`
-----------------------
.. class:: LDAPConnection
.. method:: LDAPConnection.add(entry)

   :param LDAPEntry entry: the new entry.
   
   Add new entry to the directory server.

.. method:: LDAPConnection.close()

    Close LDAP connection.
    
.. method:: LDAPConnection.delete(dn)

   :param str dn: the string format of the entry's DN.
   
   Remove entry from the directory server.
   
.. method:: LDAPConnection.search(base=None, scope=None, filter=None, attrlist=[], timeout=0, sizelimit=0, attrsonly=False)

   :param str base: the base DN of the search.
   :param int scope: the scope of the search.
   :param str filter: string to filter the search in LDAP search filter syntax. 
   :param list attrlist: list of attribute's names to receive only those 
                         attributes from the directory server.
   :param int timeout: time limit in seconds for the search.
   :param int sizelimit: the number of entries to limit the search.
   :param bool attrsonly: if it's set True, search result will contain only 
                          the name of the attributes without their values.
   :return: the search result.
   :rtype: list or iterator.
   
   Perform a search on the directory server.  

.. method:: LDAPConnection.whoami()

   This method can use to obtain authorization identity.
   
.. seealso::
    RFC about the LDAP Who am I extended operation `RFC4532`_.
    
.. _RFC4532: https://tools.ietf.org/html/rfc4532


:class:`LDAPDN`
---------------
Class for representing LDAP distinguished names.
 
.. seealso:: 
    
    RFC about **LDAP: String Representation of Distinguished Names** `RFC4514`_.

.. _RFC4514: https://tools.ietf.org/html/rfc4514

Example for working with LDAPDN objects.

    >>> import pyldap
    >>> dn = pyldap.LDAPDN("cn=testuser,dc=local")
    >>> dn
    <LDAPDN cn=testuser,dc=local>
    >>> dn.rdns # Get RDNs in tuple format.
    ((('cn', 'testuser'),), (('dc', 'local'),))
    >>> str(dn) # Convert to string.
    'cn=testuser,dc=local'
    >>> dn[1] # Get the second RDN.
    'dc=local'
    >>> dn[0] # Get the first RDN.
    'cn=testuser'
    >>> dn[1] = "ou=nerdherd,dc=local" # Change the second RDN.
    >>> dn
    <LDAPDN cn=testuser,ou=nerdherd,dc=local>
    >>> other_dn = pyldap.LDAPDN("cn=testuser,ou=nerdherd,dc=local")
    >>> dn == other_dn
    True
    >>> dn[1:3] # Get the second and third RDN.
    'ou=nerdherd,dc=local'
    >>> dn[1:3] = 'ou=buymore,dc=local' # Change them.
    >>> dn
    <LDAPDN cn=testuser,ou=buymore,dc=local>

.. autoclass:: LDAPDN
.. automethod:: LDAPDN.__getitem__
.. automethod:: LDAPDN.__setitem__
.. automethod:: LDAPDN.__eq__
.. automethod:: LDAPDN.__str__
.. autoattribute:: LDAPDN.rdns

:class:`LDAPEntry`
------------------
.. class:: LDAPEntry(dn)
.. method:: LDAPEntry.delete()

    Remove LDAP entry from the dictionary server.
    
.. method:: LDAPEntry.modify()

    Send entry's modifications to the dictionary server.
    
.. method:: LDAPEntry.rename(dn) 

   :param str dn: the new DN of the entry.

:class:`LDAPURL`
----------------
.. seealso:: 
    
    RFC about **LDAP: Uniform Resource Locator** `RFC4516`_.

.. _RFC4516: http://tools.ietf.org/html/rfc4516

.. autoclass:: LDAPURL
.. automethod:: LDAPURL.get_address
.. automethod:: LDAPURL.__str__
.. autoattribute:: LDAPURL.attributes
.. autoattribute:: LDAPURL.basedn
.. autoattribute:: LDAPURL.host
.. autoattribute:: LDAPURL.port
.. autoattribute:: LDAPURL.filter
.. autoattribute:: LDAPURL.scope
.. autoattribute:: LDAPURL.scope_num
.. autoattribute:: LDAPURL.scheme

Errors
------
.. autoclass:: pyldap.errors.LDAPError
.. autoclass:: pyldap.errors.AlreadyExists
.. autoclass:: pyldap.errors.AuthenticationError
.. autoclass:: pyldap.errors.ConnectionError
.. autoclass:: pyldap.errors.InvalidDN
.. autoclass:: pyldap.errors.ObjectClassViolation
.. autoclass:: pyldap.errors.NotConnected

