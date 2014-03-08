Tutorial
========

.. module:: pyldap

After we installed the PyLDAP module, let's see the basic functions to communicate with an LDAP server.

Connecting
----------

First we are connecting to the LDAP server at "example.org" using an :class:`LDAPClient` object:

    >>> from pyldap import LDAPClient
    >>> client = LDAPClient("ldap://example.org")
    >>> conn = client.connect()

If we want to use a secure connection over SSL/TLS we can change the URL to `ldaps://`:

    >>> client = LDAPClient("ldaps://example.org")

Or set the `tls` parameter to true for the LDAPClient:
       
    >>> client = LDAPClient("ldap://example.org", True)
    >>> conn = client.connect()
    
.. warning:: On Microsoft Windows SSL/TLS functions are under development.   
    
Now, we have an anonym bind to the server, so LDAP whoami operation - which helps to get the identity 
about the authenticated user - will return with the following:

    >>> conn.whoami()
    >>> 'anonym'

To connect with a certain user to the server we have to set credentials before connnection:

    >>> client = LDAPClient("ldaps://example.org")
    >>> client.set_credentials("SIMPLE", ("cn=test,dc=local", "secret"))
    >>> conn = client.connect()
    >>> conn.whoami()
    >>> 'cn=test,dc=local'
    
Searching
---------

To execute a simple search in the dictionary we have to use the :meth:`LDAPConnection.search` method. The
function first parameter - the Base DN - sets where we would like to start the search in the 
dictionary tree, the second parameter - the search scope - only can be one of these:
    
    - 0 (base): searching only  the Base DN.
    - 1 (one): searching only one tree level under the Base DN.
    - 2 (sub): searching of all entries at all levels under and th Base DN.

The third paramter is a standard LDAP filter string. 
The result will be a list of LDAPEntry objects or an empty list, if no object is found. 

    >>> conn = client.connect()
    >>> conn.search("ou=nerdherd,dc=local", 1, "(objectclass=*)")
    >>> [{'sn': ['Bartowski'], 'cn': ['chuck'], 'givenName': ['Chuck'], 
    'objectClass': ['inetOrgPerson', 'organizationalPerson', 'person', 'top']}, 
    {'sn': ['Patel'], cn': ['lester'], 'givenName': ['Laster'], 
    'objectClass': ['inetOrgPerson', 'organizationalPerson', 'person', 'top']}, 
    {'sn': ['Barnes'], 'cn': ['jeff'], 'givenName': ['Jeff'], 
    'objectClass': ['inetOrgPerson', 'organizationalPerson', 'person', 'top']}]
    >>> conn.search("ou=nerdherd,dc=local", 0, "(objectclass=*)")
    [{'objectClass': ['organizationalUnit', 'top'], 'ou': ['nerdherd']}]
    
.. note:: 
          As you can see every key - or LDAP attribute - in the entry has a list for clarity, even
          if there is only one value belongs to the attribute. The most of the attributes could 
          have more then one value, so it would be confusing, if some of the keys had string value 
          and the others had list.     

Add, modify, delete LDAP entry
------------------------------

To add a new entry to our dictionary we need to create an LDAPEntry object with a valid new LDAP DN:

    >>> from pyldap import LDAPEntry
    >>> anna = LDAPEntry("cn=anna,ou=nerdherd,dc=local")
    >>> anna['objectClass'] = ['top', 'inetOrgPerson'] # Must set schemas to get a valid LDAP entry.
    >>> anna['sn'] = "Wu" # Must set a surname attribute because inetOrgPerson shema requires.
    >>> anna['mail'] = "anna@nerdherd.com"
    >>> anna  
    >>> {'cn': ['anna'], 'objectClass': ['top', 'inetorgperson'], 'sn': ['Wu'], 'mail' : ['anna@nerdherd.com']}

then call :meth:`LDAPConnection.add` to add to the server:

    >>> conn.add(anna)
    
It's important, that we must set the schemas and every other attributes, that the shemas require. If we miss 
a required attribute, the server will not finish the opertion and return an :class:`ObjectClassViolation` error.

To modify an entry we need to have one that is already in the dictionary (got it back after a search or added 
it by ourself previously), then we can easly add new attributes or modify already existed ones like we usually do
with a Python dict, the only difference is that we need to call :meth:`LDAPEntry.modify` method after the end to 
save our modifications on the server side. 

    >>> anna['givenName'] = "Anna" # Set new givenName attribute.
    >>> anna['cn'].append('wu') # Add new common name attribute without remove the already set ones.
    >>> del anna['mail'] # Remove all values of the mail attribute.
    >>> anna.modify()

To delete an entry we've got two options:

    >>> conn.delete("cn=anna,ou=nerdherd,dc=local") # We have to know the DN of the entry.
    >>> # Or we have a loaded LDAPEntry object, then
    >>> anna.delete() # Entry is removed on the server (we still have the data on the client-side).

After we finished our work with the directory server we should close the connection:

    >>> conn.close()
    
To find out more about the PyLDAP module functionality read the :doc:`api`. 