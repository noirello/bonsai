Tutorial
========

.. module:: bonsai

After we installed the Bonsai module, let's see the basic functions to communicate with an LDAP server.

Connecting
----------

First we are connecting to the LDAP server at "example.org" using an :class:`LDAPClient` object:

    >>> from bonsai import LDAPClient
    >>> client = LDAPClient("ldap://example.org")
    >>> conn = client.connect()

If we want to use a secure connection over SSL/TLS we can change the URL to `ldaps://`:

    >>> client = LDAPClient("ldaps://example.org")

Or set the `tls` parameter to true for the LDAPClient:
       
    >>> client = LDAPClient("ldap://example.org", True)
    >>> conn = client.connect()  
    
Now, we have an anonym bind to the server, so LDAP whoami operation - which helps to get the identity 
about the authenticated user - will return with the following:

    >>> conn.whoami()
    >>> 'anonymous'

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
dictionary tree, the second parameter - the search scope - can have the following values:
    
    - 0 (base): searching only  the Base DN.
    - 1 (one): searching only one tree level under the Base DN.
    - 2 (sub): searching of all entries at all levels under and th Base DN.

The third parameter is a standard LDAP filter string.

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
    
The other possible parameters are listed on the API page of :meth:`LDAPConnection.search`.

.. note:: 
          As you can see every key - or LDAP attribute - in the entry has a list for clarity, even 
          if only one value belongs to the attribute. As most of the attributes could have more 
          than one value, it would be confusing, if some of the keys had string value and the 
          others had list.     

Add, modify, delete LDAP entry
------------------------------

To add a new entry to our dictionary we need to create an LDAPEntry object with a valid new LDAP DN:

    >>> from bonsai import LDAPEntry
    >>> anna = LDAPEntry("cn=anna,ou=nerdherd,dc=local")
    >>> anna['objectClass'] = ['top', 'inetOrgPerson'] # Must set schemas to get a valid LDAP entry.
    >>> anna['sn'] = "Wu" # Must set a surname attribute because inetOrgPerson shema requires.
    >>> anna['mail'] = "anna@nerdherd.com"
    >>> anna  
    >>> {'cn': ['anna'], 'objectClass': ['top', 'inetorgperson'], 'sn': ['Wu'], 'mail' : ['anna@nerdherd.com']}

then call :meth:`LDAPConnection.add` to add to the server:

    >>> conn.add(anna)
    
It's important, that we must set the schemas and every other attributes, that the shemas require. If we miss 
a required attribute, the server will not finish the opertion and return an :class:`bonsai.ObjectClassViolation` error.

To modify an entry we need to have one that is already in the dictionary (got it back after a search or added 
it by ourself previously), then we can easly add new attributes or modify already existing ones like we usually do
with a Python dict, the only difference is that we need to call :meth:`LDAPEntry.modify` method at the end to save 
our modifications on the server side. 

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

The :class:`LDAPConnection` object can be used with a context manager that will implicitly call the
:meth:`LDAPConnection.close` method:

.. code-block:: python

	import bonsai

	cli = bonsai.LDAPClient("ldap://localhost")
	with cli.connect() as conn:
	    res = conn.search("ou=nerdherd,dc=local", 1)
	    print(res)
	    print(conn.whoami())
    
Asynchronous operations
-----------------------

It is possible to start asynchronous operations, if the :meth:`LDAPClient.connect` method's async parameter is set to True.
By default the returned connection object can be used with Python's `asyncio` library. For further details about how to use
the asyncio library see the  `official documentation`_.

An example for asynchronous search and modify with `asyncio`:

.. _official documentation: https://docs.python.org/3/library/asyncio.html

.. code-block:: python
    
    import asyncio
    import bonsai

    @asyncio.coroutine
    def do():
        cli = bonsai.LDAPClient("ldap://localhost")
        with (yield from cli.connect(async=True)) as conn:
            results = yield from conn.search("ou=nerdherd,dc=local", 1)
            for res in results:
                print(res['givenName'][0])
            search = yield from conn.search("cn=chuck,ou=nerdherd,dc=local", 0)
            entry = list(search)[0]
            entry['mail'] = "chuck@nerdherd.com"
            yield from entry.modify()

    loop = asyncio.get_event_loop()
    loop.run_until_complete(do())

It is also possible to change this class to a different one with :meth:`LDAPClient.set_async_connection_class` that is able
to work with other non-blocking I/O modules like `Gevent`_ or `Tornado`_.

.. _Gevent: http://www.gevent.org/
.. _Tornado: http://www.tornadoweb.org/en/stable/
    
To find out more about the Bonsai module functionality read the :doc:`api`.
