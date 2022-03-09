Quickstart
**********

.. module:: bonsai
    :noindex:

After we installed the Bonsai module, let's see the basic functions to communicate with an LDAP
server.

Connecting
==========

First we are connecting to the LDAP server at "example.org" using an :class:`LDAPClient` object:

    >>> from bonsai import LDAPClient
    >>> client = LDAPClient("ldap://example.org")
    >>> conn = client.connect()

If we want to use a secure connection over SSL/TLS we can change the URL to `ldaps://`:

    >>> client = LDAPClient("ldaps://example.org")

Or set the `tls` parameter to True for the LDAPClient:
       
    >>> client = LDAPClient("ldap://example.org", True)
    >>> conn = client.connect()

.. note::
    Use either the `ldaps://` scheme or the tls parameter set to True for secure connection,
    but it's ill-advise to use both. If both present the client will set the tls attribute
    to False to avoid connection error.

If we want to use a filesocket connection point the URL to `ldapi://`:

    >>> client = LDAPClient("ldapi://%2Frun%2Fslapd%2Fldapi")

(Please note that in this case the file location has to be URL-encoded.)

Now, we have an anonym bind to the server, so LDAP whoami operation - which helps to get the
identity about the authenticated user - will return with the following:

    >>> conn.whoami()
    'anonymous'

To connect with a certain user to the server we have to set credentials before connection:

    >>> client = LDAPClient("ldaps://example.org")
    >>> client.set_credentials("SIMPLE", user="cn=test,dc=bonsai,dc=test", password="secret")
    >>> conn = client.connect()
    >>> conn.whoami()
    'cn=test,dc=bonsai,dc=test'
    
Searching
=========

To execute a simple search in the dictionary we have to use the :meth:`LDAPConnection.search`
method. The function's first parameter - the base DN - sets where we would like to start the search
in the dictionary tree, the second parameter - the search scope - can have the following values:

    - 0 (base): searching only the base DN.
    - 1 (one): searching only one tree level under the base DN.
    - 2 (sub): searching of all entries at all levels under, including the base DN.

The scope parameter is replaceable with an :class:`LDAPSearchScope` enumeration, for e.g.
:attr:`LDAPSearchScope.ONE` for one level search.

The third parameter is a standard LDAP filter string.

The result will be a list of LDAPEntry objects or an empty list, if no object is found.

    >>> conn = client.connect()
    >>> conn.search("ou=nerdherd,dc=bonsai,dc=test", bonsai.LDAPSearchScope.ONE, "(objectclass=*)")
    [{'dn': <LDAPDN cn=chuck,ou=nerdherd,dc=bonsai,dc=test>, 'sn': ['Bartowski'],
    'cn': ['chuck'], 'givenName': ['Chuck'], 'objectClass': ['inetOrgPerson',
    'organizationalPerson', 'person', 'top']}, {'dn': <LDAPDN cn=lester,ou=nerdherd,dc=bonsai,dc=test>,
    'sn': ['Patel'], cn': ['lester'], 'givenName': ['Laster'],  'objectClass': ['inetOrgPerson',
    'organizationalPerson', 'person', 'top']}, {'dn': <LDAPDN cn=jeff,ou=nerdherd,dc=bonsai,dc=test>,
    'sn': ['Barnes'], 'cn': ['jeff'], 'givenName': ['Jeff'], 'objectClass': ['inetOrgPerson',
    'organizationalPerson', 'person', 'top']}]
    >>> conn.search("ou=nerdherd,dc=bonsai,dc=test", 0, "(objectclass=*)")
    [{'dn': <LDAPDN ou=nerdherd,dc=bonsai,dc=test>, 'objectClass': ['organizationalUnit', 'top'],
    'ou': ['nerdherd']}]
    
The other possible parameters are listed on the API page of :meth:`LDAPConnection.search`.

.. note:: 
          As you can see every key - or LDAP attribute - in the entry has a list for clarity, even
          if only one value belongs to the attribute. As most of the attributes could have more
          than one value, it would be confusing, if some of the keys had string value and the
          others had list.

Add and modify LDAP entry
=========================

To add a new entry to our dictionary we need to create an :class:`LDAPEntry` object with a valid new
LDAP DN:

    >>> from bonsai import LDAPEntry
    >>> anna = LDAPEntry("cn=anna,ou=nerdherd,dc=bonsai,dc=test")
    >>> anna['objectClass'] = ['top', 'inetOrgPerson'] # Must set schemas to get a valid LDAP entry.
    >>> anna['sn'] = "Wu" # Must set a surname attribute because inetOrgPerson schema requires.
    >>> anna['mail'] = "anna@nerdherd.com"
    >>> anna.dn
    <LDAPDN cn=anna,ou=nerdherd,dc=bonsai,dc=test>
    >>> anna
    {'dn': <LDAPDN cn=anna,ou=nerdherd,dc=bonsai,dc=test>, 'objectClass': ['top', 'inetOrgPerson'],
    'sn': ['Wu'], 'mail': ['anna@nerdherd.com']}

then call :meth:`LDAPConnection.add` to add to the server:

    >>> conn.add(anna)
    True
    
It's important, that we must set the schemas and every other attribute, that the schemas require.
If we miss a required attribute, the server will not finish the operation and return with an
:class:`bonsai.ObjectClassViolation` error.

To modify an entry we need to have one that is already in the dictionary (got it back after a
search or added it by ourselves previously), then we can easily add new attributes or modify
already existing ones like we usually do with a Python dict, the only difference is that we need to
call :meth:`LDAPEntry.modify` method at the end to save our modifications on the server side.

    >>> anna['givenName'] = "Anna" # Set new givenName attribute.
    >>> anna['cn'].append('wu') # Add new common name attribute without remove the already set ones.
    >>> del anna['mail'] # Remove all values of the mail attribute.
    >>> anna.modify()
    True

In certain cases, an LDAP entry can have write-only attribute (e.g. password) that cannot be
represented in an LDAPEntry or we just want to change the value of an attribute without reading
it first. The :meth:`LDAPEntry.change_attribute` method expects an attribute name, the type
of the modification (as an integer or an :class:`LDAPModOp` enum) and the values as parameters
to change an entry:

    >>> from bonsai import LDAPEntry, LDAPModOp
    >>> anna = LDAPEntry("cn=anna,ou=nerdherd,dc=bonsai,dc=test")
    >>> anna.change_attribute("userPassword", LDAPModOp.REPLACE, "newsecret")
    >>> anna.modify()
    True

Delete an LDAP entry
====================

To delete an entry we've got two options: :meth:`LDAPConnection.delete` and
:meth:`LDAPEntry.delete`:

    >>> conn.delete("cn=anna,ou=nerdherd,dc=bonsai,dc=test") # We have to know the DN of the entry.
    True
    >>> # Or we have a loaded LDAPEntry object, then
    >>> anna.delete()
    True

In the second case the entry is removed on the server, but we still have the data on the
client-side.

Rename an LDAP entry
====================

To rename an existing entry call the :meth:`LDAPEntry.rename` method with the new DN on an already
loaded :class:`LDAPEntry` object:

    >>> anna.dn
    <LDAPDN cn=anna,ou=nerdherd,dc=bonsai,dc=test>
    >>> anna.rename("cn=wu,ou=nerdherd,dc=bonsai,dc=test")
    True
    >>> anna.dn
    <LDAPDN cn=wu,ou=nerdherd,dc=bonsai,dc=test>

Be aware that if you would like to move the entry into a different subtree of the directory, then
the stated subtree needs to already exist.

Close connection
================

After we finished our work with the directory server we should close the connection:

    >>> conn.close()

The :class:`LDAPConnection` object can be used with a context manager that will implicitly call the
:meth:`LDAPConnection.close` method:

.. code-block:: python

    import bonsai

    cli = bonsai.LDAPClient("ldap://localhost")
    with cli.connect() as conn:
        res = conn.search("ou=nerdherd,dc=bonsai,dc=test", 1)
        print(res)
        print(conn.whoami())


To find out more about the Bonsai module functionality read the :doc:`advanced` and the :doc:`api`.
