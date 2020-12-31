API documentation
*****************

bonsai
======

.. automodule:: bonsai

:class:`LDAPClient`
-------------------
.. autoclass:: LDAPClient(url, tls=False)
.. automethod:: LDAPClient.connect(is_async=False, timeout=None, **kwargs)
.. automethod:: LDAPClient.get_rootDSE()

    An example of getting the root DSE:
    
    >>> client = bonsai.LDAPClient()
    >>> client.get_rootDSE()
    {'namingContexts': ['dc=bonsai,dc=test'], 'supportedControl': ['2.16.840.1.113730.3.4.18',
    '2.16.840.1.113730.3.4.2', '1.3.6.1.4.1.4203.1.10.1', '1.2.840.113556.1.4.319',
    '1.2.826.0.1.3344810.2.3', '1.3.6.1.1.13.2', '1.3.6.1.1.13.1', '1.3.6.1.1.12'],
    'supportedLDAPVersion': ['3'], 'supportedExtension': ['1.3.6.1.4.1.1466.20037',
    '1.3.6.1.4.1.4203.1.11.1', '1.3.6.1.4.1.4203.1.11.3', '1.3.6.1.1.8'],
    'supportedSASLMechanisms': ['DIGEST-MD5', 'NTLM', 'CRAM-MD5']}

.. automethod:: LDAPClient.set_async_connection_class(conn)

    An example to change the default async connection class to a Gevent-based one:

    >>> import bonsai
    >>> from bonsai.gevent import GeventLDAPConnection
    >>> client = bonsai.LDAPClient()
    >>> client.set_async_connection_class(GeventLDAPConnection)
    >>> client.connect(True)
    <bonsai.gevent.geventconnection.GeventLDAPConnection object at 0x7f9b1789c6d8>

.. automethod:: LDAPClient.set_auto_page_acquire(val)
.. automethod:: LDAPClient.set_ca_cert(name)
.. automethod:: LDAPClient.set_ca_cert_dir(path)
.. automethod:: LDAPClient.set_cert_policy(policy)
.. automethod:: LDAPClient.set_client_cert(name)
.. automethod:: LDAPClient.set_client_key(name)

.. automethod:: LDAPClient.set_credentials(mechanism, user=None, password=None, realm=None, authz_id=None, keytab=None)

    >>> from bonsai import LDAPClient
    >>> client = LDAPClient()
    >>> client.set_credentials("SIMPLE", user="cn=user,dc=bonsai,dc=test", password="secret")
    >>> client.connect()
    <bonsai.LDAPConnection object at 0x7fadf8976440>

.. automethod:: LDAPClient.set_extended_dn(extdn_format)

    An example:

    >>> client = bonsai.LDAPClient()
    >>> client.set_extended_dn(1)
    >>> result = conn.search("ou=nerdherd,dc=bonsai,dc=test", 1)
    >>> result[0].extended_dn
    <GUID=899e4e01-e88d-4dea-ba64-119ed386b61c>;<SID=S-1-5-21-101232111302-1767724339-724445543-12345>;cn=chuck,ou=nerdherd,dc=bonsai,dc=test
    >>> result[0].dn
    <LDAPDN cn=chuck,ou=nerdherd,dc=bonsai,dc=test>

.. note:: If the extended dn control is not supported the LDAPEntry's extended_dn attribute
   will be None. The LDAP_SERVER_EXTENDED_DN_OID is defined as '1.2.840.113556.1.4.529'.

.. automethod:: LDAPClient.set_managedsait(val)

.. automethod:: LDAPClient.set_password_policy(ppolicy)

    An example:

    >>> import bonsai
    >>> client = bonsai.LDAPClient()
    >>> client.set_credentials("SIMPLE", "cn=user,dc=bonsai,dc=test", "secret")
    >>> client.set_password_policy(True)
    >>> conn, ctrl = client.connect()
    >>> conn
    <bonsai.ldapconnection.LDAPConnection object at 0x7fa552ab4e28>
    >>> ctrl
    {'grace': 1, 'expire': 3612, 'oid': '1.3.6.1.4.1.42.2.27.8.5.1'})

.. note:: Password policy control cannot be used on MS Windows with WinLDAP.
   In this case after opening a connection the control dictionary will always be
   `None`.

.. automethod:: LDAPClient.set_raw_attributes(raw_list)

    An example:

    >>> client = bonsai.LDAPClient()
    >>> client.set_raw_attributes(["cn", "sn"])
    >>> conn = client.connect()
    >>> conn.search("cn=jeff,ou=nerdherd,dc=bonsai,dc=test", 0, attrlist=['cn', 'sn', 'gn'])
    [{'dn': <LDAPDN cn=jeff,ou=nerdherd,dc=bonsai,dc=test>, 'sn': [b'Barnes'], 'cn': [b'jeff'],
    'givenName': ['Jeff']}]

.. automethod:: LDAPClient.set_server_chase_referrals(val)
.. automethod:: LDAPClient.set_url(url)

.. autoattribute:: LDAPClient.auto_page_acquire
.. autoattribute:: LDAPClient.ca_cert
.. autoattribute:: LDAPClient.ca_cert_dir
.. autoattribute:: LDAPClient.cert_policy
.. autoattribute:: LDAPClient.client_cert
.. autoattribute:: LDAPClient.client_key
.. autoattribute:: LDAPClient.credentials
.. autoattribute:: LDAPClient.extended_dn_format
.. autoattribute:: LDAPClient.managedsait
.. autoattribute:: LDAPClient.mechanism
.. autoattribute:: LDAPClient.password_policy
.. autoattribute:: LDAPClient.raw_attributes
.. autoattribute:: LDAPClient.server_chase_referrals
.. autoattribute:: LDAPClient.tls
.. autoattribute:: LDAPClient.url

:class:`LDAPConnection`
-----------------------
.. autoclass:: LDAPConnection

.. method:: LDAPConnection.abandon(msg_id)

    Abandon an ongoing asynchronous operation associated with the given message id.
    Note that there is no guarantee that the LDAP server will be able to honor the request, which
    means the operation could be performed anyway. Nevertheless, it is a good programming paradigm
    to abandon unwanted operations (e.g after a timeout is exceeded).

    :param int msg_id: the ID of an ongoing LDAP operation.

.. automethod:: LDAPConnection.add(entry, timeout=None)

.. method:: LDAPConnection.close()

    Close LDAP connection.
    
.. automethod:: LDAPConnection.delete(dname, timeout=None, recursive=False)

.. method:: LDAPConnection.fileno()

    Return the file descriptor of the underlying socket that is used for the LDAP connection.

    :return: The file descriptor.
    :rtype: int

.. method:: LDAPConnection.get_result(msg_id, timeout=None)

    Get the result of an ongoing asynchronous operation associated with the given message id.
    The method blocks the caller until the given `timeout` parameter is passed or the result
    is arrived. If the operation is not finished until the timeout, it returns None. If the
    `timeout` is None, it returns immediately.

    :param int msg_id: the ID of an ongoing LDAP operation.
    :param float timeout:  time limit in seconds for waiting on the result.
    :return: the result of the operation.
    :rtype: depending on the type of the operation.
    :raises bonsai.InvalidMessageID: if the message ID is invalid or the associated operation is
                                     already finished

.. automethod:: LDAPConnection.open(timeout=None)
.. automethod:: LDAPConnection.modify_password(user=None, new_password=None, old_password=None, timeout=None)
.. seealso::
    RFC about the LDAP Password Modify extended operation `RFC3062`_.

.. _RFC3062: https://www.ietf.org/rfc/rfc3062.txt

.. method:: LDAPConnection.search(base=None, scope=None, filter_exp=None, attrlist=None, timeout=None,\
                                  sizelimit=0, attrsonly=False, sort_order=None)

    Perform a search on the directory server. A base DN and a search scope is always necessary to
    perform a search, but these values - along with the attribute's list and search filter - can
    also be set with the :class:`LDAPClient` LDAP URL parameter. The parameters, which are passed
    to the :meth:`LDAPConnection.search` method will overrule the previously set ones with the
    LDAP URL.

    Setting `sort_order` will invoke server side sorting LDAP control, based on the provided attribute list.

    >>> from bonsai import LDAPClient
    >>> client = LDAPClient("ldap://localhost") # without additional parameters
    >>> conn = client.connect()
    >>> conn.search("ou=nerdherd,dc=bonsai,dc=test", 1, "(cn=ch*)", ["cn", "sn", "gn"])
    [{'dn': <LDAPDN cn=chuck,ou=nerdherd,dc=bonsai,dc=test>, 'sn': ['Bartowski'], 'cn': ['chuck'],
    'givenName': ['Chuck']}]
    >>> client = LDAPClient("ldap://localhost/ou=nerdherd,dc=bonsai,dc=test?cn,sn,gn?one?(cn=ch*)") # with additional parameters
    >>> conn = client.connect()
    >>> conn.search()
    [{'dn': <LDAPDN cn=chuck,ou=nerdherd,dc=bonsai,dc=test>, 'sn': ['Bartowski'], 'cn': ['chuck'],
    'givenName': ['Chuck']}]
    >>> conn.search(filter_exp="(cn=j*)")
    [{'dn': <LDAPDN cn=jeff,ou=nerdherd,dc=bonsai,dc=test>, 'sn': ['Barnes'], 'cn': ['jeff'],
    'givenName': ['Jeff']}]

    :param str base: the base DN of the search.
    :param int scope: the scope of the search. An :class:`LDAPSearchScope` also can be used as
                      value.
    :param str filter_exp: string to filter the search in LDAP search filter syntax.
    :param list attrlist: list of attribute's names to receive only those attributes from the
                          directory server.
    :param float timeout: time limit in seconds for the search.
    :param int sizelimit: the number of entries to limit the search.
    :param bool attrsonly: if it's set True, search result will contain only the name of the
                           attributes without their values.
    :param list sort_order: list of attribute's names to use for server-side ordering, start name
                            with '-' for descending order.
    :return: the search result.
    :rtype: list

.. method:: LDAPConnection.paged_search(base=None, scope=None, filter_exp=None, attrlist=None,\
                                        timeout=None, sizelimit=0, attrsonly=False,\
                                        sort_order=None, page_size=1)

    Perform a search that returns a paged search result. The number of entries on a page is limited
    with the `page_size` parameter. The return value is an :class:`ldapsearchiter` which is an
    iterable object. By default, after returning the last entry on the page it automatically requests
    the next page from the server until the final page is delivered. This functionality can be
    disabled by setting the :attr:`LDAPClient.auto_page_acquire` to `false`. Then the next page
    can be acquired manually by calling the :meth:`ldapsearchiter.acquire_next_page` method.

    :param str base: the base DN of the search.
    :param int scope: the scope of the search. An :class:`LDAPSearchScope` also can be used as
                      value.
    :param str filter_exp: string to filter the search in LDAP search filter syntax.
    :param list attrlist: list of attribute's names to receive only those attributes from the
                          directory server.
    :param float timeout: time limit in seconds for the search.
    :param int sizelimit: the number of entries to limit the search.
    :param bool attrsonly: if it's set True, search result will contain only the name of the
                           attributes without their values.
    :param list sort_order: list of attribute's names to use for server-side ordering, start name
                            with '-' for descending order.
    :param int page_size: the number of entries on a page.
    :return: the search result.
    :rtype: ldapsearchiter

.. method:: LDAPConnection.virtual_list_search(base=None, scope=None, filter_exp=None, attrlist=None,\
                                               timeout=None, sizelimit=0, attrsonly=False,\
                                               sort_order=None, offset=1, before_count=0,\
                                               after_count=0, est_list_count=0, attrvalue=None)

    Perform a search using virtual list view control. To perform the search the server side sort
    control has to be set with `sort_order`. The result set will be shifted to the `offset` or
    `attrvalue` and contains the specific number of entries after and before, set with
    `after_count` and `before_count`. The `est_list_count` is an estimation of the entire searched
    list that helps to the server to position the target entry.

    The result of the operation is a tuple of a list and a dictionary. The dictionary contains
    the VLV server response: the target position and the real list size. Thi list contains the
    searched entries.

    For further details using these controls please see :ref:`ldap-controls`.

    :param str base: the base DN of the search.
    :param int scope: the scope of the search. An :class:`LDAPSearchScope` also can be used as
                      value.
    :param str filter_exp: string to filter the search in LDAP search filter syntax.
    :param list attrlist: list of attribute's names to receive only those attributes from the
                          directory server.
    :param float timeout: time limit in seconds for the search.
    :param int sizelimit: the number of entries to limit the search.
    :param bool attrsonly: if it's set True, search result will contain only the name of the
                           attributes without their values.
    :param list sort_order: list of attribute's names to use for server-side ordering, start name
                            with '-' for descending order.
    :param int offset: an offset of the search result to select a target entry for virtual list
                       view (VLV).
    :param int before_count: the number of entries before the target entry for VLV.
    :param int after_count: the number of entries after the target entry for VLV.
    :param int est_list_count: the estimated content count of the entire list for VLV.
    :param attrvalue: an attribute value (of the attribute that is used for sorting) for
                      identifying the target entry for VLV.
    :return: the search result.
    :rtype: (list, dict)

.. automethod:: LDAPConnection.whoami(timeout=None)
.. seealso::
    RFC about the LDAP Who am I extended operation `RFC4532`_.
    
.. _RFC4532: https://tools.ietf.org/html/rfc4532

.. attribute:: LDAPConnection.closed

    A readonly attribute about the connection's state.

.. attribute:: LDAPConnection.is_async

    A readonly attribute to define that the connections is asynchronous.

:class:`LDAPDN`
---------------

Class for representing LDAP distinguished names.
 
.. seealso:: 
    
    RFC about **LDAP: String Representation of Distinguished Names** `RFC4514`_.

.. _RFC4514: https://tools.ietf.org/html/rfc4514

Example for working with LDAPDN objects.

    >>> import bonsai
    >>> dn = bonsai.LDAPDN("cn=testuser,dc=bonsai,dc=test")
    >>> dn
    <LDAPDN cn=testuser,dc=bonsai,dc=test>
    >>> dn.rdns # Get RDNs in tuple format.
    ((('cn', 'testuser'),), (('dc', 'bonsai'),), (('dc', 'test'),))
    >>> str(dn) # Convert to string.
    'cn=testuser,dc=bonsai,dc=test'
    >>> dn[1] # Get the second RDN.
    'dc=bonsai'
    >>> dn[0] # Get the first RDN.
    'cn=testuser'
    >>> dn[1] = "ou=nerdherd,dc=bonsai" # Change the second RDN.
    >>> dn
    <LDAPDN cn=testuser,ou=nerdherd,dc=bonsai,dc=test>
    >>> other_dn = bonsai.LDAPDN("cn=testuser,ou=nerdherd,dc=bonsai,dc=test")
    >>> dn == other_dn
    True
    >>> dn[1:3] # Get the second and third RDN.
    'ou=nerdherd,dc=bonsai'
    >>> dn[1:3] = 'ou=buymore,dc=bonsai' # Change them.
    >>> dn
    <LDAPDN cn=testuser,ou=buymore,dc=bonsai,dc=test>

.. autoclass:: LDAPDN
.. automethod:: LDAPDN.__getitem__(idx)
.. automethod:: LDAPDN.__setitem__(idx, value)
.. automethod:: LDAPDN.__eq__(other)
.. automethod:: LDAPDN.__str__
.. autoattribute:: LDAPDN.rdns

:class:`LDAPEntry`
------------------
.. class:: LDAPEntry(dn[, conn])

.. automethod:: LDAPEntry.change_attribute(name, optype, *values)

.. note::
    It is possible to create an inconsistent state that the server will reject. To
    get a clean state use :meth:`LDAPEntry.clear_attribute_changes`.

.. automethod:: LDAPEntry.clear
.. automethod:: LDAPEntry.clear_attribute_changes(name)
.. automethod:: LDAPEntry.delete(timeout=None, recursive=False)
.. automethod:: LDAPEntry.get(key, default=None)
.. automethod:: LDAPEntry.items(exclude_dn=False)
.. automethod:: LDAPEntry.keys(exclude_dn=False)

.. note::
    Be aware when the `exclude_dn` argument of :meth:`LDAPEntry.items`, :meth:`LDAPEntry.keys`
    or :meth:`LDAPEntry.values` is set to `True` you lose the benefits of `dict views`_ and
    get a generator object that will be sensitive of adding and removing items to the entry.

.. automethod:: LDAPEntry.modify(timeout=None)
.. automethod:: LDAPEntry.rename(newdn, timeout=None, delete_old_rdn=True)
.. automethod:: LDAPEntry.update(*args, **kwds)
.. automethod:: LDAPEntry.values(exclude_dn=False)

.. attribute:: LDAPEntry.connection

    The LDAPConnection object of the entry. Needs to be set for any LDAP operations.

.. attribute:: LDAPEntry.dn

    The distinguished name of the entry.
    
    >>> from bonsai import LDAPEntry
    >>> anna = LDAPEntry('cn=anna,ou=nerdherd,dc=bonsai,dc=test')
    >>> anna.dn
    <LDAPDN cn=anna,ou=nerdherd,dc=bonsai,dc=test>
    >>> str(anna.dn)
    'cn=anna,ou=nerdherd,dc=bonsai,dc=test'

.. autoattribute:: LDAPEntry.extended_dn


:class:`LDAPModOp`
------------------

.. autoclass:: LDAPModOp

.. autoattribute:: LDAPModOp.ADD
.. autoattribute:: LDAPModOp.DELETE
.. autoattribute:: LDAPModOp.REPLACE

:class:`LDAPReference`
----------------------

.. autoclass:: LDAPReference(client, references)

.. autoattribute:: LDAPReference.client
.. autoattribute:: LDAPReference.references

:class:`LDAPSearchScope`
------------------------

.. autoclass:: LDAPSearchScope

.. autoattribute:: LDAPSearchScope.BASE
.. autoattribute:: LDAPSearchScope.ONELEVEL
.. autoattribute:: LDAPSearchScope.ONE
.. autoattribute:: LDAPSearchScope.SUBTREE
.. autoattribute:: LDAPSearchScope.SUB

:class:`LDAPURL`
----------------
.. seealso:: 
    
    RFC about **LDAP: Uniform Resource Locator** `RFC4516`_.

.. _RFC4516: http://tools.ietf.org/html/rfc4516

.. autoclass:: LDAPURL(str)

    An example of a valid LDAP URL with port number, base DN, list of 
    attributes and search filter:
    
    >>> from bonsai import LDAPURL
    >>> url = LDAPURL("ldap://localhost:789/ou=nerdherd,dc=bonsai,dc=test?cn,sn,gn?sub?(cn=c*)")
    >>> url
    <LDAPURL ldap://localhost:789/ou=nerdherd,dc=bonsai,dc=test?cn,sn,gn?sub?(cn=c*)>
    >>> url.basedn
    <LDAPDN ou=nerdherd,dc=bonsai,dc=test>
    >>> url.attributes
    ['cn', 'sn', 'gn']

.. automethod:: LDAPURL.get_address

   >>> import bonsai
   >>> url = bonsai.LDAPURL("ldaps://example.com/cn=test,dc=bonsai,dc=test??sub")
   >>> url
   <LDAPURL ldaps://example.com:636/cn=test,dc=bonsai,dc=test??sub>
   >>> url.get_address()
   'ldaps://example.com:636'

.. automethod:: LDAPURL.__str__
.. autoattribute:: LDAPURL.attributes
.. autoattribute:: LDAPURL.basedn
.. autoattribute:: LDAPURL.host
.. autoattribute:: LDAPURL.port
.. autoattribute:: LDAPURL.filter_exp
.. autoattribute:: LDAPURL.scope
.. autoattribute:: LDAPURL.scope_num
.. autoattribute:: LDAPURL.scheme

:class:`LDAPValueList`
----------------------

.. autoclass:: LDAPValueList(items)
.. automethod:: LDAPValueList.__contains__(item)
.. automethod:: LDAPValueList.__delitem__(idx)
.. automethod:: LDAPValueList.__setitem__(idx, value)
.. automethod:: LDAPValueList.__add__(other)
.. automethod:: LDAPValueList.__iadd__(other)
.. automethod:: LDAPValueList.__mul__(value)
.. automethod:: LDAPValueList.append(item)
.. automethod:: LDAPValueList.extend(items)
.. automethod:: LDAPValueList.insert(idx, value)
.. automethod:: LDAPValueList.remove(value)
.. automethod:: LDAPValueList.pop(idx=-1)
.. automethod:: LDAPValueList.clear
.. automethod:: LDAPValueList.copy
.. autoattribute:: LDAPValueList.status

bonsai.asyncio
==============

.. automodule:: bonsai.asyncio


:class:`AIOLDAPConnection`
--------------------------

.. autoclass:: AIOLDAPConnection

.. note::
    The default asyncio event loop is changed with Python 3.8 on Windows to
    `ProactorEventLoop`. Unfortunately, bonsai's asynio connection requires
    the old `SelectorEventLoop`. Make sure to change it back before using
    the module:

    .. code-block:: python

        if sys.platform == 'win32':
            import asyncio
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    Getting ``NotImplementedError`` from the ``add_reader`` method of the
    event loop may indicate that it has not been properly set.

:class:`AIOConnectionPool`
--------------------------

.. autoclass:: AIOConnectionPool

bonsai.gevent
=============

.. automodule:: bonsai.gevent

:class:`GeventLDAPConnection`
-----------------------------

.. autoclass:: bonsai.gevent.GeventLDAPConnection

bonsai.ldif
===========

.. automodule:: bonsai

:class:`LDIFReader`
-------------------

.. autoclass:: LDIFReader(input_file, autoload=True, max_length=76)

Example of reading an LDIF file:

.. code-block:: python

    import bonsai

    with open("./users.ldif") as fileobj:
        reader = bonsai.LDIFReader(fileobj)
        for entry in reader:
            print(entry.dn)

.. autoattribute:: LDIFReader.autoload
.. autoattribute:: LDIFReader.input_file
.. autoattribute:: LDIFReader.resource_handlers

:class:`LDIFWriter`
-------------------

.. autoclass:: LDIFWriter(output_file, max_length=76)
.. automethod:: LDIFWriter.write_entry(entry)

   >>> import bonsai
   >>> output = open("./out.ldif", "w")
   >>> writer = bonsai.LDIFWriter(output)
   >>> entry = bonsai.LDAPEntry("cn=test")
   >>> entry["cn"] = "test"
   >>> writer.write_entry(entry)

.. automethod:: LDIFWriter.write_entries(entries, write_version=True)

   >>> client = bonsai.LDAPClient()
   >>> conn = client.connect()
   >>> res = conn.search("ou=nerdherd,dc=bonsai,dc=test", bonsai.LDAPSearchScope.ONE)
   >>> output = open("./out.ldif", "w")
   >>> writer = bonsai.LDIFWriter(output)
   >>> writer.write_entries(res)

.. automethod:: LDIFWriter.write_changes(entry)
.. autoattribute:: LDIFWriter.output_file

bonsai.pool
===========

:class:`ConnectionPool`
-----------------------

.. autoclass:: bonsai.pool.ConnectionPool

   >>> import bonsai
   >>> from bonsai.pool import ConnectionPool
   >>> client = bonsai.LDAPClient()
   >>> pool = ConnectionPool(client, 1, 2)
   >>> pool.open()
   >>> conn = pool.get()
   >>> conn.whomai()
   'anonymus'
   >>> pool.put(conn)
   >>> pool.close()

.. automethod:: bonsai.pool.ConnectionPool.close
.. automethod:: bonsai.pool.ConnectionPool.get
.. automethod:: bonsai.pool.ConnectionPool.open
.. automethod:: bonsai.pool.ConnectionPool.put
.. automethod:: bonsai.pool.ConnectionPool.spawn

    Example usage:

.. code-block:: python

    import bonsai
    from bonsai.pool import ConnectionPool

    client = bonsai.LDAPClient()
    pool = ConnectionPool(client)
    with pool.spawn() as conn:
        print(conn.whoami())

:class:`ThreadedConnectionPool`
-------------------------------

.. autoclass:: bonsai.pool.ThreadedConnectionPool
.. automethod:: bonsai.pool.ThreadedConnectionPool.get

bonsai.tornado
==============

:class:`TornadoLDAPConnection`
------------------------------

.. autoclass:: bonsai.tornado.TornadoLDAPConnection

_bonsai
=======

:class:`ldapsearchiter`
-----------------------

Helper class for paged search result.

.. method:: ldapsearchiter.acquire_next_page

    Request the next page of result. Returns with the message ID of the search operation.
    This method can only be used if the :attr:`LDAPClient.auto_page_acquire` is `False`.

    :return: an ID of the next search operation.
    :rtype: int.

Errors
======
.. autoclass:: bonsai.LDAPError
.. autoclass:: bonsai.LDIFError
.. autoclass:: bonsai.AffectsMultipleDSA
.. autoclass:: bonsai.AlreadyExists
.. autoclass:: bonsai.AuthenticationError
.. autoclass:: bonsai.AuthMethodNotSupported
.. autoclass:: bonsai.ConnectionError
.. autoclass:: bonsai.ClosedConnection
.. autoclass:: bonsai.InsufficientAccess
.. autoclass:: bonsai.InvalidDN
.. autoclass:: bonsai.InvalidMessageID
.. autoclass:: bonsai.NoSuchAttribute
.. autoclass:: bonsai.NoSuchObjectError
.. autoclass:: bonsai.NotAllowedOnNonleaf
.. autoclass:: bonsai.ObjectClassViolation
.. autoclass:: bonsai.ProtocolError
.. autoclass:: bonsai.SizeLimitError
.. autoclass:: bonsai.TimeoutError
.. autoclass:: bonsai.TypeOrValueExists
.. autoclass:: bonsai.UnwillingToPerform
.. autoclass:: bonsai.PasswordPolicyError()
.. autoclass:: bonsai.AccountLocked()
.. autoclass:: bonsai.ChangeAfterReset()
.. autoclass:: bonsai.InsufficientPasswordQuality()
.. autoclass:: bonsai.MustSupplyOldPassword()
.. autoclass:: bonsai.PasswordExpired()
.. autoclass:: bonsai.PasswordInHistory()
.. autoclass:: bonsai.PasswordModNotAllowed()
.. autoclass:: bonsai.PasswordTooShort()
.. autoclass:: bonsai.PasswordTooYoung()
.. autoclass:: bonsai.pool.PoolError
.. autoclass:: bonsai.pool.ClosedPool
.. autoclass:: bonsai.pool.EmptyPool

Utility functions
=================
.. autofunction:: bonsai.utils.escape_attribute_value(attrval)

    >>> import bonsai
    >>> bonsai.escape_attribute_value(",cn=escaped")
    '\\,cn\\=escaped'

.. autofunction:: bonsai.utils.escape_filter_exp(filter_exp)

    >>> import bonsai
    >>> bonsai.escape_filter_exp("(objectclass=*)")
    '\\28objectclass=\\2A\\29'

.. function:: bonsai.get_tls_impl_name

    Return the identification of the underlying TLS implementation that is used by
    the LDAP library:

    >>> bonsai.get_tls_impl_name()
    "MozNSS"

    The possible return values are: `GnuTLS`, `OpenSSL`, `MozNSS` and `SChannel`.

    :return: A identification of TLS implementation.
    :rtype: str

.. function:: bonsai.get_vendor_info

    Return the vendor's name and the version number of the LDAP library:

    >>> bonsai.get_vendor_info()
    ("OpenLDAP", 20440)

    :return: A tuple of the vendor's name and the library's version.
    :rtype: tuple

.. function:: bonsai.has_krb5_support

    :return: True if the module is built with the optional Kerberos/GSSAPI headers.
    :rtype: bool

.. function:: bonsai.set_connect_async(allow)

    Disable/enable asynchronous connection for the underlying socket, which means
    that the socket is set to be non-blocking when it's enabled. The default setting
    is `False` on every platform. This is an OpenLDAP specific setting (see
    `LDAP_OPT_CONNECT_ASYNC` option in the OpenLDAP documentation for further details).

    :param bool allow: Enabling/disabling async connect mode.

.. warning:: Experience shows that this is a delicate setting. Even with a newer OpenLDAP,
    the TLS library version used by libldap might be unable to handle non-blocking
    sockets correctly.

.. function:: bonsai.set_debug(debug, level=0)

    Set debug mode for the module. Turning it on will provide traceback information
    of C function calls on the standard output.

    If the module uses OpenLDAP, then setting the `level` parameter to a non-zero
    integer will also give additional info about the libldap function calls.

    :param bool debug: Enabling/disabling debug mode.
    :param int level: The debug level (for OpenLDAP only).

.. _dict views: https://docs.python.org/3/library/stdtypes.html#dict-views
