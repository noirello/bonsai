API documentation
*****************

.. automodule:: bonsai

:class:`LDAPClient`
===================
.. autoclass:: LDAPClient
.. automethod:: LDAPClient.connect
.. automethod:: LDAPClient.get_rootDSE

    An example of getting the root DSE:
    
    >>> client = bonsai.LDAPClient()
    >>> client.get_rootDSE()
    {'namingContexts': ['dc=bonsai,dc=test'], 'supportedControl': ['2.16.840.1.113730.3.4.18',
    '2.16.840.1.113730.3.4.2', '1.3.6.1.4.1.4203.1.10.1', '1.2.840.113556.1.4.319',
    '1.2.826.0.1.3344810.2.3', '1.3.6.1.1.13.2', '1.3.6.1.1.13.1', '1.3.6.1.1.12'],
    'supportedLDAPVersion': ['3'], 'supportedExtension': ['1.3.6.1.4.1.1466.20037',
    '1.3.6.1.4.1.4203.1.11.1', '1.3.6.1.4.1.4203.1.11.3', '1.3.6.1.1.8'],
    'supportedSASLMechanisms': ['DIGEST-MD5', 'NTLM', 'CRAM-MD5']}

.. automethod:: LDAPClient.set_credentials
    
    >>> from bonsai import LDAPClient
    >>> client = LDAPClient()
    >>> client.set_credentials("SIMPLE", ("cn=user,dc=bonsai,dc=test", "secret"))
    >>> client.connect()
    <bonsai.LDAPConnection object at 0x7fadf8976440>
    >>> client.set_credentials("DIGEST-MD5", ("user", "secret", None, None))
    >>> client.connect()
    <bonsai.LDAPConnection object at 0x7fadf892d3a0>

.. automethod:: LDAPClient.set_cert_policy
.. automethod:: LDAPClient.set_ca_cert
.. automethod:: LDAPClient.set_ca_cert_dir
.. automethod:: LDAPClient.set_client_cert
.. automethod:: LDAPClient.set_client_key
.. automethod:: LDAPClient.set_async_connection_class

    An example to change the default async connection class to a Gevent-based one:

    >>> import bonsai
    >>> from bonsai.gevent import GeventLDAPConnection
    >>> client = bonsai.LDAPClient()
    >>> client.set_async_connection_class(GeventLDAPConnection)
    >>> client.connect(True)
    <bonsai.gevent.geventconnection.GeventLDAPConnection object at 0x7f9b1789c6d8>

.. automethod:: LDAPClient.set_raw_attributes

    An example:
    
    >>> client = bonsai.LDAPClient()
    >>> client.set_raw_attributes(["cn", "sn"])
    >>> conn = client.connect()
    >>> conn.search("cn=jeff,ou=nerdherd,dc=bonsai,dc=test", 0, attrlist=['cn', 'sn', 'gn'])
    [{'givenName': ['Jeff'], 'sn': [b'Barnes'], 'cn': [b'jeff']}]

.. autoattribute:: LDAPClient.cert_policy
.. autoattribute:: LDAPClient.ca_cert
.. autoattribute:: LDAPClient.ca_cert_dir
.. autoattribute:: LDAPClient.client_cert
.. autoattribute:: LDAPClient.client_key
.. autoattribute:: LDAPClient.credentials
.. autoattribute:: LDAPClient.mechanism
.. autoattribute:: LDAPClient.raw_attributes
.. autoattribute:: LDAPClient.tls
.. autoattribute:: LDAPClient.url


:class:`LDAPConnection`
=======================
.. autoclass:: LDAPConnection

.. method:: LDAPConnection.abandon(msg_id)

    Abandon an ongoing asynchronous operation associated with the given message id.
    Note that there is no guarantee that the LDAP server will be able to honor the request, which
    means the operation could be performed anyway. Nevertheless, it is a good programming paradigm
    to abandon unwanted operations (e.g after a timeout is exceeded).

    :param int msg_id: the ID of an ongoing LDAP operation.

.. automethod:: LDAPConnection.add

.. method:: LDAPConnection.close()

    Close LDAP connection.
    
.. automethod:: LDAPConnection.delete

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

.. automethod:: LDAPConnection.open

.. method:: LDAPConnection.search(base=None, scope=None, filter=None, \
            attrlist=None, timeout=None, sizelimit=0, attrsonly=False, \
            sort_order=None, page_size=0, offset=0, before_count=0, \
            after_count=0, est_list_count=0, attrvalue=None)

    :param str base: the base DN of the search.
    :param int scope: the scope of the search. An :class:`LDAPSearchScope` also can be used as
                      value.
    :param str filter: string to filter the search in LDAP search filter syntax.
    :param list attrlist: list of attribute's names to receive only those attributes from the
                          directory server.
    :param float timeout: time limit in seconds for the search.
    :param int sizelimit: the number of entries to limit the search.
    :param bool attrsonly: if it's set True, search result will contain only the name of the
                           attributes without their values.
    :param list sort_order: list of attribute's names to use for server-side ordering, start name
                            with '-' for descending order.
    :param int page_size: the number of entries on a page for paged search result.
    :param int offset: an offset of the search result to select a target entry for virtual list
                       view (VLV).
    :param int before_count: the number of entries before the target entry for VLV.
    :param int after_count: the number of entries after the target entry for VLV.
    :param int est_list_count: the estimated content count of the entire list for VLV.
    :param attrvalue: an attribute value (of the attribute that is used for sorting) for
                      identifying the target entry for VLV.
    :return: the search result.
    :rtype: list, ldapsearchiter or (list, dict) tuple.
   
    Perform a search on the directory server. A base DN and a search scope is always necessary to
    perform a search, but these values - along with the attribute's list and search filter - can
    also be set with the :class:`LDAPClient` LDAP URL parameter. The parameters, which are passed
    to the :meth:`LDAPConnection.search` method will overrule the previously set ones with the
    LDAP URL.
   
   >>> from bonsai import LDAPClient
   >>> client = LDAPClient("ldap://localhost") # without additional parameters
   >>> conn = client.connect()
   >>> conn.search("ou=nerdherd,dc=bonsai,dc=test", 1, "(cn=ch*)", ["cn", "sn", "gn"])
   [{'sn': ['Bartowski'], 'cn': ['chuck'], 'givenName': ['Chuck']}]
   >>> client = LDAPClient("ldap://localhost/ou=nerdherd,dc=bonsai,dc=test?cn,sn,gn?one?(cn=ch*)") # with additional parameters
   >>> conn = client.connect()
   >>> conn.search()
   [{'sn': ['Bartowski'], 'cn': ['chuck'], 'givenName': ['Chuck']}]
   >>> conn.search(filter="(cn=j*)")
   [{'sn': ['Barnes'], 'cn': ['jeff'], 'givenName': ['Jeff']}]
   
    Depending which optional parameters are set additional LDAP controls are appended to the search
    request. These controls will change the behaviour of the :meth:`LDAPConnection.search` method:

        - setting `sort_order` will invoke server side sorting, based on the provided attribute
          list.
        - `page_size` will invoke paged search result and the method will return with an
          :class:`ldapsearchiter` instead of a list.
        - setting `offset` or `attrvalue` with `sort_order` will invoke virtual list view and the
          method will return with a tuple of (list, dict) where the list contains the result of the
          search and the dict contains the LDAP VLV response control from the server.
   
    The method raises :class:`bonsai.UnwillingToPerform` if an `offset` or `attrvalue` is set
    without `sort_order`, or if an `offset` or `attrvalue` is set along with `page_size`.

    For further details using these controls please see :ref:`ldap-controls`.

.. automethod:: LDAPConnection.whoami
.. seealso::
    RFC about the LDAP Who am I extended operation `RFC4532`_.
    
.. _RFC4532: https://tools.ietf.org/html/rfc4532

.. attribute:: LDAPConnection.closed

    A readonly attribute about the connection's state.

.. attribute:: LDAPConnection.is_async

    A readonly attribute to define that the connections is asynchronous.

:class:`LDAPDN`
===============

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
.. automethod:: LDAPDN.__getitem__
.. automethod:: LDAPDN.__setitem__
.. automethod:: LDAPDN.__eq__
.. automethod:: LDAPDN.__str__
.. autoattribute:: LDAPDN.rdns

:class:`LDAPEntry`
==================
.. class:: LDAPEntry(dn[, conn])
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

.. automethod:: LDAPEntry.delete
.. automethod:: LDAPEntry.modify
.. automethod:: LDAPEntry.rename
.. automethod:: LDAPEntry.update

:class:`LDAPSearchScope`
========================

.. autoclass:: LDAPSearchScope

.. autoattribute:: LDAPSearchScope.BASE
.. autoattribute:: LDAPSearchScope.ONELEVEL
.. autoattribute:: LDAPSearchScope.ONE
.. autoattribute:: LDAPSearchScope.SUBTREE
.. autoattribute:: LDAPSearchScope.SUB

:class:`LDAPURL`
================
.. seealso:: 
    
    RFC about **LDAP: Uniform Resource Locator** `RFC4516`_.

.. _RFC4516: http://tools.ietf.org/html/rfc4516

.. autoclass:: LDAPURL

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
.. autoattribute:: LDAPURL.filter
.. autoattribute:: LDAPURL.scope
.. autoattribute:: LDAPURL.scope_num
.. autoattribute:: LDAPURL.scheme

:class:`ldapsearchiter`
=======================

    Helper class for paged search result.

.. method:: ldapsearchiter.acquire_next_page

    Request the next page of result. Returns with the message ID of the search operation.

    :return: an ID of the next search operation.
    :rtype: int.

Errors
======
.. autoclass:: bonsai.LDAPError
.. autoclass:: bonsai.AffectsMultipleDSA
.. autoclass:: bonsai.AlreadyExists
.. autoclass:: bonsai.AuthenticationError
.. autoclass:: bonsai.AuthMethodNotSupported
.. autoclass:: bonsai.ConnectionError
.. autoclass:: bonsai.ClosedConnection
.. autoclass:: bonsai.InsufficientAccess
.. autoclass:: bonsai.InvalidDN
.. autoclass:: bonsai.InvalidMessageID
.. autoclass:: bonsai.NoSuchObjectError
.. autoclass:: bonsai.ObjectClassViolation
.. autoclass:: bonsai.ProtocolError
.. autoclass:: bonsai.TimeoutError
.. autoclass:: bonsai.UnwillingToPerform

Module functions
================

.. function:: bonsai.get_tls_impl_name

    Return the identification of the underlying TLS implementation that is used by
    the LDAP library:

    >>> bonsai.get_tls_impl_name()
    "MozNSS"

    The possible return values are: `GnuTLS`, `OpenSSL`, `MozNSS` and `Schannel`.

    :return: A identification of TLS implementation.
    :rtype: str

.. function:: bonsai.get_vendor_info

    Return the vendor's name and the version number of the LDAP library:

    >>> bonsai.get_vendor_info()
    ("OpenLDAP", 20440)

    :return: A tuple of the vendor's name and the library's version.
    :rtype: tuple

.. function:: bonsai.has_krb5_support

    :return: True if the module is build with the optional Kerberos/GSSAPI headers.
    :rtype: bool
