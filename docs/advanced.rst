Advanced Usage
**************

.. module:: bonsai

This document covers some of the more advanced features of Bonsai.

.. _auth-mechs:

Authentication mechanisms
=========================

There are several authentication mechanisms, which can be used with Bonsai. The selected mechanism
with the necessary credentials can be set with the :meth:`LDAPClient.set_credentials` method.

Simple bind
-----------

The simplest way to authenticate with an LDAP server is using the SIMPLE mechanism which requires a
bind DN and a password::

    >>> import bonsai
    >>> client = bonsai.LDAPClient()
    >>> client.set_credentials("SIMPLE", user="cn=user,dc=bonsai,dc=test", password="secret")
    >>> client.connect()
    <bonsai.ldapconnection.LDAPConnection object at 0x7fed62b19828>

.. warning::
    Be aware that during the authentication the password is sent to the server in clear text form.
    It is ill-advised to use simple bind without secure channel (TLS/SSL) in production.

Simple Authentication and Security Layer
----------------------------------------

The OpenLDAP library uses the Simple Authentication and Security Layer (`SASL`_) (while the WinLDAP
uses the similar `SSPI`_) to provide different authentication mechanisms. Of course to use a
certain mechanism it has to be supported both the client and the server. To learn which mechanisms
are accessible from the server, check the root DSE's `supportedSASLMechanisms` value::

    >>> client.get_rootDSE()['supportedSASLMechanisms']
    ['GSS-SPNEGO', 'GSSAPI', 'DIGEST-MD5', 'NTLM']

.. note::
    On Unix systems, make sure that the necessary libraries of the certain mechanism are also
    installed on the client (e.g. `libsasl2-modules-gssapi-mit` or `cyrus-sasl-gssapi` for GSSAPI
    support).

.. _SASL: https://tools.ietf.org/html/rfc4422
.. _SSPI: https://msdn.microsoft.com/en-us/library/windows/desktop/aa380493%28v=vs.85%29.aspx


DIGEST-MD5 and NTLM
^^^^^^^^^^^^^^^^^^^

The DIGEST-MD5 and the NTLM mechanisms are challenge-response based authentications. Nowadays they
are considered as weak security protocols, but still popular ones. An example of using NTLM::

    >>> client.set_credentials("NTLM", "user", "secret")
    >>> client.connect().whoami()
    "dn:cn=user,dc=bonsai,dc=test"

The credentials consist of a username and a password, just like for the simple authentication.
When using DIGEST-MD5 you can also use an authorization ID during the bind to perform operation
under the authority of a different identity afterwards, if the necessary rights are granted for you.
NTLM does not support this functionality.

    >>> client.set_credentials("DIGEST-MD5", "user", "secret", authz_id="u:root")
    >>> client.connect().whoami()
    "dn:cn=admin,dc=bonsai,dc=test"

GSSAPI and GSS-SPNEGO
^^^^^^^^^^^^^^^^^^^^^

GSSAPI uses Kerberos tickets to authenticate to the server. To use GSSAPI or GSS-SPNEGO the client
must be Kerberos-aware, which means the necessary Kerberos tools and libraries have to be
installed, and the proper configuration has to be set. (Typically, the configuration is in the
`/etc/krb5.conf` on a Unix system). GSS-SPNEGO mechanism can negotiate a common authentication
method between server and client.

Basically, to start a GSSAPI authentication a ticket granting ticket (TGT) needs to be already
acquired by the client with the help of the command-line `kinit` tool::

    [noirello@bonsai.test ~]$ kinit admin@BONSAI.TEST
    Password for admin@BONSAI.TEST:

The acquired TGT can be listed with `klist`::

    [noirello@bonsai.test ~]$ klist 
    Ticket cache: FILE:/tmp/krb5cc_1000
    Default principal: admin@BONSAI.TEST

    Valid starting     Expires            Service principal
    22/02/16 22:06:14  23/02/16 08:06:14  krbtgt/BONSAI.TEST@BONSAI.TEST
        renew until 23/02/16 22:06:12

After successfully acquire a TGT, the module can used it for authenticating:

    >>> import bonsai
    >>> client = bonsai.LDAPClient("ldap://bonsai.test")
    >>> client.set_credentials("GSSAPI")
    >>> client.connect().whoami()
    'dn:cn=admin,dc=bonsai,dc=test'

In normal case the passed credentials with the exception of the authorization ID are irrelevant 
-- at least on a Unix system, the underlying SASL library figures it out on its own. The
module's client can only interfere with the authorization ID:

    >>> client.set_credentials("GSSAPI", authz_id="u:chuck")
    >>> client.connect().whoami()
    'dn:cn=chuck,ou=nerdherd,dc=bonsai,dc=test'

But on a Windows system (by default) or if Bonsai is built with the optional Kerberos headers, then
it is possible to requesting a TGT with the module's client if username, password and realm name
are all provided:

    >>> client = bonsai.LDAPClient("ldap://bonsai.test")
    >>> client.set_credentials("GSSAPI", "admin", "secret", "BONSAI.TEST")
    >>> client.connect().whoami()
    'dn:cn=admin,dc=bonsai,dc=test'

It is also possible to use Kerberos keytabs when the module is built with Kerberos support:
    
    >>> client.set_credentials("GSSAPI", user="chuck", realm="BONSAI.TEST", keytab="./user.keytab")
    >>> client.connect().whoami()
    'dn:cn=chuck,ou=nerdherd,dc=bonsai,dc=test'

Please note that the Kerberos realm names are typically uppercase with few exceptions.

.. note::
    Automatic TGT requesting only accessible on Unix systems if the optional Kerberos headers are
    provided during the module's build.
  
EXTERNAL
^^^^^^^^

With EXTERNAL mechanism TLS certifications are used to authenticate the user. In certain cases (e.g
the remote server is an OpenLDAP directory) the EXTERNAL option is presented as an available SASL
mechanism only when the client have built up a TLS connection with the server and already set a
client cert.

    >>> client = bonsai.LDAPClient("ldap://bonsai.test", tls=True)
    >>> client.set_ca_cert_dir('/etc/openldap/certs')
    >>> client.set_ca_cert("RootCACert")
    >>> client.set_client_cert("BonsaiTestUser")
    >>> client.set_client_key("./key.txt")
    >>> client.get_rootDSE()['supportedSASLMechanisms']
    ['GSS-SPNEGO', 'GSSAPI', 'DIGEST-MD5', 'EXTERNAL', 'NTLM']   
    >>> client.set_credentials("EXTERNAL")
    >>> client.connect()
    <bonsai.ldapconnection.LDAPConnection object at 0x7f006ad3d888>

For EXTERNAL mechanism only the authorization ID is used in as credential information.

    >>> client.set_credentials("EXTERNAL", authz_id=u:chuck")
    >>> client.connect()
    >>> client.connect().whoami()
    'dn:cn=chuck,ou=nerdherd,dc=bonsai,dc=test'


The proper way of setting the certifications is depend on the TLS implementation that the LDAP
library uses. Please for more information see :ref:`tls-settings`.

.. _tls-settings:

TLS settings
============

There are two practices to use secure connection:

* Either use the `ldaps://` scheme in the LDAP URL, then the client will use
  the LDAP over SSL protocol (similar to HTTPS).
* Or set the tls parameter of the :class:`LDAPClient` to True, which will
  instruct the client to preform a `StartTLS` operation after connected to the
  LDAP server.

Both practices rely on well-set credentials with the TLS related methods --
:meth:`LDAPClient.set_ca_cert_dir`, :meth:`LDAPClient.set_ca_cert`,
:meth:`LDAPClient.set_client_cert` and :meth:`LDAPClient.set_client_key`.

These are expecting different inputs depending on which TLS library is used by
the LDAP library. To find out which TLS library is used call
:func:`bonsai.get_tls_impl_name`.

.. rubric:: GnuTLS and OpenSSL

For GnuTLS and OpenSSL the :meth:`LDAPClient.set_ca_cert` and :meth:`LDAPClient.set_client_cert`
are expecting file paths that link to certification files in PEM-format.

The :meth:`LDAPClient.set_ca_cert_dir` works only for OpenSSL if the content of provided
directory is symbolic links of certifications that are generated by the `c_rehash` utility.

.. rubric:: Mozilla NSS

When using Mozilla NSS the input of :meth:`LDAPClient.set_ca_cert_dir` is the path of the directory
containing the NSS certificate database (that is created with the `certutil` command).

The :meth:`LDAPClient.set_ca_cert` and :meth:`LDAPClient.set_client_cert` can be used to select the
certificate with their names in the certificate database.

If the client certificate is password protected, then the input of
:meth:`LDAPClient.set_client_key` should be a path to the file that contains the password in clear
text format.

.. rubric:: Microsoft Schannel

Unfortunately, none of the listed TLS modules are effective on Microsoft Windows. The WinLDAP
library automatically searches for the corresponding certificates in the cert store. All of the
necessary certificates have to be loaded manually before the client tries to use them. 

.. _ldap-controls:

LDAP controls
=============

Several LDAP controls can be used to extend and improve the basic LDAP operations. Bonsai is
supporting the following controls. Always check (the root DSE's `supportedControls`) that the
server also supports the selected control.  

Server side sort
----------------

Using the server side sort control the result of the search is ordered based on the selected
attributes. To invoke the control simply set the `sort_order` parameter of the
:meth:`LDAPConnection.search` method:

    >>> conn = client.connect()
    >>> conn.search("ou=nerdherd,dc=bonsai,dc=test", 2, sort_order=["-cn", "gn"])

Attributes that start with `-` are used for descending order.

.. warning::
    Even if the server side sort control is supported by the server there is no guarantee that the
    results will be sorted for multiple attributes.

.. note::
    The OID of server side sort control is: 1.2.840.113556.1.4.473.

Paged search result
-------------------

Paged search can be used to reduce large search result into smaller pages. Page result can be used
with the :meth:`LDAPConnection.paged_search` method and the size of the page can be set with the
`page_size` parameter:
    
    >>> conn = client.connect()
    >>> conn.paged_search("ou=nerdherd,dc=bonsai,dc=test", 2, page_size=3)
    <_bonsai.ldapsearchiter object at 0x7f006ad455d0>

Please note that the return value of :meth:`LDAPConnection.paged_search` is an :class:`ldapsearchiter`.
This object can be iterated over the entries of the page. By default the next page of results is
acquired automatically during the iteration. This behaviour can be changed by setting the 
:attr:`LDAPClient.auto_page_acquire` to `False` and using the :meth:`ldapsearchiter.acquire_next_page`
method which explicitly initiates a new search request to get the next page.

.. warning::
    Avoid using server-side referral chasing with paged search. It's likely to fail with invalid
    cookie error.

.. note::
    The OID of paged search control is: 1.2.840.113556.1.4.319.

Virtual list view
-----------------

Virtual list view (VLV) is also for reducing large search result, but with a more specific manner.
Virtual list view mimics the scrolling view of an application: it can select a target entry of a 
large list (ordered search result) with an offset or an attribute value and receiving only a
given number of entries before and after it as a partial result of the entire search.

The :meth:`LDAPConnection.virtual_list_search` method's `offset` or `attrvalue` can be used to select
the target, the `before_count` and `after_count` for specifying the number of entries before and after
the target.

Also need to set the `est_list_count` parameter: the estimated size of the entire list by the
client. The server will adjust the position of the target entry based on the real list size,
estimated size and the offset.  

Virtual list view control cannot be used without a server side sort control thus a sort order
always has to be set.

    >>> conn.virtual_list_search("ou=nerdherd,dc=bonsai,dc=test", 2, attrlist=['cn', 'uidNumber'], sort_order=['-uidNumber'], offset=4, before_count=1, after_count=1, est_list_count=6)
    ([{'dn': <LDAPDN cn=sam,ou=nerdherd,dc=bonsai,dc=test>, 'cn': ['sam'], 'uidNumber': [4]},
    {'dn': <LDAPDN cn=skip,ou=nerdherd,dc=bonsai,dc=test>, 'cn': ['skip'], 'uidNumber': [3]},
    {'dn': <LDAPDN cn=jeff,ou=nerdherd,dc=bonsai,dc=test>, 'cn': ['jeff'], 'uidNumber': [2]}],
    {'oid': '2.16.840.1.113730.3.4.10', 'target_position': 4, 'list_count': 7})

The return value of the search is a tuple of a list and a dictionary. The dictionary contains
the VLV server response: the target position and the real list size.

.. note::
    The OID of virtual list view control is: 2.16.840.1.113730.3.4.9.

Password policy
---------------

Password policy defines a set of rules about accounts and modification of passwords. It allows
for the system administrator to set expiration time for passwords and a maximal number of failed
login attempts before the account become locked. Is also specifies rules about the quality of
password.

Enabling the password policy control with :meth:`LDAPClient.set_password_policy` method, the client
can receive additional information during connecting to a server or modifying a user's password.
Setting this control will change the return value of :meth:`LDAPClient.connect` and
:meth:`LDAPConnection.open` to a tuple of :class:`LDAPConnection` and a dictionary that contains
the remaining seconds until the password's expiration and the remaining grace logins. The client
can also receive new exceptions related to password modifications.

    >>> import bonsai
    >>> client = bonsai.LDAPClient()
    >>> client.set_credentials("SIMPLE", "cn=user,dc=bonsai,dc=test", "secret")
    >>> client.set_password_policy(True)
    >>> conn, ctrl = client.connect()
    >>> conn
    <bonsai.ldapconnection.LDAPConnection object at 0x7fa552ab4e28>
    >>> ctrl
    {'grace': 1, 'expire': 3612, 'oid': '1.3.6.1.4.1.42.2.27.8.5.1'})

If the server does not support password policy control or the given credentials does not have
policies (like anonymous or administrator user) the second item in the tuple will be `None`.

.. note::
    Because the password policy is not standardized, it is not listed by the server among
    the `supportedControls` even if it is available.

.. note::
    Password policy control cannot be used on MS Windows with WinLDAP. In this case after 
    opening a connection the control dictionary will always be `None`.

Extended DN
-----------

Setting LDAP_SERVER_EXTENDED_DN control with :meth:`LDAPClient.set_extended_dn` will extend the
standard DN format with the SID and GUID attributes to `<GUID=xxxxxxxx>;<SID=yyyyyyyyy>;distinguishedName`
during the LDAP search. The method's parameter can be either 0 which means that the GUID and SID
strings will be in a hexadecimal string format or 1 for receiving the extended dn in a standard
string format. This control is only supported by Microsoft's Active Directory.

Regardless of setting the control, the :attr:`LDAPEntry.dn` still remains a simple :class:`LDAPDN`
object without the SID or GUID extensions. The extended DN will be set to the :attr:`LDAPEntry.extended_dn`
as a string. The extended DN control also affects other LDAP attributes that use distinguished names
(e.g. `memberOf` attribute).

    >>> client = bonsai.LDAPClient()
    >>> client.set_extended_dn(1)
    >>> result = conn.search("ou=nerdherd,dc=bonsai,dc=test", 1)
    >>> result[0].extended_dn
    <GUID=899e4e01-e88d-4dea-ba64-119ed386b61c>;<SID=S-1-5-21-101232111302-1767724339-724445543-12345>;cn=chuck,ou=nerdherd,dc=bonsai,dc=test
    >>> result[0].dn
    <LDAPDN cn=chuck,ou=nerdherd,dc=bonsai,dc=test>

.. note::
    The OID of extended DN control is: 1.2.840.113556.1.4.529.

Server tree delete
------------------

Server tree delete control allows the client to remove entire subtree with a single request if
the user has appropriate permissions to remove every corresponding entry. Setting the `recursive` 
parameter of :meth:`LDAPConnection.delete` and :meth:`LDAPEntry.delete` to `True` will send 
the control with the delete request automatically, no further settings are required.

.. note::
    The OID of server tree delete control is: 1.2.840.113556.1.4.805

ManageDsaIT
-----------

The ManageDsaIT control can be used to work with LDAP referrals as simple LDAP entries. After
setting it with the :meth:`LDAPClient.set_managedsait` method, the referrals can be added
removed, and modified just like entries.

    >>> client = bonsai.LDAPClient()
    >>> client.set_managedsait(True)
    >>> conn = client.connect()
    >>> ref = conn.search("o=admin-ref,ou=nerdherd,dc=bonsai,dc=test", 0)[0]
    >>> ref
    {'dn': <LDAPDN o=admin-ref,ou=nerdherd,dc=bonsai,dc=test>, 'objectClass': ['referral',
    'extensibleObject'], 'o': ['admin-ref']}
    >>> type(ref)
    <class 'bonsai.ldapentry.LDAPEntry'>

.. note::
    The OID of ManageDsaIT control is: 2.16.840.1.113730.3.4.2

Using connection pools
======================

When your application requires to use multiple open LDAP connections, Bonsai
provides you connection pools to help you creating and accessing them. This way
you can acquire an opened connection, do some operations and put it back into
the pool for other threads/tasks to use.

.. code-block:: python3

    import bonsai
    import threading
    from bonsai.pool import ThreadedConnectionPool

    def work(pool):
        with pool.spawn() as conn:
            print(conn.whoami())
            # Some other operations...

    client = bonsai.LDAPClient()
    pool = ThreadedConnectionPool(client, minconn=5, maxconn=10)
    thr = threading.Thread(target=work, args=(pool,))
    thr.start()
    conn = pool.get()
    res = conn.search()
    # After finishing up...
    pool.put(conn)



Reading and writing LDIF files
==============================

Bonsai has a limited support to read and write LDIF files. LDIF (LDAP Data Interchange Format)
is a plain text file format for representing LDAP changes and updates. It can be used to exchange
data between directory servers.

To read an LDIF file, simply open the file in read-mode, pass it to the :class:`LDIFReader`,
then the reader object can be used as an iterator to get the entries from the LDIF file.

.. code-block:: python3

    from bonsai import LDIFReader

    with open("users.ldif", "r") as data:
        reader = LDIFReader(data)
        for ent in reader:
            print(ent)


Writing LDIF files is similar. The :class:`LDIFWriter` needs an open file-object in write-mode,
and the :meth:`LDIFWriter.write_entry` expects an :class:`LDAPEntry` object whose attributes will be
serialised. It also possible to serialise the changes of an entry with :meth:`LDIFWriter.write_changes`.

.. code-block:: python3

    from bonsai import LDAPClient
    from bonsai import LDIFWriter

    client = LDAPClient("ldap://bonsai.test")
    with client.connect() as conn:
        res = conn.search("cn=jeff,ou=nerdherd,dc=bonsai,dc=test", 0)
        with open("user.ldif", "w") as data:
            writer = LDIFWriter(data)
            writer.write_entry(res[0])
        # Make some changes on the entry.
        res[0]["mail"].append("jeff_secondary@mail.test")
        res[0]["homeDirectory"] = "/opt/jeff"
        with open("changes.ldif", "w") as data:
            writer = LDIFWriter(data)
            writer.write_changes(res[0])

.. note::

    As mentioned above :class:`LDIFReader` and :class:`LDIFWriter` have their limitations. They
    can handle basic attribute changes (adding, modifying and removing), serialising attributes,
    but they're not capable to cope with deleting and renaming entries, or processing LDAP controls
    that are presented in the LDIF file.

Asynchronous operations
=======================

Asynchronous operations are first-class citizens in the underlying C API that Bonsai is built on.
That makes relatively easy to integrate the module with popular Python async libraries. Bonsai is
shipped with support to some: `asyncio`_, `gevent`_, and `Tornado`_.

.. _asyncio: https://docs.python.org/3/library/asyncio.html
.. _gevent: http://www.gevent.org/
.. _Tornado: http://www.tornadoweb.org/en/stable/

Using async out-of-the-box
--------------------------

To start asynchronous operations set the :meth:`LDAPClient.connect` method's `is_async` parameter
to True. By default the returned connection object can be used with Python's `asyncio` library.
For further details about how to use `asyncio` see the `official documentation`_.

.. _official documentation: https://docs.python.org/3/library/asyncio.html

An example for asynchronous search and modify with `asyncio`:

.. code-block:: python3

    import asyncio
    import bonsai

    async def do():
        cli = bonsai.LDAPClient("ldap://localhost")
        async with cli.connect(is_async=True) as conn:
            results = await conn.search("ou=nerdherd,dc=bonsai,dc=test", 1)
            for res in results:
                print(res['givenName'][0])
            search = await conn.search("cn=chuck,ou=nerdherd,dc=bonsai,dc=test", 0)
            entry = search[0]
            entry['mail'] = "chuck@nerdherd.com"
            await entry.modify()

    loop = asyncio.get_event_loop()
    loop.run_until_complete(do())

To work with other non-blocking I/O modules the default asynchronous class has to be set to a
different one with :meth:`LDAPClient.set_async_connection_class`.

For example changing it to `GeventLDAPConnection` makes it possible to use the module with
gevent:

.. code-block:: python

    import gevent

    import bonsai
    from bonsai.gevent import GeventLDAPConnection

    def do():
        cli = bonsai.LDAPClient("ldap://localhost")
        # Change the default async conn class.
        cli.set_async_connection_class(GeventLDAPConnection)
        with cli.connect(True) as conn:
            results = conn.search("ou=nerdherd,dc=bonsai,dc=test", 1)
            for res in results:
                print(res['givenName'][0])
            search = conn.search("cn=chuck,ou=nerdherd,dc=bonsai,dc=test", 0)
            entry = search[0]
            entry['mail'] = "chuck@nerdherd.com"
            entry.modify()

    gevent.joinall([gevent.spawn(do)])

.. note::
    Since 1.2.1, to achieve non-blocking socket connection, the `bonsai.set_connect_async(True)`
    has to be called before connecting the server. But setting it and using TLS can cause errors
    even on newer Ubuntu releases (18.04+), thus it has been turned off by default on every
    platform.

Create your own async class
---------------------------

If you would like to use an asynchronous library that is currently not supported by Bonsai,
then you have to work a little bit more to make it possible. The following example will help
you to achieve that by showing how to create a new async class for `Curio`_. Inspecting the
implementations of the supported libraries can also help.

.. warning::
    This class is just for education purposes, the implementation is made after just scraping the
    surface of Curio. It's far from perfect and not meant to use in production.

The C API's asynchronous functions are designed to return a message ID immediately after calling
them, and then polling the state of the executed operations. The `BaseLDAPConnection` class exposes
the same functionality of the C API. Therefore it makes possible to start an operation then poll
the result with :meth:`LDAPConnection.get_result()` periodically in the `_evaluate` method which
happens to be called in every other method that evaluates an LDAP operation.

.. code-block:: python3

    from typing import Optional
    import bonsai
    import curio

    from bonsai.ldapconnection import BaseLDAPConnection

    # You have to inherit from BaseLDAPConnection.
    class CurioLDAPConnection(BaseLDAPConnection):
        def __init__(self, client: "LDAPClient"):
            super().__init__(client, is_async=True)

        async def _evaluate(self, msg_id: int, timeout: Optional[float] = None):
            while True:
                res = self.get_result(msg_id)
                if res is not None:
                    return res
                await curio.sleep(1)

The constant polling can be avoided with voluntarily sleep, but it's more efficient to register to an
I/O event that will notify when the data is available. The :meth:`LDAPConnection.fileno()` method
returns the socket's file descriptor that can be used with the OS's default I/O monitoring function
(e.g select or epoll) for this purpose. In Curio you can wait until a socket becomes writable with
`curio.traps._write_wait`:

.. code-block:: python3

        async def _evaluate(self, msg_id: int, timeout: Optional[float] = None):
            while True:
                await curio.traps._write_wait(self.fileno())
                res = self.get_result(msg_id)
                if res is not None:
                    return res


The following code is a simple litmus test for proving that the created class plays nice with other
coroutines:

.. code-block:: python3

    async def countdown(n):
        while n > 0:
            print(f"T-minus {n}")
            await curio.sleep(1)
            n -= 1

    async def search():
        cli = bonsai.LDAPClient()
        cli.set_async_connection_class(CurioLDAPConnection)
        conn = await cli.connect(is_async=True)
        res = await conn.search("ou=nerdherd,dc=bonsai,dc=test", 1)
        for ent in res:
            print(ent.dn)

    async def tasks():
        tsk1 = await curio.spawn(countdown, 20)
        tsk2 = await curio.spawn(search)
        await tsk1.join()
        await tsk2.join()

    if __name__ == "__main__":
        curio.run(tasks)

This example class has the minimal functionalities only but hopefully gives you the basic idea how
the asynchronous integration works.

.. _Curio: https://curio.readthedocs.io/en/latest/
