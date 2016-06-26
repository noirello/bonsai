Change Log
==========
[0.8.7] - 2016-06-25
--------------------

Changed
~~~~~~~

-  LDAPDN object to validate with regex instead of splitting to tuples.

Added
~~~~~

-  Optional `recursive` bool parameter for LDAPConnection.delete method to
   remove entities in a subtree recursively.

Fixed
~~~~~

-  Wrong typing for LDAPConnection.search when VLV is set.
-  Py_None return values in C functions.
-  Timeout parameter for operations of Tornado and Asyncio connections.

[0.8.6] - 2016-06-05
--------------------

Changed
~~~~~~~

-  AttributeErrors to Type- and ValueErrors for invalid function parameters.
-  LDAPConnection.delete and LDAPEntry.rename accept LDAPDN as DN parameter. 

Added
~~~~~

-  New SizeLimitError.
-  Some typing info and typing module dependecy for 3.4 and earlier versions.

Fixed
~~~~~

-  Ordered search returning with list (instead of ldapsearchiter).
-  Setting error messages on Unix systems.
-  Timeout for connecting.
-  Setting default ioloop for TornadoLDAPConnection (Thanks to @lilydjwg).

[0.8.5] - 2016-02-23
--------------------

Changed
~~~~~~~

-  Removed LDAPConnection's set_page_size and set_sort_order method.
-  If virtual list view parameters are set for the search, the search
   method will return a tuple of the results and a dictionary of the
   received VLV response LDAP control.
-  Renamed LDAPConnection's async attribute and LDAPClient.connect method's
   async parameter to is_async.
-  Improved Mac OS X support: provide wheel with newer libldap libs.

Added
~~~~~

-  New optional parameters for LDAPConnection's search method to perform
   searches with virtual list view, paged search result and sort order.
-  New module functions: get_vendor_info and get_tls_impl_name.
-  NTLM and GSS-SPNEGO support for MS Windows.
-  Automatic TGT requesting for GSSAPI/GSS-SPNEGO, if the necessary
   credential information is provided. (Available only if optional Kerberos
   headers are installed before building the module.)
-  LDAPSearchScope enumeration for search scopes.

Fixed
~~~~~

-  Parsing result of an extended operation, if it is not supported by the
   server.
-  Binary data handling.
-  LDAPEntry's rename method do not change the entry's DN after failure.

[0.8.1] - 2015-10-27
--------------------

Changed
~~~~~~~

-  Renamed LDAPConnection’s cancel method to abandon.

Added
~~~~~

-  Timeout support for opening an LDAP connection.

Fixed
~~~~~

-  Possible deadlock (by constantly locking from the main thread) during
   initialising an LDAP session on Linux.

[0.8.0] - 2015-10-17
--------------------

Changed
~~~~~~~

-  New module name (from PyLDAP) to avoid confusion with other Python
   LDAP packages.
-  LDAPEntry’s clear and get method are rewritten in Python.
-  Connection settings are accessible via properties of LDAPClient.
-  Moved asyncio related code into a separate class that inherits from
   LDAPConnection.
-  Default async class can be change to other class implementation that
   can work with non-asyncio based approaches (e.g. like Gevent).
-  Names of the objects implemented in C are all lower-cased.

Added
~~~~~

-  Full unicode (UTF-8) support on MS Windows with WinLDAP.
-  LDAPConnection.fileno() method to get the socket descriptor of the
   connection.
-  New methods for LDAPClient to set CA cert, client cert and client
   key.
-  EXTERNAL SASL mechanism for binding.
-  Use of authorization ID during SASL binding.
-  New classes for supporting Gevent and Tornado asynchronous modules.
-  Timeout parameter for LDAP operations.

Fixed
~~~~~

-  Own error codes start from -100 to avoid overlap with OpenLDAP’s and
   WinLDAP’s error codes.
-  New folder structure prevents the interpreter to try to load the
   local files without the built C extension(, if the interpreter is
   started from the module’s root directory).

[0.7.5] - 2015-07-12
--------------------

Changed
~~~~~~~

-  LDAPClient.connect is a coroutine if async param is True. (Issue #1)
-  The binding function on Windows uses ldap\_sasl\_bind instead of the
   deprecated ldap\_bind.
-  The connection procedure (init, set TLS, bind) creates POSIX and
   Windows threads to avoid I/O blocking.
-  Optional error messages are appended to the Python LDAP errors.

Added
~~~~~

-  New open method for LDAPConnection object to build up the connection.
-  New LDAPConnectIter object for initialisation, setting TLS, and
   binding to the server.

Fixed
~~~~~

-  LDAPConnection.whoami() returns ‘anonymous’ after an anonymous bind.
-  After failed connection LDAPClient.connect() returns ConnectionError
   on MS Windows.
