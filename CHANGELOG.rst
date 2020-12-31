Changelog
==========
[1.2.1 - 2020-12-31]
--------------------

Changed
~~~~~~~

-  Asynchronous connection process during socket initialisation is disabled
   by default on every platform. It caused TLS errors on newer Ubuntus (18.04+).
   Use set_connect_async explicitly to enable it.
-  LDAPClient's server_chase_referrals is set to False automatically before
   starting a paged_search.
-  Using urllib.parse for LDAPURL, instead of regular expressions.

Fixed
~~~~~

-  Freeing resources allocated by the LDAP structure during LDAPConnection's
   deallocation. (Issue #45)
-  Package name in documentation. (Thanks to @ikreb7)


[1.2.0] - 2020-01-18
--------------------

Added
~~~~~

-  The get_result coroutines to AIOLDAPConnection and TornadoLDAPConnection.
-  LDAPI example to docs. (Thanks to @senfomat)

Fixed
~~~~~

-  Raising ConnectionError instead of ValueError of invalid file descriptor
   with AIOLDAPConnection when the server is unreachable. (Issue #27)
-  Raising SizeLimitError when the query hits either the client-side or the
   server-side limit, fix condition check when acquiring next page. (Issue #31)
-  Race condition for open method of ThreadedConnectionPool and AIOConnectionPool.

[1.1.0] - 2019-04-06
--------------------

Changed
~~~~~~~
-  Drop support for Python 3.4. From further releases 3.4 related codes will
   be removed (some asyncio related code has already changed), and the module
   will require 3.5 or newer Python to be built.
-  Add gevent and tornado as extra requirements for setup.py.

Added
~~~~~

-  New set_connect_async function to disable/enable asynchronous connection
   process during socket initialisation. (Thanks to @tck42)
-  New connection pool classes: simple ConnectionPool, ThreadedConnectionPool
   that can be shared between threads and AIOConnectionPool for asyncio tasks.

Fixed
~~~~~

-  Defining PY_SSIZE_T_CLEAN and changing parameter size variables from int to
   Py_ssize_t for Python 3.8.

[1.0.0] - 2018-09-09
--------------------

Changed
~~~~~~~

-  Separate basic search functionality to three different methods in
   LDAPConnection: search, paged_search and virtual_list_search.
-  LDAPEntry's DN is listed among its attributes under the dn key.
-  LDAPClient's set_credentials method uses optional named parameters instead
   of tuples.
-  LDAPClient's credentials property returns a dict instead of a tuple.
-  LDAPURL's filter property and the filter parameters of LDAPConnection's
   search methods are renamed to filter_exp.
-  The representation of LDAPEntry honours the last call of its
   change_attribute method better than previously.
-  Drop Heimdal support for advanced Kerberos capabilities (at least
   temporarily).
-  The get_tls_impl_name, get_vendor_info, has_krb5_support, and set_debug
   functions are moved to the utils submodule.

Added
~~~~~

-  LDIFReader and LDIFWriter objects for handling LDIF format.
-  The delete_old_rdn parameter for LDAPEntry's rename method. (Issue #17)
-  Kerberos keytab support for set_credentials (Thanks to @Mirraz).
-  Utils submodule with escape_filter_exp and escape_attribute_value
   functions. (Issue #18)
-  An exclude_dn keyword-only argument to LDAPEntry's keys, items and
   values methods to exclude the dn key and value from the return values.
-  Support for ldapi connection in LDAPURL and LDAPConnection.
-  BaseLDAPConnection as a super class for all connection classes.
-  Type annotations for several methods.

Fixed
~~~~~

-  Several reference counting errors that caused memory leaks. (Issue #19)
-  Escaping brackets in LDAPURL's regular expressions. (Issue #22)
-  Missing ManageDsaIT control during LDAPConnection's delete.
-  Honouring timeout settings for network connections, but only on
   Linux with newer OpenLDAP than 2.4.43. (Issue #21)
-  Typo in documentation (Thanks to @magnuswatn).

[0.9.1] - 2017-12-03
--------------------

Changed
~~~~~~~

-  LDAPError messages have the original LDAP error codes.
-  TLS initialisation is separated from LDAP struct initialisation.

Added
~~~~~

-  Async with support for AIOLDAPConnection. (Issue #12)
-  New set_debug module function that enables debug mode.

Fixed
~~~~~

-  Signalling after LDAP initialisation is failed.
-  Using TLS settings while getting the root DSE in get_rootDSE method.

[0.9.0] - 2017-02-15
--------------------

Changed
~~~~~~~

-  Python 3.3 is no longer considered to be supported. The package won't be
   tested with 3.3 anymore.
-  The LDAPSearchIter object is automatically acquiring the next page during
   iteration for paged LDAP search by default.
-  Installing the package from source on Mac OS X became simpler with
   setup.cfg (Thanks to @LukeXuan).
-  When recursive is True, LDAPConnection.delete uses LDAP_SERVER_TREE_DELETE
   control (if it is possible).
-  LDAPClient.url property became writeable.

Added
~~~~~

-  LDAPClient.set_auto_page_acquire and auto_page_acquire property for
   enabling/disabling automatic page acquiring during paged LDAP search.
-  LDAPEntry.change_attribute and LDAPEntry.clear_attribute_changes methods
   for handling LDAP attributes with explicit modification operation types.
-  Async iterator (async for) support for LDAPSearchIter.
-  LDAPClient.server_chase_referrals property to set chasing LDAP referrals
   by the server.
-  LDAPReference object for handling LDAP referrals.
-  LDAPURL.__eq__ method to check LDAPURL objects and string equality.
-  LDAPClient.set_url method to set url attribute.
-  LDAPClient.set_managedsait method to support LDAP ManageDsaIT control
   during search, add and modify operations.

Fixed
~~~~~

-  The value validation of LDAPDN's __setitem__ method.
-  The missing asyncio.coroutine decorators of AIOLDAPConnection's methods.
-  IPv6 parsing for LDAPURL.

[0.8.9] - 2016-11-19
--------------------

Changed
~~~~~~~

-  Reimplemented LDAPValueList in Python, removed C implementations of
   ldapvaluelist and uniquelist.
-  Reimplemented LDAPEntry.delete method in Python.
-  LDAPConnection.search method to accept bytes-like object as a filter
   parameter. (Issue #7)
-  LDAPClient.get_rootDSE method uses anonym bind without any previously set
   LDAP controls to search for rootDSE.

Added
~~~~~

-  LDAP_EXTENDED_DN_CONTROL support with LDAPClient.set_extended_dn method
   and LDAPEntry's new extended_dn string attribute. (Issue #6)

Fixed
~~~~~

-  Case sensitivity when checking LDAPDN equality.

[0.8.8] - 2016-07-19
--------------------

Changed
~~~~~~~

-  LDAPDN object is loaded for the C extension after initialisation once,
   rather than loading it for every time when an LDAPEntry's DN is set.

Added
~~~~~

-  Password policy control support with LDAPClient.set_password_policy on
   Unix.
-  New exceptions for password policy errors.
-  LDAP Password Modify extended operation support with
   LDAPConnection.modify_password.

Fixed
~~~~~

-  AIOLDAPConnection hanging on write events during selecting socket
   descriptors.

[0.8.7] - 2016-06-27
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
-  Some typing info and typing module dependency for 3.4 and earlier versions.

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

[0.7.0] - 2015-01-28
--------------------

Changed
~~~~~~~

-  The set_page_size method is moved from LDAPClient to LDAPConnection.

Added
~~~~~

-  Support for asynchronous LDAP operations.
-  Cancel method for LDAPConnection.
-  New LDAPEntry and LDAPConnection Python objects as wrappers around the
   C implementations.

Fixed
~~~~~

-  UniqueList contains method.

[0.6.0] - 2014-09-24
--------------------

Changed
~~~~~~~

-  LDAPClient accepts LDAPURL objects as url.
-  LDAPConnection search accepts LDAPDN objects as basedn parameter.

Added
~~~~~

-  Method to set certificate policy.
-  Server side sort control.

Fixed
~~~~~

-  Getting paged result cookie on MS Windows.
-  Segmentation fault of LDAPEntry.popitem().

[0.5.0] - 2014-03-08
--------------------

Changed
~~~~~~~

-  Module name to lower case.
-  Removed get_entry method.
-  LDAP URL parameters are used for search properly.

Added
~~~~~

-  New LDAPClient object for managing the connection settings.
-  DIGEST-MD5 support on MS Windows.
-  Raw attribute support: the given attributes will be kept in bytearray form.
-  Paged search control support.
-  Sphinx documentation with tutorial.

Fixed
~~~~~

- Several memory management issues.

[0.1.5] - 2013-07-31
--------------------

Changed
~~~~~~~

-  Errors are implemented in Python.
-  Using WinLDAP on MS Windows for LDAP operations.

Added
~~~~~

-  UniqueList for storing case-insensitive unique elements.
-  LDAPURL and LDAPDN Python classes for handling LDAP URL and distinguished
   name.

Fixed
~~~~~

-  Getting empty list for searching non-existing entries.

[0.1.0] - 2013-06-23
--------------------

-  Initial public release.
