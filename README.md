PyLDAP
======

This is a module for handling LDAP operations in Python. Uses libldap2 on Unix platforms and winldap 
on Microsoft Windows. LDAP entries are mapped to a special Python case-insensitive dictionary, 
tracking the changes of the dictionary to modify the entry on the server easily.
<br/>*Heavily* under development. <br/>
Support only Python 3.x, and LDAPv3. <br/>
No chance to call asynchronous LDAP operations at the moment. <br/>
<br/>
<br/>
This is my first public Python module, and very first time for me to use the Python/C API.
Contributions and advices are welcome. :) (Just tell me the whats and whys.)  


Documentation
=============
Online documentation with tutorial at http://pyldap.readthedocs.org/en/latest/.


Requirements for building
=========================

- python3.x-dev (tested with 3.2 and 3.3)
- libldap2-dev
- libsasl2-dev
