PyLDAP
======

This is a module for handling LDAP operations in Python. Uses libldap2 on Unix platforms and WinLDAP 
on Microsoft Windows. LDAP entries are mapped to a special Python case-insensitive dictionary,
tracking the changes of the dictionary to modify the entry on the server easily.

Support only Python 3.3 or newer, and LDAPv3. 

Requirements for building
-------------------------

- python3.3-dev or python3.4-dev
- libldap2-dev
- libsasl2-dev


Documentation
-------------

Online documentation with a simple tutorial at http://pyldap.readthedocs.org/en/latest/.


Contribution
------------

This is my first public Python module, and very first time for me to use the Python/C API.
Contributions and advices are welcome. :) (Just tell me the whats and whys.) 
