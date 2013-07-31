pyLDAP
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


Requirements for building
=========================

- python3.x-dev (tested with 3.2 and 3.3)
- libldap2-dev
- libsasl2-dev

Examples
========
Add a new attribute (mail) for an existing entry:
```python
    import pyLDAP
    client = pyLDAP.LDAPClient("ldap://example.com/")
    client.connect("cn=admin,dc=example,dc=com", "secret")
    entry = client.get_entry("cn=test,dc=example,dc=com")
    entry['mail'] = "test@example.com"
    entry.modify()
    client.close()
```
Add a new entry:
```python
    import pyLDAP
    client = pyLDAP.LDAPClient("ldap://example.com/")
    client.connect("cn=admin,dc=example,dc=com", "secret")
    entry = pyLDAP.LDAPEntry("cn=test,dc=example,dc=com", client)
    entry['objectClass'] = ["top", "organizationalPerson", "inetOrgPerson"]
    # Case-insenstitve dict.
    entry['ObjEctClaSS'].append("person")
    entry['sn'] = "Smith"
    entry['gn'] = "John"
    entry.add()
    client.close()
```
Search:
```python
    import pyLDAP
    client = pyLDAP.LDAPClient("ldap://example.com/")
    client.connect()
    client.search(base="dc=example.dc=com", scope=2)
```
Delete:
```python
    import pyLDAP
    client = pyLDAP.LDAPClient("ldap://example.com/")
    client.connect("cn=admin,dc=example,dc=com", "secret")
    client.del_entry("cn=test,dc=example.dc=com")
    client.close()
```
or (keeping the data on the local machine):
```python
    import pyLDAP
    client = pyLDAP.LDAPClient("ldap://example.com/")
    client.connect("cn=admin,dc=example,dc=com", "secret")
    entry = client.get_entry("cn=test,dc=example.dc=com")
    entry.delete()
    client.close()
```
