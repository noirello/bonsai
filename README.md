pyLDAP
======

Python 3.x wrapper for libldap2.

Requirements for building
======

- python3.x-dev (tested with 3.2 and 3.3)
- libldap2-dev
- libsasl2-dev

Examples
======
.. code-block:: pycon
 >>> import pyLDAP

 >>> client = pyLDAP.LDAPClient("ldap://example.com/")
 >>> client.connect("cn=admin,dc=example,dc=com", "secret")
 >>> entry = client.get_entry("cn=test,dc=example,dc=com")
 >>> entry['mail'] = "test@example.com"
 >>> entry.modify()
 >>> client.close()
