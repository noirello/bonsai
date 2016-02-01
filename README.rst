Bonsai
======

.. image:: https://img.shields.io/pypi/v/bonsai.svg?style=flat-square
    :target: https://pypi.python.org/pypi/bonsai/
    :alt: PyPI Version

.. image:: https://img.shields.io/travis/Noirello/bonsai/dev.svg?style=flat-square
    :target: https://travis-ci.org/Noirello/bonsai
    :alt: Build Status
    
.. image:: https://img.shields.io/codecov/c/github/Noirello/bonsai/dev.svg?style=flat-square
    :target: https://codecov.io/github/Noirello/bonsai?branch=dev
    :alt: Coverage Status

.. image:: https://readthedocs.org/projects/bonsai/badge/?version=latest&style=flat-square
    :target: http://bonsai.readthedocs.org/en/latest/
    :alt: Documentation Status

.. image:: https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square
    :target: https://raw.githubusercontent.com/Noirello/bonsai/master/LICENSE
    :alt: GitHub License

This is a module for handling LDAP operations in Python. Uses libldap2 on Unix platforms and WinLDAP on Microsoft Windows.
LDAP entries are mapped to a special Python case-insensitive dictionary, tracking the changes of the dictionary to modify
the entry on the server easily.

Supports only Python 3.3 or newer, and LDAPv3.

Requirements for building
-------------------------

-  python3.3-dev or newer
-  libldap2-dev
-  libsasl2-dev

Features
--------

-  Uses LDAP libraries (OpenLDAP and WinLDAP) written in C for faster
   processing.
-  Simple pythonic design.
-  Implements an own dictionary-like object for mapping LDAP entries
   that makes easier to add and modify them.
-  Works with various asynchronous library (like asyncio, gevent).

Example
-------

Simple search and modify:

.. code:: python

        import bonsai

        client = bonsai.LDAPClient("ldap://localhost")
        client.set_credentials("SIMPLE", ("cn=admin,dc=local", "secret"))
        with client.connect() as conn:
            res = conn.search("ou=nerdherd,dc=local", 2, "(cn=chuck)")
            res[0]['givenname'] = "Charles"
            res[0]['sn'] = "Carmichael"
            res[0].modify()

Using with asnycio:

.. code:: python

        import asyncio
        import bonsai

        @asyncio.coroutine
        def do():
            client = bonsai.LDAPClient("ldap://localhost")
            client.set_credentials("DIGEST-MD5", ("admin", "secret", None, None))
            with (yield from client.connect(async=True)) as conn:
                res = yield from conn.search("ou=nerdherd,dc=local", 2)
                print(res)
                who = yield from conn.whoami()
                print(who)

Documentation
-------------

Documentation is available `online`_ with a simple tutorial.

Changelog
---------

Currently, you can read the changelog `here`_.

Contribution
------------

Any contributions and advices are welcome. Please report any issues at
the `GitHub page`_.

.. _online: http://bonsai.readthedocs.org/en/latest/
.. _here: https://github.com/noirello/bonsai/blob/master/CHANGELOG.md
.. _GitHub page: https://github.com/Noirello/bonsai/issues