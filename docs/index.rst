.. bonsai documentation master file, created by
   sphinx-quickstart on Sat Jan 18 21:30:25 2014.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Bonsai's documentation
**********************

Bonsai is an LDAP module for Python 3, using OpenLDAP's libldap2 library on Linux, and the WinLDAP
library on Microsoft Windows to handle communications with LDAP capable directory servers.
The module main goal is to give a simple way to use the LDAP protocol as pythonic as it can be.

.. note::
   The module is compatible only with Python 3.6 or newer releases.

Features
========

* Uses LDAP libraries (OpenLDAP and WinLDAP) written in C for faster processing.
* Simple pythonic design.
* Implements an own dictionary-like object for mapping LDAP entries that makes easier to add and
  modify them.
* Works with various asynchronous library (like asyncio, gevent).


Contents
========

.. toctree::
   :maxdepth: 3

   install
   tutorial
   advanced
   api
   changelog
   
Contribution
============

Any contributions are welcome. If you would like to help in development fork or report issue on the
project's `GitHub site`_. You can also help in improving the documentation.

.. _github site: https://github.com/noirello/bonsai

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

