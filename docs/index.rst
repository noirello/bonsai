.. bonsai documentation master file, created by
   sphinx-quickstart on Sat Jan 18 21:30:25 2014.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Bonsai's documentation
======================

Bonsai is an LDAP module for Python 3, using OpenLDAP's libldap2 library on Linux, and the WinLDAP
library on Microsoft Windows to handle communications with LDAP capable directory servers.
The module main goal is to give a simple way to use the LDAP protocol as pythonic as it can be.

.. warning::
   The module is under development, therefore the module's architecture could change significantly.
   
.. note::
   The module compatibles only with Python 3.3 or newer releases.

Features
--------

* Uses LDAP libraries (OpenLDAP and WinLDAP) written in C for faster processing. 
* Implements an own dictionary-like object for mapping LDAP entries that makes easier to add and modify them.
* Works with asyncio for asynchronous operations.


Contents
--------

.. toctree::
   :maxdepth: 2

   install
   tutorial
   api
   
Contribution
------------

Any contributions are welcome. If you would like to help in development
fork or report issue on the project's `GitHub site`_. 
You can also help in improving the documentation. My English is far from perfect, so if you find 
any grammatically incorrect sentence, please report to me (with suggestion).   

.. _github site: https://github.com/Noirello/bonsai

Indices and tables
------------------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

