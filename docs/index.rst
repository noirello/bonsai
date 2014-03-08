.. pyldap documentation master file, created by
   sphinx-quickstart on Sat Jan 18 21:30:25 2014.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

PyLDAP's documentation
======================

PyLDAP is an LDAP module for Python 3, using OpenLDAP's libldap2 library on Linux, and the WinLDAP 
library on Microsoft Windows to handle communictaions with LDAP capable directory servers. 
The module main goal is to give a simple way to use the LDAP protocol as pythonic as it can be.

.. warning::
   The module is under development. Only blocking operations are implemented yet, and the module's 
   architecture could change significantly.
   
.. note::
   There is no support for Python 2.7.6 or older releases.

Contents:

.. toctree::
   :maxdepth: 2

   install
   tutorial
   api
   
Contribution
============
Any contribution is welcome. If you would like to help in development 
fork or report issue on the project's `github site`_. 
You can also help in improving the documentation. My English is far from perfect, so if you find 
any grammatically incorrect sentence, please report to me (with suggestion).   

.. _github site: https://github.com/Noirello/PyLDAP

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

