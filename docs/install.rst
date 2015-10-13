Installing 
==========

Install from source on Linux
----------------------------

These notes illustrate how to compile Bonsai on Linux.

.. _requirements:

Bonsai is a C wrapper to the OpenLDAP libldap2 library. To install it
from sources you will need:

- A C compiler (tested with gcc).

- The Python 3 header files. They are usually installed in a package such as
  **python3-dev**. 

- The libldap header files. They are usually installed in a package such as
  **libldap2-dev**.
  
- The libsasl header files. They are usually installed in a package such as
  **libsasl-dev**.

- The Bonsai source files. You can download it form the project's `GitHub site`_.

.. _github site: https://github.com/Noirello/bonsai

Once you downloaded and unpackaged the Bonsai source files, you can run the
following command to compile and install the package::
    
    $ python3 setup.py build
    $ sudo python3 setup.py install
    
Install from source on Windows
------------------------------

Bonsai uses WinLDAP on Microsoft Windows. To install it from sources you will
need a C compiler and the Bonsai source files. After you downloaded and 
unpackaged the sources, you can run::
    
    $ python setup.py build
    $ python setup.py install

.. note::  
   Compiling the package with MinGW is no longer recommended.
