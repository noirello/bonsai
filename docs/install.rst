Installing 
==========

Using pip
---------

Bonsai can be simply installed with Pip::

    $ pip install bonsai

Install from source on Linux
----------------------------

These notes illustrate how to compile Bonsai on Linux.

.. _requirements:

Bonsai is a C wrapper to the OpenLDAP libldap2 library. To install it
from sources you will need:

- A C compiler (The module is tested with gcc).

- The Python 3 header files. They are usually installed in a package such as
  **python3-dev**. 

- The libldap header files. They are usually installed in a package such as
  **libldap2-dev**.
  
- The libsasl header files. They are usually installed in a package such as
  **libsasl2-dev**.

- The Bonsai source files. You can download it from the project's `GitHub site`_.

- Optionally for additional functions the Kerberos header files. They are
  usually installed in a package such as **libkrb5-dev** or **heimdal-dev**.

.. _github site: https://github.com/noirello/bonsai

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

Install from source on Mac OS X
-------------------------------

Because Mac OS X is shipped with an older version of libldap which lacks of
several features that Bonsai relies on, a newer library needs to be installed
before compiling the module.

Install `openldap` homebrew-core formula::

    $ brew install openldap

Modify the `setup.cfg` in the root folder to customize the library and headers
directory:

.. code-block:: ini

 [build_ext]
 include_dirs=/usr/local/opt/openldap/include
 library_dirs=/usr/local/opt/openldap/lib

and then you can follow the standard build commands::
    
    $ python setup.py build
    $ python setup.py install

.. note::
   More directories can be set for include and library dirs (e.g. path to the
   Kerberos headers and libraries) by separating the paths with `:` in the
   `setup.cfg` file.

After installing Bonsai, you can learn the basic usage in the :doc:`tutorial`.
