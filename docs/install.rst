Installing 
==========

Install from source on Linux
----------------------------

These notes illustrate how to compile pyLDAP on Linux. 

.. _requirements:

PyLDAP is a C wrapper to the OpenLDAP libldap2 library. To install it
from sources you will need:

- A C compiler (tested with gcc).

- The Python 3 header files. They are usually installed in a package such as
  **python3-dev**. 

- The libldap header files. They are usually installed in a package such as
  **libldap2-dev**.
  
- The libsasl header files. They are usually installed in a package such as
  **libsasl-dev**.

- The pyLDAP source files. You can download it form the project's `github site`_.

.. _github site: https://github.com/Noirello/PyLDAP

Once you downloaded and unpackaged the pyLDAP source files, you can run the 
following command to compile and install the package::
    
    $ python3 setup.py build
    $ sudo python3 setup.py install
    
Install from source on Windows
------------------------------
pyLDAP uses WinLDAP on Microsoft Windows. To install it form sources you will
need a C compiler and the pyLDAP source files. After you downloaded and 
unpackaged the sources, you can run::
    
    $ python setup.py build
    $ python setup.py install

.. note::  
   The package compiled with MinGW under development on Windows. The setuptools 
   uses the Visual C++ compiler by default. You can change it::
       
       $ python setup.py build -c mingw32
