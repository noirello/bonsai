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

- A C compiler (tested with gcc).

- The Python 3 header files. They are usually installed in a package such as
  **python3-dev**. 

- The libldap header files. They are usually installed in a package such as
  **libldap2-dev**.
  
- The libsasl header files. They are usually installed in a package such as
  **libsasl-dev**.

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

Based on the `description`_ of Rob McBroom installing only the OpenLDAP library
can be done by using Homebrew and the following formula:

.. code-block:: ruby

 require 'formula'

 class OpenldapLibs < Formula
   url 'ftp://ftp.openldap.org/pub/OpenLDAP//openldap-release/openldap-2.4.43.tgz'
   homepage 'http://www.openldap.org/'
   sha1 '3b52924df2f45e81f25ecbe37551bc837d090cfa'
   version '2.4.43'

   def install
     system "./configure", "--disable-debug", "--prefix=#{prefix}",
            "--disable-slapd", "--disable-slurpd"

     # empty Makefiles to prevent unnecessary installation attempts
     makefile = "all:\ninstall:\n"
     unwanted_paths = ['clients', 'servers', 'tests', 'doc']
     unwanted_paths.each do |upath|
       File.open(Dir.getwd + '/' + upath + '/Makefile', 'w') {|f| f.write(makefile)}
     end

     system "make install"
     File.rename("#{prefix}/etc/openldap/ldap.conf", "#{prefix}/etc/openldap/ldap.conf.backup")
     File.symlink('/etc/openldap/ldap.conf', "#{prefix}/etc/openldap/ldap.conf")
   end
 end

Save this formula to `/usr/local/Library/Formula/openldap-libs.rb`, then::

    # Might needed on newer Mac OS X for working TLS support.
    $ brew link openssl --force
    $ brew install openldap-libs

After this Bonsai can be compiled and installed the usual way::

    $ python setup.py build
    $ python setup.py install

Alternative way to install
**************************

Install `openldap` library by homebrew/dupes' formula::

    $ brew install homebrew/dupes/openldap

Then create `setup.cfg` in the root folder to customize the library and headers directory:

.. code-block:: ini

 [build_ext]
 include_dirs=/usr/local/opt/openldap/include
 library_dirs=/usr/local/opt/openldap/lib

and then you can follow the standard build commands::
    
    $ python setup.py build
    $ python setup.py install

.. _description: http://projects.skurfer.com/posts/2011/python_ldap_lion/
