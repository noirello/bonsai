Installing 
==========

Using pip
---------

Bonsai can be simply installed with Pip::

    $ pip install bonsai

.. _binary-wheels:

Binary wheels on Linux
----------------------

On Linux x86_64, pip installs a binary wheel where one is available for the interpreter,
built for both `manylinux_2_28` and `musllinux_1_2`, so no compiler and no development
headers are needed. Anything without a matching wheel installs from source as before.

Because the wheel cannot rely on the host having a suitable OpenLDAP, it carries its own
copies of OpenLDAP, Cyrus SASL, MIT Kerberos and OpenSSL. They are private to Bonsai, loaded
under content-hashed names, so they neither replace nor interfere with the system libraries,
and the standard library's ``ssl`` module keeps using the interpreter's own OpenSSL.

The versions are pinned in one place, and included here from it rather than restated:

.. literalinclude:: ../.ci/deps.env
   :language: ini
   :caption: .ci/deps.env
   :start-at: OPENSSL_VERSION=

A security update to one of these can be published as a wheel-only release, so for a wheel
already installed, read the versions out of the wheel itself; see
`Auditing what is shipped`_ below.

The SASL mechanisms are compiled into the bundled library rather than loaded from a plugin
directory at run time, so PLAIN, ANONYMOUS, EXTERNAL, CRAM-MD5, DIGEST-MD5, SCRAM, NTLM and
GSSAPI all work without `libsasl2-modules` installed.

Auditing what is shipped
~~~~~~~~~~~~~~~~~~~~~~~~

Every bundled library's version is recorded in `licenses/BUNDLED.txt` inside the installed
package, alongside the upstream license texts::

    $ cat "$(python -c 'import bonsai; print(bonsai.__path__[0])')/licenses/BUNDLED.txt"

To check what the extension actually links against::

    $ ldd "$(python -c 'import bonsai._bonsai as m; print(m.__file__)')"

Certificate verification
~~~~~~~~~~~~~~~~~~~~~~~~

A bundled OpenSSL has a single compiled-in trust store location, and no single value is
correct on every distribution. The wheel therefore locates the host's CA bundle at run time
and uses it as the default. An explicit :meth:`bonsai.LDAPClient.set_ca_cert` still wins, and
the `SSL_CERT_FILE` and `SSL_CERT_DIR` environment variables are honored ahead of the probe,
so a private or corporate trust store keeps working. Source builds are unaffected.

Installing from source instead
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To link against the distribution's own OpenLDAP and OpenSSL, for example to keep security
updates in the hands of the system package manager, skip the wheel::

    $ pip install --no-binary bonsai bonsai

This needs the build requirements listed in the next section.

.. note::
   Building the Linux wheels locally is done with `cibuildwheel`, not with a plain
   ``pip wheel``: the dependency build runs as root inside the manylinux or musllinux
   container and installs into ``/opt``. ::

       $ pipx run cibuildwheel --platform linux

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

Install from source on macOS
----------------------------

Because macOS is shipped with an older version of libldap which lacks of
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

Or with Apple Silicon:

.. code-block:: ini

 [build_ext]
 library_dirs = /opt/homebrew/opt/openldap/lib
 include_dirs = /usr/include/sasl:/opt/homebrew/opt/openldap/include


and then you can follow the standard build commands::
    
    $ python setup.py build
    $ python setup.py install

.. note::
   More directories can be set for include and library dirs (e.g. path to the
   Kerberos headers and libraries) by separating the paths with `:` in the
   `setup.cfg` file.

After installing Bonsai, you can learn the basic usage in the :doc:`tutorial`.
