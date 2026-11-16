Installing
==========

Using pip
---------

Bonsai can be simply installed with pip::

    $ pip install bonsai

.. note::
    To skip the prebuilt wheels (and the libraries bundled in them) and build
    against the system libraries instead, pass ``--no-binary`` to pip::

        $ pip install --no-binary bonsai bonsai

    See the source installation sections below for the required headers.

Binary wheels on Linux
----------------------

On Linux x86_64, pip installs a binary wheel, built for both `manylinux_2_28` and
`musllinux_1_2`, so no compiler and no development headers are needed.
Anything without a matching wheel installs from source.

Because the wheel cannot rely on the host having a suitable OpenLDAP, it carries its own
copies of OpenLDAP, Cyrus SASL, MIT Kerberos and OpenSSL. They are private to Bonsai, loaded
under content-hashed names, so they neither replace nor interfere with the system libraries,
and the standard library's ``ssl`` module keeps using the interpreter's own OpenSSL.

The SASL mechanisms are compiled into the bundled library rather than loaded
from a plugin directory at run time, so PLAIN, ANONYMOUS, EXTERNAL, CRAM-MD5,
DIGEST-MD5, SCRAM, NTLM and GSSAPI all work without `libsasl2-modules`
installed.

Binary wheels on macOS
----------------------

The distributed wheels for macOS are also bundled with their own OpenLDAP and
OpenSSL libraries, so they do not depend on the versions installed on the host.

Unlike the Linux wheels, they do not bundle Cyrus SASL or Kerberos/GSSAPI.
Those are part of macOS itself: Cyrus SASL loads its mechanisms from
``/usr/lib/sasl2`` at run time, and the system Kerberos is tied to the OS
credential cache, so a private copy would break both.

Auditing what is shipped
------------------------

For bundled wheels, every library's version is recorded in ``licenses/BUNDLED.txt``
inside the installed package, alongside the upstream licence texts::

    $ cat "$(python -c 'import bonsai; print(bonsai.__path__[0])')/licenses/BUNDLED.txt"

Certificate verification
~~~~~~~~~~~~~~~~~~~~~~~~

When OpenSSL is bundled, it has a single compiled-in trust store location,
and no single value is correct on every distribution. The wheel therefore
locates the host's CA bundle at run time and uses it as the default. An
explicit :meth:`bonsai.LDAPClient.set_ca_cert` still wins, and the
`SSL_CERT_FILE` and `SSL_CERT_DIR` environment variables are honoured ahead of
the probe, so a private or corporate trust store keeps working. Source builds
are unaffected.

Install from source on Linux
----------------------------

These notes illustrate how to compile Bonsai on Linux.

Bonsai is a C wrapper around the OpenLDAP libldap2 library. To install it
from sources you will need:

- A C compiler (The module is tested with gcc).

- The Python 3 header files. They are usually installed in a package such as
  **python3-dev**.

- The libldap header files. They are usually installed in a package such as
  **libldap2-dev**.

- The libsasl header files. They are usually installed in a package such as
  **libsasl2-dev**.

- The Bonsai source files. You can download them from the project's `GitHub site`_.

- Optionally, the Kerberos header files, for additional functions. They are
  usually installed in a package such as **libkrb5-dev** or **heimdal-dev**.

.. _github site: https://github.com/noirello/bonsai

Once you have downloaded and unpacked the Bonsai source files, you can run the
following command in the root of the source directory to compile and install
the package::

    $ pip install .

This will link against the system-provided libraries.

Install from source on Windows
------------------------------

Bonsai uses WinLDAP on Microsoft Windows. To install it from sources you will
need a C compiler and the Bonsai source files. Once you have downloaded and
unpacked the sources, you can run the following command in the root of the
source directory::

    $ pip install .

.. note::
    Compiling the package with MinGW is no longer recommended.

Install from source on macOS
----------------------------

Because macOS is shipped with an older version of libldap that lacks several
features that Bonsai relies on, a newer library needs to be installed before
compiling the module.

Install the `openldap` Homebrew formula::

    $ brew install openldap

Modify the `setup.cfg` in the root folder to customize the library and header
directories:

.. code-block:: ini

    [build_ext]
    include_dirs=/usr/local/opt/openldap/include
    library_dirs=/usr/local/opt/openldap/lib

Or with Apple Silicon:

.. code-block:: ini

    [build_ext]
    library_dirs = /opt/homebrew/opt/openldap/lib
    include_dirs = /usr/include/sasl:/opt/homebrew/opt/openldap/include


And then you can follow the standard build commands::

    $ pip install .

.. note::
    More directories can be set for include and library dirs (e.g. path to the
    Kerberos headers and libraries) by separating the paths with `:` in the
    `setup.cfg` file.

.. note::
    When using `uv`_ as packaging- and dependency-tool, you have to define
    the separate libraries for MAC-OS-Installation from above in a
    pyproject.toml section:

    .. code-block:: ini

        [tool.uv]
        extra-build-variables = { bonsai = { CFLAGS="-I/opt/homebrew/opt/openldap/include -L/opt/homebrew/opt/openldap/lib" } }

.. _uv: https://docs.astral.sh/uv/

After installing Bonsai, you can learn the basic usage in the :doc:`tutorial`.
