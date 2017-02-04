import configparser
import os
import sys
import tempfile

from contextlib import contextmanager

import distutils.sysconfig
import distutils.ccompiler
from distutils.errors import CompileError, LinkError

try:
    from setuptools import setup, Extension, Command
except ImportError:
    from distutils.core import setup, Extension, Command

@contextmanager
def silent_stderr():
    """ Shush stderr for receiving unnecessary errors during setup. """
    devnull = open(os.devnull, 'w')
    old = os.dup(sys.stderr.fileno())
    os.dup2(devnull.fileno(), sys.stderr.fileno())
    try:
        yield devnull
    finally:
        os.dup2(old, sys.stderr.fileno())

def have_krb5(libs, libdirs=None):
    """ Check that the target platform has KRB5 support. """
    code = """
    #include <krb5.h>
    #include <gssapi/gssapi_krb5.h>

    int main(void) {
        unsigned int ms = 0;
        krb5_context ctx;
        const char *cname = NULL;

        krb5_init_context(&ctx);
        gss_krb5_ccache_name(&ms, cname, NULL);
        return 0;
    }
    """
    curdir = os.path.abspath(os.path.dirname(__file__))
    cfg = configparser.ConfigParser()
    cfg.read(os.path.join(curdir, 'setup.cfg'))
    with tempfile.TemporaryDirectory() as tmp_dir:
        name = os.path.join(tmp_dir, 'test_krb5')
        src_name = name + '.c'
        with open(src_name, 'w') as source:
            source.write(code)

        comp = distutils.ccompiler.new_compiler()
        distutils.sysconfig.customize_compiler(comp)
        for include_dir in cfg.get("build_ext", "include_dirs",
                                   fallback="").split(":"):
            if include_dir:
                comp.add_include_dir(include_dir)
        for library_dir in cfg.get("build_ext", "library_dirs",
                                   fallback="").split(":"):
            if library_dir:
                comp.add_library_dir(library_dir)
        try:
            with silent_stderr():
                if "-coverage" in os.getenv("CFLAGS", ""):
                    # If coverage flag is set.
                    libs.append("gcov")
                comp.link_executable(
                    comp.compile([src_name], output_dir=tmp_dir),
                    name, libraries=libs, library_dirs=libdirs)
        except (CompileError, LinkError):
            return False
        else:
            return True

class TestCommand(Command):
    description = "Run the tests."
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        import unittest
        tests = unittest.defaultTestLoader.discover("./tests")
        suite = unittest.TestSuite()
        suite.addTests(tests)
        #result = unittest.TestResult()
        unittest.TextTestRunner().run(suite)
        sys.exit(0)

SOURCES = ["bonsaimodule.c", "ldapentry.c", "ldapconnectiter.c",
           "ldapconnection.c", "ldapmodlist.c", "ldap-xplat.c",
           "ldapsearchiter.c", "utils.c"]

DEPENDS = ["ldapconnection.h", "ldapentry.h", "ldapconnectiter.h",
           "ldapmodlist.h", "ldapsearchiter.h", "ldap-xplat.h",
           "utils.h"]

LIBDIRS = []
MACROS = []
if sys.platform == "darwin":
    LIBDIRS.append("/usr/local/lib")
    MACROS.append(("MACOSX", 1))

if sys.platform == "win32":
    LIBS = ["wldap32", "secur32", "Ws2_32"]
    SOURCES.append("wldap-utf8.c")
    DEPENDS.append("wldap-utf8.h")
    MACROS.append(("WIN32", 1))
else:
    LIBS = ["ldap", "lber"]
    if have_krb5(["krb5", "gssapi"], LIBDIRS):
        LIBS.extend(["krb5", "gssapi"])
        MACROS.append(("HAVE_KRB5", 1))
    elif have_krb5(["krb5", "gssapi_krb5"], LIBDIRS):
        LIBS.extend(["krb5", "gssapi_krb5"])
        MACROS.append(("HAVE_KRB5", 1))
    else:
        print("INFO: Kerberos headers and libraries are not found."
              " Additional GSSAPI capabilities won't be installed.")

SOURCES = [os.path.join('src', x) for x in SOURCES]
DEPENDS = [os.path.join('src', x) for x in DEPENDS]

BONSAI_MODULE = Extension("bonsai._bonsai",
                          libraries=LIBS,
                          sources=SOURCES,
                          depends=DEPENDS,
                          define_macros=MACROS,
                          library_dirs=LIBDIRS)
PYTHON_DEPS = []

if sys.version_info.minor < 5:
    # Typing dependecy for Python 3.4 and earlier.
    PYTHON_DEPS.append("typing")

if sys.version_info.minor < 4:
    # Enum dependecy for Python 3.3.
    PYTHON_DEPS.append("enum34")

# Get long description from the README.rst file.
with open('README.rst') as file:
    LONG_DESC = file.read()

# Get version number from the module's __init__.py file.
with open('./lib/__init__.py') as src:
    VER = [line.split("'")[1] for line in src.readlines()
           if line.startswith('__version__')][0]

setup(name="bonsai",
      version=VER,
      description="Python 3 module for accessing LDAP directory servers.",
      author="noirello",
      author_email="noirello@gmail.com",
      url="https://github.com/noirello/bonsai",
      long_description=LONG_DESC,
      license="MIT",
      ext_modules=[BONSAI_MODULE],
      package_dir={"bonsai": "lib"},
      packages=["bonsai", "bonsai.asyncio", "bonsai.gevent", "bonsai.tornado"],
      include_package_data=True,
      install_requires=PYTHON_DEPS,
      cmdclass={"test": TestCommand},
      keywords=["python3", "ldap", "libldap", "winldap", "asyncio",
                "gevent", "tornado"],
      classifiers=[
          'Development Status :: 4 - Beta',
          'Intended Audience :: Developers',
          'Intended Audience :: System Administrators',
          'License :: OSI Approved :: MIT License',
          'Operating System :: Microsoft :: Windows',
          'Operating System :: Unix',
          'Programming Language :: C',
          'Programming Language :: Python :: 3',
          'Topic :: Software Development :: Libraries :: Python Modules',
          'Topic :: System :: Systems Administration :: Authentication/Directory :: LDAP']
     )
