import os
import sys
import shutil
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
    with tempfile.TemporaryDirectory() as tmp_dir:
        name = os.path.join(tmp_dir, 'test_krb5')
        src_name = name + '.c'
        with open(src_name, 'w') as source:
            source.write(code)

        comp = distutils.ccompiler.new_compiler()
        distutils.sysconfig.customize_compiler(comp)
        try:
            with silent_stderr():
                if "-coverage" in os.getenv("CFLAGS", ""):
                    # If coverage flag is set.
                    libs.append("gcov")
                comp.link_executable(
                        comp.compile([src_name],output_dir=tmp_dir),
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

sources = ["bonsaimodule.c", "ldapentry.c", "ldapconnectiter.c",
           "ldapconnection.c", "ldapmodlist.c", "ldap-xplat.c",
           "ldapsearchiter.c", "utils.c"]

depends = ["ldapconnection.h", "ldapentry.h", "ldapconnectiter.h",
           "ldapmodlist.h", "ldapsearchiter.h", "ldap-xplat.h",
           "utils.h"]

libdirs = []
macros = []
if sys.platform == "darwin":
    libdirs.append("/usr/local/lib")
    macros.append(("MACOSX", 1))

if sys.platform == "win32":
    libs = ["wldap32", "secur32", "Ws2_32"]
    sources.append("wldap-utf8.c")
    depends.append("wldap-utf8.h")
    macros.append(("WIN32", 1))
else:
    libs = ["ldap", "lber"]
    if have_krb5(["krb5", "gssapi"], libdirs):
        libs.extend(["krb5", "gssapi"])
        macros.append(("HAVE_KRB5", 1))
    elif have_krb5(["krb5", "gssapi_krb5"], libdirs):
        libs.extend(["krb5", "gssapi_krb5"])
        macros.append(("HAVE_KRB5", 1))
    else:
        print("INFO: Kerberos headers and libraries are not found."
              " Additional GSSAPI capabilities won't be installed.")

sources = [os.path.join('src', x) for x in sources]
depends = [os.path.join('src', x) for x in depends]

bonsai_module = Extension("bonsai._bonsai",
                          libraries=libs,
                          sources=sources,
                          depends=depends,
                          define_macros=macros,
                          library_dirs=libdirs)
python_deps = []

if sys.version_info.minor < 5:
    # Typing dependecy for Python 3.4 and earlier.
    python_deps.append("typing")

if sys.version_info.minor < 4:
    # Enum dependecy for Python 3.3.
    python_deps.append("enum34")

with open('README.rst') as file:
    long_descr = file.read()

setup(name="bonsai",
      version="0.8.9",
      description="Python 3 module for accessing LDAP directory servers.",
      author="noirello",
      author_email="noirello@gmail.com",
      url="https://github.com/noirello/bonsai",
      long_description=long_descr,
      license="MIT",
      ext_modules=[bonsai_module],
      package_dir = {"bonsai": "lib"},
      packages=["bonsai", "bonsai.asyncio", "bonsai.gevent", "bonsai.tornado"],
      include_package_data=True,
      install_requires=python_deps,
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

