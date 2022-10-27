import os
import sys
import tempfile

from contextlib import contextmanager

from distutils.errors import CompileError, LinkError

from setuptools.command.build_ext import build_ext
from setuptools import setup, Extension


@contextmanager
def silent_stderr():
    """Shush stderr for receiving unnecessary errors during setup."""
    devnull = open(os.devnull, "w")
    old = os.dup(sys.stderr.fileno())
    os.dup2(devnull.fileno(), sys.stderr.fileno())
    try:
        yield devnull
    finally:
        os.dup2(old, sys.stderr.fileno())


class BuildExt(build_ext):
    """Custom build_ext to test Kerberose capability."""

    def _have_krb5(self, libs: list) -> bool:
        code = """
        #include <krb5.h>
        #include <gssapi/gssapi_krb5.h>

        int main(void) {
            unsigned int ms = 0;
            krb5_context ctx;
            const char *cname = NULL;
            gss_key_value_set_desc store;

            store.count = 0;
            krb5_init_context(&ctx);
            gss_krb5_ccache_name(&ms, cname, NULL);
            return 0;
        }
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            name = os.path.join(tmp_dir, "test_krb5")
            src_name = name + ".c"
            with open(src_name, "w") as source:
                source.write(code)
            comp = self.compiler
            try:
                with silent_stderr():
                    if "-coverage" in os.getenv("CFLAGS", ""):
                        # If coverage flag is set.
                        libs.append("gcov")
                    comp.link_executable(
                        comp.compile([src_name], output_dir=tmp_dir),
                        name,
                        libraries=libs,
                        library_dirs=self.library_dirs,
                    )
            except (CompileError, LinkError):
                return False
            else:
                return True

    def build_extensions(self) -> None:
        if sys.platform != "win32":
            if self._have_krb5(["krb5", "gssapi"]):
                self.extensions[0].libraries.extend(["krb5", "gssapi"])
                self.extensions[0].define_macros.append(("HAVE_KRB5", 1))
            elif self._have_krb5(["krb5", "gssapi_krb5"]):
                self.extensions[0].libraries.extend(["krb5", "gssapi_krb5"])
                self.extensions[0].define_macros.append(("HAVE_KRB5", 1))
            else:
                print(
                    "INFO: Kerberos headers and libraries are not found."
                    " Additional GSSAPI capabilities won't be installed."
                )
        return super().build_extensions()


SOURCES = [
    "bonsaimodule.c",
    "ldapentry.c",
    "ldapconnectiter.c",
    "ldapconnection.c",
    "ldapmodlist.c",
    "ldap-xplat.c",
    "ldapsearchiter.c",
    "utils.c",
]

DEPENDS = [
    "ldapconnection.h",
    "ldapentry.h",
    "ldapconnectiter.h",
    "ldapmodlist.h",
    "ldapsearchiter.h",
    "ldap-xplat.h",
    "utils.h",
]

MACROS = []
if sys.platform == "darwin":
    MACROS.append(("MACOSX", 1))

if sys.platform == "win32":
    LIBS = ["wldap32", "secur32", "Ws2_32"]
    SOURCES.append("wldap-utf8.c")
    DEPENDS.append("wldap-utf8.h")
    MACROS.append(("WIN32", 1))
else:
    LIBS = ["ldap", "lber"]

SOURCES = [os.path.join("src/_bonsai", x) for x in SOURCES]
DEPENDS = [os.path.join("src/_bonsai", x) for x in DEPENDS]

BONSAI_MODULE = Extension(
    "bonsai._bonsai",
    libraries=LIBS,
    sources=SOURCES,
    depends=DEPENDS,
    define_macros=MACROS,
)

# Get long description from the README.rst file.
with open("README.rst") as file:
    LONG_DESC = file.read()

# Get version number from the module's __init__.py file.
with open("./src/bonsai/__init__.py") as src:
    VER = [
        line.split('"')[1] for line in src.readlines() if line.startswith("__version__")
    ][0]

setup(
    name="bonsai",
    version=VER,
    description="Python 3 module for accessing LDAP directory servers.",
    author="noirello",
    author_email="noirello@gmail.com",
    url="https://github.com/noirello/bonsai",
    long_description=LONG_DESC,
    long_description_content_type="text/x-rst",
    license="MIT",
    ext_modules=[BONSAI_MODULE],
    cmdclass={"build_ext": BuildExt},
    package_dir={"bonsai": "src/bonsai"},
    package_data={"bonsai": ["py.typed"]},
    packages=[
        "bonsai",
        "bonsai.active_directory",
        "bonsai.asyncio",
        "bonsai.gevent",
        "bonsai.tornado",
        "bonsai.trio",
    ],
    include_package_data=True,
    install_requires=[
        'typing-extensions >= 4.0.0 ; python_version < "3.8"',
    ],
    extras_require={
        "gevent": ["gevent>=1.4.0"],
        "tornado": ["tornado>=5.1.1"],
        "trio": ["trio>=0.16.0"],
    },
    keywords=[
        "python3",
        "ldap",
        "ldap3",
        "python-ldap",
        "libldap",
        "winldap",
        "asyncio",
        "gevent",
        "tornado",
        "trio",
    ],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: Unix",
        "Programming Language :: C",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: Implementation :: CPython",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Systems Administration :: Authentication/Directory :: LDAP",
    ],
)
