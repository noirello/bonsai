import os
import sys
import pathlib
import tempfile

from contextlib import contextmanager

from distutils.errors import CompileError, LinkError

from setuptools.command.build_ext import build_ext
from setuptools.command.build_py import build_py
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

    def finalize_options(self) -> None:
        super().finalize_options()
        prefix = self.get_finalized_command("build_py").bundled_deps
        if prefix:
            # Prepended, so a bundled build finds its own headers and libraries
            # before the system ones the checked-in setup.cfg names. Done here
            # rather than in build_extensions() because run() copies both lists
            # onto the compiler before calling it, and a later change would
            # reach _have_krb5 but not the extension.
            self.include_dirs.insert(0, os.path.join(prefix, "include"))
            self.library_dirs.insert(0, os.path.join(prefix, "lib"))

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

    def _accepts_flags(self, compile_args: list, link_args: list) -> bool:
        """Check the toolchain accepts the flags, since they are GNU ld specific."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            name = os.path.join(tmp_dir, "test_flags")
            src_name = name + ".c"
            with open(src_name, "w") as source:
                source.write("int PyInit__bonsai(void) { return 0; }\n")
            comp = self.compiler
            try:
                with silent_stderr():
                    comp.link_shared_object(
                        comp.compile(
                            [src_name], output_dir=tmp_dir, extra_postargs=compile_args
                        ),
                        name + ".so",
                        extra_postargs=link_args,
                    )
            except (CompileError, LinkError):
                return False
            else:
                return True

    def _harden_symbols(self) -> None:
        """Export only the module init symbol from the extension.

        The extension defines ~60 globals with names general enough to collide
        with another extension in the same interpreter, such as `lowercase` and
        `set_exception`. Hiding them also keeps the bundled OpenSSL and OpenLDAP
        symbols out of the wheel's dynamic symbol table, so nothing loaded later
        can bind to them by accident.
        """
        version_script = str(CURRDIR / "src" / "_bonsai" / "bonsai.map")
        compile_args = ["-fvisibility=hidden"]
        link_args = [f"-Wl,--version-script={version_script}"]
        if not self._accepts_flags(compile_args, link_args):
            print("INFO: toolchain does not accept symbol visibility flags, skipping.")
            return
        self.extensions[0].extra_compile_args.extend(compile_args)
        self.extensions[0].extra_link_args.extend(link_args)

    def build_extensions(self) -> None:
        if sys.platform.startswith("linux"):
            self._harden_symbols()
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
        if self.get_finalized_command("build_py").bundled_deps:
            self.extensions[0].define_macros.append(("BONSAI_BUNDLED", 1))
        return super().build_extensions()


class BuildPy(build_py):
    """Custom build_py to ship the licenses of the libraries bundled into the wheel."""

    # The prefix .ci/build-dependencies.sh installed the native dependencies
    # into for the build. Only a wheel build sets it, so BuildExt reads it back
    # from here to decide whether to define BONSAI_BUNDLED and where to look for
    # the headers and libraries.
    user_options = build_py.user_options + [
        (
            "bundled-deps=",
            None,
            "install prefix of the native dependencies to bundle into the wheel",
        )
    ]

    def initialize_options(self) -> None:
        super().initialize_options()
        self.bundled_deps = None

    def _copy_licenses(self, prefix: str) -> None:
        """Ship the licenses of the libraries the wheel redistributes.

        They go next to the package so that anyone auditing an installed wheel
        can list what it carries without unpacking or reverse engineering it.
        The build fails when they are missing, since a wheel that redistributes
        these libraries without their licenses does not satisfy their terms.
        """
        src_dir = os.path.join(prefix, "licenses")
        names = sorted(
            name for name in os.listdir(src_dir) if name.endswith(".txt")
        ) if os.path.isdir(src_dir) else []
        if not names:
            raise RuntimeError(
                f"no bundled licenses in {src_dir};"
                " the dependency build must collect them"
            )
        dst_dir = os.path.join(self.build_lib, "bonsai", "licenses")
        os.makedirs(dst_dir, exist_ok=True)
        for name in names:
            self.copy_file(os.path.join(src_dir, name), os.path.join(dst_dir, name))

        # The versions matter more than the license text for anyone matching this wheel
        # against a CVE, so a missing version file fails the build rather than quietly
        # producing an inventory with no versions in it.
        versions = os.path.join(prefix, "bundled-versions.env")
        if not os.path.isfile(versions):
            raise RuntimeError(f"{versions} is missing, cannot record bundled versions")
        lines = ["This wheel redistributes the following libraries in binary form.", ""]
        with open(versions) as src:
            for line in src:
                key, _, value = line.strip().partition("=")
                key = key.replace("BONSAI_BUNDLED_", "").replace("_VERSION", "")
                if key and value:
                    lines.append(f"{key.lower()} {value}")
        if len(lines) == 2:
            raise RuntimeError(f"no versions parsed from {versions}")
        lines += ["", "Their licenses are the other .txt files in this directory."]
        with open(os.path.join(dst_dir, "BUNDLED.txt"), "w") as dst:
            dst.write("\n".join(lines) + "\n")

    def run(self) -> None:
        super().run()
        if self.bundled_deps:
            self._copy_licenses(self.bundled_deps)


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

# Get the absolute path to the directory of setup.py.
CURRDIR = pathlib.Path(__file__).resolve().parent

# Get version number from the module's __init__.py file.
with open(CURRDIR / "src" / "bonsai" / "__init__.py") as src:
    VER = [
        line.split('"')[1] for line in src.readlines() if line.startswith("__version__")
    ][0]

setup(
    name="bonsai",
    version=VER,
    description="Python 3 module for accessing LDAP directory servers.",
    author="noirello",
    author_email="noirello@gmail.com",
    ext_modules=[BONSAI_MODULE],
    cmdclass={"build_ext": BuildExt, "build_py": BuildPy},
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
)
