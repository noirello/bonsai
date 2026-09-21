import os
import pathlib
import posixpath
import re
import subprocess
import sys

import pytest

import bonsai
from bonsai import _bundled

bundled_only = pytest.mark.skipif(
    not _bundled.is_bundled(),
    reason="only applies to wheels that bundle their own libraries",
)

source_only = pytest.mark.skipif(
    _bundled.is_bundled(),
    reason="only applies to builds that link against the system libraries",
)


@pytest.fixture
def probe(monkeypatch, tmp_path):
    """Drive find_ca_bundle() against a fake trust store, as if this were a wheel."""

    def configure(files=(), dirs=(), env=None):
        monkeypatch.setattr(_bundled, "is_bundled", lambda: True)
        monkeypatch.setattr(_bundled, "CA_BUNDLE_FILES", tuple(files))
        monkeypatch.setattr(_bundled, "CA_BUNDLE_DIRS", tuple(dirs))
        for name in ("SSL_CERT_FILE", "SSL_CERT_DIR"):
            monkeypatch.delenv(name, raising=False)
        for name, value in (env or {}).items():
            monkeypatch.setenv(name, value)
        return _bundled.find_ca_bundle()

    return configure


def test_probe_skips_a_present_but_empty_directory(probe, tmp_path):
    """RHEL ships an empty /etc/ssl/certs, which otherwise looks like an answer.

    This is the failure the probe exists to avoid, and it is silent: TLS
    verification just fails later with no indication that an empty directory was
    chosen.
    """
    empty = tmp_path / "empty-certs"
    empty.mkdir()
    populated = tmp_path / "real-certs"
    populated.mkdir()
    (populated / "ca.pem").write_text("cert")

    assert probe(dirs=[str(empty), str(populated)]) == (None, str(populated))


def test_probe_returns_nothing_when_every_directory_is_empty(probe, tmp_path):
    empty = tmp_path / "empty-certs"
    empty.mkdir()
    assert probe(dirs=[str(empty)]) == (None, None)


def test_probe_skips_a_present_but_empty_bundle_file(probe, tmp_path):
    """An image that installs ca-certificates but never runs
    update-ca-certificates leaves an empty bundle at the first candidate path.
    Choosing it fails every verification while a populated bundle sits further
    down the list.
    """
    empty = tmp_path / "empty-bundle.crt"
    empty.touch()
    populated = tmp_path / "real-bundle.crt"
    populated.write_text("cert")

    assert probe(files=[str(empty), str(populated)]) == (str(populated), None)


def test_probe_skips_an_unreadable_directory(probe, tmp_path, monkeypatch):
    """Listing a directory can raise where stat does not, and the probe runs
    while a client is being constructed, so an unreadable trust store must not
    break LDAPClient().
    """
    unreadable = tmp_path / "unreadable-certs"
    unreadable.mkdir()
    populated = tmp_path / "real-certs"
    populated.mkdir()
    (populated / "ca.pem").write_text("cert")

    real_listdir = os.listdir

    def deny(path):
        if str(path) == str(unreadable):
            raise PermissionError(13, "Permission denied", str(path))
        return real_listdir(path)

    monkeypatch.setattr(os, "listdir", deny)

    assert probe(dirs=[str(unreadable), str(populated)]) == (None, str(populated))


def test_probe_prefers_a_bundle_file_over_a_directory(probe, tmp_path):
    bundle = tmp_path / "ca-bundle.crt"
    bundle.write_text("cert")
    certs = tmp_path / "certs"
    certs.mkdir()
    (certs / "ca.pem").write_text("cert")

    assert probe(files=[str(bundle)], dirs=[str(certs)]) == (str(bundle), None)


def test_probe_takes_the_first_existing_candidate_in_order(probe, tmp_path):
    first = tmp_path / "first.crt"
    second = tmp_path / "second.crt"
    second.write_text("cert")
    third = tmp_path / "third.crt"
    third.write_text("cert")

    assert probe(files=[str(first), str(second), str(third)]) == (str(second), None)


def test_probe_finds_nothing_when_no_candidate_exists(probe, tmp_path):
    assert probe(
        files=[str(tmp_path / "absent.crt")], dirs=[str(tmp_path / "absent")]
    ) == (None, None)


@pytest.mark.parametrize("variable", ["SSL_CERT_FILE", "SSL_CERT_DIR"])
def test_probe_defers_to_the_openssl_environment_variables(probe, tmp_path, variable):
    """OpenSSL already honors these, and the caller may mean a private store."""
    bundle = tmp_path / "ca-bundle.crt"
    bundle.write_text("cert")

    assert probe(files=[str(bundle)], env={variable: str(tmp_path / "elsewhere")}) == (
        None,
        None,
    )


def test_probe_is_inert_unless_the_build_is_bundled(monkeypatch, tmp_path):
    """A source build must keep whatever the system OpenSSL already does."""
    bundle = tmp_path / "ca-bundle.crt"
    bundle.write_text("cert")
    monkeypatch.setattr(_bundled, "is_bundled", lambda: False)
    monkeypatch.setattr(_bundled, "CA_BUNDLE_FILES", (str(bundle),))

    assert _bundled.find_ca_bundle() == (None, None)


def test_candidate_paths_are_absolute():
    """A relative path here would resolve against the caller's directory."""
    # posixpath, not os.path: these are POSIX paths whatever the host is, and
    # ntpath.isabs() stopped calling a single leading slash absolute in 3.13.
    for path in _bundled.CA_BUNDLE_FILES + _bundled.CA_BUNDLE_DIRS:
        assert posixpath.isabs(path), f"{path} is not absolute"


def test_client_defaults_to_the_probed_bundle(monkeypatch, tmp_path):
    """The probe is only useful if LDAPClient actually adopts its result."""
    bundle = tmp_path / "ca-bundle.crt"
    bundle.write_text("cert")
    monkeypatch.setattr(
        "bonsai.ldapclient.find_ca_bundle", lambda: (str(bundle), None)
    )
    assert bonsai.LDAPClient().ca_cert == str(bundle)


def test_explicit_ca_cert_overrides_the_probe(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "bonsai.ldapclient.find_ca_bundle", lambda: (str(tmp_path / "probed.crt"), None)
    )
    client = bonsai.LDAPClient()
    client.set_ca_cert("/explicit/ca.pem")
    assert client.ca_cert == "/explicit/ca.pem"


def test_source_build_probe_is_inert():
    """A source build must not change the default CA paths."""
    if _bundled.is_bundled():
        pytest.skip("this build bundles its own libraries")
    assert _bundled.find_ca_bundle() == (None, None)
    assert bonsai.LDAPClient().cert_policy == -1


@bundled_only
def test_bundled_licenses_are_shipped():
    """Redistributing these libraries in binary form requires their licenses."""
    licenses = pathlib.Path(bonsai.__file__).parent / "licenses"
    assert licenses.is_dir(), f"{licenses} is missing from the wheel"
    shipped = {path.name for path in licenses.glob("*.txt")}
    for expected in ("openssl.txt", "cyrus-sasl.txt", "openldap.txt", "BUNDLED.txt"):
        assert expected in shipped, f"{expected} missing, have {sorted(shipped)}"
    for name in shipped:
        assert (licenses / name).stat().st_size > 0, f"{name} is empty"


@bundled_only
def test_bundled_inventory_lists_versions():
    """An auditor has to match this wheel against a CVE without unpacking it."""
    inventory = pathlib.Path(bonsai.__file__).parent / "licenses" / "BUNDLED.txt"
    content = inventory.read_text()
    for library in ("openssl", "cyrus_sasl", "openldap"):
        assert library in content, f"{library} not listed in BUNDLED.txt"
    versions = [
        line
        for line in content.splitlines()
        if line and line[-1].isdigit() and "." in line
    ]
    assert len(versions) >= 3, f"expected three versioned entries, got {versions}"


# Each library stamps its own version into its object, so these read back what
# was actually built rather than what the build was asked for. Checking the
# inventory against them covers .ci/deps.env too, since BUNDLED.txt is generated
# from it by substitution: a tarball that does not match the pin shows up here
# as a disagreement.
#
# SASL is read from libldap, which absorbs the mechanisms, so there is no
# libsasl2 to inspect. Its marker is the bare SASL_VERSION_STRING rather than an
# identifying phrase, because the phrases OpenLDAP wraps it in are emitted on
# glibc but not on musl. That is only safe while it is the single standalone
# version token in the object, which the test enforces.
BUNDLED_VERSION_MARKERS = (
    ("openssl", "libcrypto-*.so*", rb"OpenSSL (\d+\.\d+\.\d+)"),
    ("openldap", "libldap-*.so*", rb"\$OpenLDAP: libldap\.la (\d+\.\d+\.\d+)"),
    ("cyrus_sasl", "libldap-*.so*", rb"\x00(\d+\.\d+\.\d+)\x00"),
    ("krb5", "libkrb5-*.so*", rb"KRB5_BRAND: krb5-(\d+\.\d+(?:\.\d+)?)"),
)


EXPECTED_SONAMES = (
    "libldap",
    "liblber",
    "libcrypto",
    "libssl",
    "libkrb5",
    "libgssapi_krb5",
)


def _bundled_lib_dir():
    """Locate the directory the bundled libraries were repaired into."""
    # Not a skip: reaching here means the extension was compiled with
    # BONSAI_BUNDLED, so the wheel claims to carry its own libraries, and a
    # missing directory is that claim being false rather than a configuration
    # this test does not apply to.
    lib_dir = pathlib.Path(bonsai.__file__).parent.parent / "bonsai.libs"
    assert lib_dir.is_dir(), (
        f"the build is marked bundled but {lib_dir} does not exist;"
        " the wheel was never repaired, or was repaired without bundling anything"
    )
    return lib_dir


@bundled_only
def test_bundled_libraries_are_shipped():
    """A bundled wheel with no libraries would resolve against the host instead."""
    # auditwheel renames each library with a hash of its contents, so they are
    # matched on the soname prefix rather than by exact filename.
    contents = sorted(path.name for path in _bundled_lib_dir().iterdir())
    missing = [
        soname
        for soname in EXPECTED_SONAMES
        if not any(name.startswith(soname) for name in contents)
    ]
    assert not missing, f"missing from bonsai.libs: {missing}, have {contents}"


def _inventory_versions():
    """Parse BUNDLED.txt back into {library: version}."""
    inventory = pathlib.Path(bonsai.__file__).parent / "licenses" / "BUNDLED.txt"
    entries = {}
    for line in inventory.read_text().splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1][0].isdigit():
            entries[parts[0]] = parts[1]
    return entries


@bundled_only
@pytest.mark.parametrize("library, glob, marker", BUNDLED_VERSION_MARKERS)
def test_inventory_matches_the_linked_libraries(library, glob, marker):
    """An inventory that disagrees with the object it describes is worse than none."""
    lib_dir = _bundled_lib_dir()
    matches = sorted(lib_dir.glob(glob))
    assert len(matches) == 1, f"expected one {glob} in {lib_dir}, got {matches}"

    lib = matches[0]
    found = {hit.group(1).decode() for hit in re.finditer(marker, lib.read_bytes())}
    assert found, f"no version marker {marker!r} in {lib.name}"
    assert len(found) == 1, f"{lib.name} reports several versions: {sorted(found)}"
    linked = found.pop()

    declared = _inventory_versions().get(library)
    assert declared == linked, (
        f"BUNDLED.txt says {library} {declared}, {lib.name} reports {linked}"
    )


def _run_binutil(*args):
    """Run a binary-inspection tool, skipping the test where it is not installed.

    Minimal build containers often lack binutils, and a missing tool must not read as a
    failing assertion about the wheel.
    """
    if not sys.platform.startswith("linux"):
        pytest.skip("ELF inspection is platform specific")
    try:
        out = subprocess.run(args, capture_output=True, text=True)
    except (FileNotFoundError, OSError):
        pytest.skip(f"{args[0]} is not available")
    # Only a tool that produced nothing has really failed. musl's ldd relocates
    # as well as resolves, so on an extension module it exits non-zero over the
    # interpreter symbols that exist only in a running process, while still
    # printing correct resolution on stdout.
    if out.returncode != 0 and not out.stdout.strip():
        pytest.skip(f"{args[0]} failed: {out.stderr.strip()[:60]}")
    return out.stdout


@bundled_only
def test_extension_exports_only_its_init_symbol():
    """Generic globals in the extension could otherwise collide with another."""
    stdout = _run_binutil("nm", "-D", "--defined-only", bonsai._bonsai.__file__)
    exported = [line.split()[-1] for line in stdout.splitlines() if line.strip()]
    assert exported == ["PyInit__bonsai"], f"unexpected exports: {exported}"


@bundled_only
def test_no_system_ldap_or_sasl_is_used():
    """The wheel resolves its own libraries, not whatever the host happens to have."""
    stdout = _run_binutil("ldd", bonsai._bonsai.__file__)
    for line in stdout.splitlines():
        if any(name in line for name in ("libldap", "liblber", "libsasl")):
            assert "bonsai.libs" in line, f"resolved outside the wheel: {line.strip()}"


@source_only
def test_source_build_carries_no_bundled_artifacts():
    """`--no-binary bonsai` has to leave these libraries to the package manager."""
    package = pathlib.Path(bonsai.__file__).parent
    # Not to be confused with bonsai-<version>.dist-info/licenses/LICENSE, which
    # is bonsai's own and ships either way. This is the inventory BuildPy writes
    # beside the package, and only a bundled build has one.
    assert not (package / "licenses").exists(), "carries a bundled license inventory"
    assert not (package.parent / "bonsai.libs").exists(), "carries bundled libraries"


@source_only
def test_source_build_resolves_outside_the_package():
    """The mirror of the bundled case: it must link what the system installed."""
    stdout = _run_binutil("ldd", bonsai._bonsai.__file__)
    resolved = [line for line in stdout.splitlines() if "libldap" in line]
    assert resolved, f"the extension does not link libldap at all:\n{stdout}"
    for line in resolved:
        assert "bonsai.libs" not in line, f"resolved inside the package: {line.strip()}"


@bundled_only
@pytest.mark.parametrize("order", [("ssl", "bonsai"), ("bonsai", "ssl")])
def test_stdlib_ssl_is_unaffected(order):
    """The bundled OpenSSL must not displace the one the stdlib ssl module uses.

    Both import orders are checked, because this is a dynamic loader problem and the
    answer can differ depending on which OpenSSL is mapped first.
    """
    code = (
        f"import {order[0]}; import {order[1]}; import ssl, json;"
        " print(json.dumps({'v': ssl.OPENSSL_VERSION,"
        " 'ctx': bool(ssl.create_default_context())}))"
    )
    baseline = subprocess.run(
        [sys.executable, "-c", "import ssl; print(ssl.OPENSSL_VERSION)"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True
    )
    assert out.returncode == 0, out.stderr
    assert baseline in out.stdout, f"stdlib ssl changed: {baseline!r} vs {out.stdout!r}"
    assert '"ctx": true' in out.stdout.replace("'", '"').lower()
