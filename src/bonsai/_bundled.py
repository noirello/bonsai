"""
.. module:: _bundled
   :platform: Unix
   :synopsis: Support for binary wheels that ship their own native libraries.

Source builds link against the libraries already installed on the machine. The
Linux wheel ships its own instead, so it does not depend on the system libraries.
"""

import os
from typing import Optional, Tuple


def is_bundled() -> bool:
    """True when the extension is linked against libraries shipped inside the wheel."""
    # Imported here so that importing this module does not import the extension.
    from . import _bonsai

    return bool(getattr(_bonsai, "BUNDLED", False))

# Where the common distributions keep their CA bundle. A bundled OpenSSL has a single
# compiled-in location, and no value is right everywhere: Debian and Alpine use
# /etc/ssl/certs, while RHEL uses /etc/pki/tls and ships an empty /etc/ssl that would
# otherwise look like a valid answer.
CA_BUNDLE_FILES: Tuple[str, ...] = (
    "/etc/ssl/certs/ca-certificates.crt",  # Debian, Ubuntu, Alpine, Arch, Gentoo
    "/etc/pki/tls/certs/ca-bundle.crt",  # RHEL, Fedora, Rocky, Alma, Amazon
    # RHEL, where ca-trust extracts to
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/etc/ssl/ca-bundle.pem",  # openSUSE
    "/etc/pki/tls/cacert.pem",  # older RHEL
    "/etc/ssl/cert.pem",  # Alpine, some minimal images
)

CA_BUNDLE_DIRS: Tuple[str, ...] = (
    "/etc/ssl/certs",
    "/etc/pki/tls/certs",
)


def _is_populated_file(path: str) -> bool:
    """True for a CA bundle that has something in it.

    An empty bundle is a trust store that was never populated, which happens when
    an image installs ca-certificates but never runs update-ca-certificates.
    Handing it to OpenSSL fails every verification, so it has to lose to a later
    candidate that has certificates.
    """
    try:
        return os.path.isfile(path) and os.path.getsize(path) > 0
    except OSError:
        return False


def _is_populated_dir(path: str) -> bool:
    """True for a CA directory that has something in it.

    Unreadable directories count as absent. The probe runs while a client is being
    constructed, long before anyone asks for a connection, so it must not raise.
    """
    try:
        return os.path.isdir(path) and bool(os.listdir(path))
    except OSError:
        return False


def find_ca_bundle() -> Tuple[Optional[str], Optional[str]]:
    """
    Locate the host's CA bundle, as a (file, directory) pair of which either may
    be None.

    Only used for binary wheels. SSL_CERT_FILE and SSL_CERT_DIR win when set, since
    OpenSSL already honors them and the caller may be pointing at a private trust store.

    :return: the path of a CA bundle file and of a CA directory.
    :rtype: tuple
    """
    if not is_bundled():
        return None, None

    if os.environ.get("SSL_CERT_FILE") or os.environ.get("SSL_CERT_DIR"):
        return None, None

    for path in CA_BUNDLE_FILES:
        if _is_populated_file(path):
            return path, None

    for path in CA_BUNDLE_DIRS:
        if _is_populated_dir(path):
            return None, path

    return None, None
