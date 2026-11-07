#!/bin/bash
#
# Prepare the native libraries that get bundled into the macOS wheels.
# Intended to run as cibuildwheel's before-all, on the macOS host.
#
# Unlike .ci/build-dependencies.sh (Linux), nothing is compiled here: the libraries come
# from Homebrew, and `delocate-wheel` (cibuildwheel's default macOS repair step) copies
# the Homebrew dylibs into the wheel as bonsai/.dylibs and rewrites the install names:
#
#   _bonsai.so
#   └── .dylibs/libldap.2.dylib
#       ├── liblber.2.dylib
#       ├── libssl.3.dylib
#       └── libcrypto.3.dylib
#
# What is deliberately NOT bundled: libsasl2 and Kerberos/GSSAPI. These are part of macOS
# itself (/usr/lib), Cyrus SASL dlopen()s its mechanisms from /usr/lib/sasl2 and the
# system Kerberos is tied to the OS's credential cache, so a private copy would only
# break both. delocate leaves system libraries alone.
#
# The script lays out a prefix with the same shape the Linux build produces, so that
# setup.py's `build_ext --bundled-deps=<prefix>` works unchanged:
#
#   <prefix>/include, <prefix>/lib   -> the Homebrew openldap keg (symlinks)
#   <prefix>/licenses/*.txt          -> upstream licenses, of the exact Homebrew versions
#   <prefix>/bundled-versions.env    -> versions recorded into BUNDLED.txt

set -euo pipefail

PREFIX="${BONSAI_DEPS_PREFIX:-/tmp/bonsai-deps}"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT

log()  { printf '\n==> %s\n' "$*"; }
fail() { printf 'FATAL: %s\n' "$*" >&2; exit 1; }

log "Installing Homebrew dependencies"
brew install openldap

LDAP_KEG="$(brew --prefix openldap)"
[ -f "${LDAP_KEG}/include/ldap.h" ] || fail "no ldap.h in ${LDAP_KEG}/include"
ls "${LDAP_KEG}"/lib/libldap*.dylib >/dev/null || fail "no libldap in ${LDAP_KEG}/lib"

# The OpenSSL bundled is whichever formula the openldap bottle was built against (it moves
# from openssl@3 to newer ones over time), so ask Homebrew instead of naming a version.
SSL_FORMULA="$(brew deps --1 --formula openldap | grep '^openssl' | head -n 1 || true)"
[ -n "${SSL_FORMULA}" ] || fail "openldap does not depend on an openssl formula"
# Guard against a license and version inventory for an OpenSSL that is not the linked one.
LINKED_SSL="$(otool -L "${LDAP_KEG}"/lib/libldap.*.dylib | grep -o '/opt/openssl@[0-9.]*' | sort -u || true)"
if [ -n "${LINKED_SSL}" ] && [ "${LINKED_SSL}" != "/opt/${SSL_FORMULA}" ]; then
    fail "libldap links ${LINKED_SSL} but openldap depends on ${SSL_FORMULA}"
fi

# `brew list --versions` prints "<formula> <version>"; drop Homebrew's _revision suffix.
version_of() { brew list --versions "$1" | awk '{print $NF}' | sed 's/_[0-9]*$//'; }
OPENLDAP_VERSION="$(version_of openldap)"
OPENSSL_VERSION="$(version_of "${SSL_FORMULA}")"
[ -n "${OPENLDAP_VERSION}" ] && [ -n "${OPENSSL_VERSION}" ] || fail "cannot read formula versions"

log "Laying out ${PREFIX}"
rm -rf "${PREFIX}"
mkdir -p "${PREFIX}/licenses"
ln -s "${LDAP_KEG}/include" "${PREFIX}/include"
ln -s "${LDAP_KEG}/lib" "${PREFIX}/lib"

log "Collecting third-party licenses"
# The kegs do not reliably ship license files, so they are taken from the very source
# tarballs Homebrew builds from, which also guarantees they match the bundled version.
# --build-from-source is needed on both brew calls: by default `brew fetch` and
# `brew --cache` refer to the prebuilt bottle, which has no upstream license files.
collect_license() {
    local formula="$1" name="$2" src found=""
    brew fetch --formula --build-from-source "${formula}" >/dev/null
    src="$(brew --cache --formula --build-from-source "${formula}")"
    mkdir -p "${WORK_DIR}/${name}"
    tar -xf "${src}" -C "${WORK_DIR}/${name}" --strip-components=1
    for candidate in LICENSE LICENSE.txt COPYING COPYRIGHT NOTICE; do
        if [ -f "${WORK_DIR}/${name}/${candidate}" ]; then
            cat "${WORK_DIR}/${name}/${candidate}" >> "${PREFIX}/licenses/${name}.txt"
            found="yes"
        fi
    done
    if [ -z "${found}" ]; then
        ls "${WORK_DIR}/${name}" >&2
        fail "no license file found for ${name} in ${src}"
    fi
    echo "  ${name}"
}
collect_license openldap openldap
collect_license "${SSL_FORMULA}" openssl

cat > "${PREFIX}/bundled-versions.env" <<VERSIONS
BONSAI_BUNDLED_OPENSSL_VERSION=${OPENSSL_VERSION}
BONSAI_BUNDLED_OPENLDAP_VERSION=${OPENLDAP_VERSION}
VERSIONS

log "What libldap links against (informational)"
otool -L "${LDAP_KEG}"/lib/libldap.*.dylib | head -20
cat "${PREFIX}/bundled-versions.env"
