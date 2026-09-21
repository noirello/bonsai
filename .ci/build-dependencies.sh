#!/bin/bash
#
# Build the native libraries that get bundled into the Linux wheels.
# Intended to run as cibuildwheel's CIBW_BEFORE_ALL, inside the manylinux or musllinux
# container.
#
# The resulting layout, after `auditwheel repair`, is:
#
#   _bonsai.so
#   └── bonsai.libs/libldap-<hash>.so   <- Cyrus SASL statically absorbed, mechanisms built in
#       ├── liblber-<hash>.so
#       ├── libssl-<hash>.so
#       └── libcrypto-<hash>.so
#
# There is deliberately NO libsasl2.so and there are NO SASL mechanism plugin .so files.
# Cyrus SASL normally dlopen()s its mechanisms from a plugin directory at run time, which
# cannot work from inside a wheel. Building it as a static archive compiles the mechanisms
# directly into the library instead, so nothing is loaded from disk at run time.
#
# Several of the flags below look redundant or removable and are not. Each one is annotated.

set -euo pipefail

SOURCE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
# shellcheck source=deps.env
source "${SOURCE_DIR}/.ci/deps.env"

PREFIX="${BONSAI_DEPS_PREFIX:-/opt/bonsai-deps}"
BUILD_DIR="${BONSAI_BUILD_DIR:-/opt/bonsai-deps-build}"
JOBS="$(nproc)"

mkdir -p "${BUILD_DIR}" "${PREFIX}"

log()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
fail() { printf '\033[1;31mFATAL: %s\033[0m\n' "$*" >&2; exit 1; }

register_library_path() {
    arch="$(uname -m)"
    if [ -e "/lib/ld-musl-${arch}.so.1" ]; then
        # musl reads its library search path from this file. The contents replace the
        # loader's built-in path rather than extending it, so the defaults are written
        # out alongside the prefix.
        musl_path="/etc/ld-musl-${arch}.path"
        if [ ! -f "${musl_path}" ]; then
            printf '%s\n' /lib /usr/local/lib /usr/lib > "${musl_path}"
        fi
        grep -qxF "${PREFIX}/lib" "${musl_path}" || echo "${PREFIX}/lib" >> "${musl_path}"
    else
        mkdir -p /etc/ld.so.conf.d
        echo "${PREFIX}/lib" > /etc/ld.so.conf.d/bonsai-deps.conf
        ldconfig
    fi
}

# ---------------------------------------------------------------------------------------
# Build prerequisites
# ---------------------------------------------------------------------------------------
# The manylinux and musllinux images each ship part of what the build needs and lack a
# different part, so every prerequisite is probed and installed only when it is missing.
#
# NB: dnf aborts the *entire* transaction if any single package name is unknown, installing
# nothing while still looking plausible. perl-FindBin / perl-File-Compare / perl-File-Copy
# do NOT exist on AlmaLinux 8. So: only real names here, output not swallowed, and the
# modules are then verified directly rather than trusting the package manager's exit code.
log "Checking build prerequisites"
perl_missing=""
for module in IPC::Cmd Time::Piece Data::Dumper; do
    perl -M"${module}" -e '1' 2>/dev/null || perl_missing="${perl_missing} ${module}"
done

if [ -n "${perl_missing}" ]; then
    echo "  missing perl modules:${perl_missing}"
    if command -v dnf >/dev/null 2>&1; then
        dnf install -y perl-IPC-Cmd perl-Time-Piece perl-Pod-Html
    elif command -v apk >/dev/null 2>&1; then
        apk add --no-cache perl perl-utils
    else
        fail "no supported package manager to install:${perl_missing}"
    fi
    for module in IPC::Cmd Time::Piece Data::Dumper; do
        perl -M"${module}" -e '1' 2>/dev/null || fail "perl module ${module} still missing"
    done
fi
echo "  perl modules present."

# OpenLDAP builds its man pages as part of `make all`, which needs soelim from groff.
if ! command -v soelim >/dev/null 2>&1; then
    echo "  missing soelim"
    if command -v dnf >/dev/null 2>&1; then
        dnf install -y groff-base
    elif command -v apk >/dev/null 2>&1; then
        apk add --no-cache groff
    else
        fail "no supported package manager to install groff"
    fi
    command -v soelim >/dev/null 2>&1 || fail "soelim still missing after installing groff"
fi
echo "  soelim present."

# ---------------------------------------------------------------------------------------
# OpenSSL: shared, bundled by auditwheel
# ---------------------------------------------------------------------------------------
# Shared rather than statically linked into _bonsai.so on purpose: it keeps the wheel in the
# conventional auditwheel layout, and leaves the bundled crypto as an inspectable file that
# SBOM/CVE tooling can identify by version. (Static linking would hide it from that tooling
# without reducing the number of OpenSSL instances in the process, which is two either way.
# The interpreter's own OpenSSL is untouched and keeps serving the stdlib ssl module.)
#
# --libdir=lib     : otherwise OpenSSL installs to lib64 on x86_64 and lib on some other
#                    arches, which would make every downstream -L path arch-dependent.
# --openssldir     : a fallback only. No single value is correct on every distro (RHEL uses
#                    /etc/pki/tls and ships an empty /etc/ssl), so the CA bundle location is
#                    resolved at run time instead.
# no-dso          : MODULESDIR and ENGINESDIR are compiled into libcrypto as absolute paths
#                    under ${PREFIX} and are handed to dlopen() verbatim, with no search and
#                    no fallback. ${PREFIX} does not exist on the machine where the wheel is
#                    installed, and a host openssl.cnf naming a provider is enough to reach
#                    them, so they are load paths nothing owns. no-dso selects the DSO_NONE
#                    backend, a null DSO_METHOD, which leaves them as inert strings.
#                    Note what this does to the legacy provider, which DIGEST-MD5 needs for
#                    RC4: no-dso cascades into no-module, so the provider is linked into
#                    libcrypto as a built-in instead of being a separate ossl-modules file.
#                    That is what makes RC4 reachable here without any dlopen at all -- see
#                    the legacy-provider patch applied to Cyrus SASL below. no-legacy would
#                    remove it and cost DIGEST-MD5 its confidentiality layer.
log "Building OpenSSL ${OPENSSL_VERSION}"
cd "${BUILD_DIR}"
curl -fsSL "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" | tar xzf -
cd "openssl-${OPENSSL_VERSION}"
./Configure linux-"$(uname -m)" shared no-tests no-docs no-dso \
    --prefix="${PREFIX}" --libdir=lib --openssldir=/etc/ssl
make -j"${JOBS}"
make install_sw

# Register the library path now, before anything else is configured. The configure scripts
# that follow compile and then *run* small test programs linked against these libraries, and
# those fail with "cannot run C compiled programs" if the loader cannot resolve them.
register_library_path

# ---------------------------------------------------------------------------------------
# MIT Kerberos: shared, bundled by auditwheel
# ---------------------------------------------------------------------------------------
# Built here rather than installed from the base image, which would otherwise give the
# manylinux and musllinux wheels different Kerberos versions. Must precede Cyrus SASL, which
# needs these headers to build its GSSAPI mechanism.
# -rpath-link in LDFLAGS below: the linker resolves the transitive dependencies of the
# libraries built here through the loader search path, which musl keeps in a file that
# the linker does not read, so it must be named explicitly.
log "Building MIT Kerberos ${KRB5_VERSION}"
cd "${BUILD_DIR}"
curl -fsSL "https://kerberos.org/dist/krb5/${KRB5_VERSION%.*}/krb5-${KRB5_VERSION}.tar.gz" | tar xzf -
cd "krb5-${KRB5_VERSION}/src"
# --disable-nls: translated Kerberos messages are not worth a libintl dependency, and on musl
# dgettext lives outside libc, where krb5 does not add -lintl and fails to link.
./configure --prefix="${PREFIX}" --sysconfdir=/etc --localstatedir=/var \
    --enable-shared --disable-static \
    --without-ldap --without-tcl --without-readline --without-libedit \
    --disable-rpath --disable-nls \
    CPPFLAGS="-I${PREFIX}/include" \
    LDFLAGS="-L${PREFIX}/lib -Wl,-rpath-link,${PREFIX}/lib"

# Remove dynamic plugin loading, for the same reason OpenSSL is built no-dso: Kerberos
# compiles ${PREFIX}/lib/krb5/plugins and ${PREFIX}/lib/gss into libkrb5 and dlopen()s
# modules from there, the wheel ships none, and ${PREFIX} does not exist where the wheel is
# installed. Clearing USE_DLOPEN leaves util/support/plugins.c on its open_plugin_dummy()
# branch, which upstream maintains for platforms without dynamic loading; built-in modules
# go through k5_plugin_register and are unaffected.
#
# Edited in the generated header rather than passed to configure. USE_DLOPEN comes from an
# AC_SEARCH_LIBS feature test with no --disable switch, and presetting ac_cv_search_dlopen
# does suppress the define -- but the same conditional also sets DL_LIB, so -ldl drops off
# every link line and tests/gssapi/reload.c, which calls dlopen directly, fails to link.
sed -i 's|^#define USE_DLOPEN 1$|/* USE_DLOPEN cleared: see .ci/build-dependencies.sh */|' \
    include/autoconf.h
if grep -q '^#define USE_DLOPEN' include/autoconf.h; then
    fail "USE_DLOPEN survived in krb5 autoconf.h: dynamic plugin loading was not removed"
fi

make -j"${JOBS}"
make install

register_library_path

# ---------------------------------------------------------------------------------------
# Cyrus SASL: static archive, mechanisms compiled in
# ---------------------------------------------------------------------------------------
# This is the part that makes wheels possible at all, and it is easy to break silently.
#
# --enable-static --disable-shared
#     The static mechanism table (_sasl_static_plugins[] in lib/staticopen.h, consumed by
#     _sasl_load_plugins in lib/dlopen.c) is guarded by `#ifndef PIC`. A shared build has
#     PIC defined and therefore ignores the table entirely and dlopen()s a plugin directory
#     instead. That is exactly the failure this build exists to eliminate.
#
# CFLAGS=-fPIC, and deliberately NOT --with-pic
#     The archive still has to be linkable into a shared object, so it needs PIC code
#     generation. But --with-pic sets libtool's pic_mode=yes, which compiles with
#     $lt_prog_compiler_pic, and that variable carries `-DPIC` (see libtool.m4). Passing
#     --with-pic would therefore define the PIC macro and silently disable the static
#     mechanisms while looking like the obviously correct flag. -fPIC in CFLAGS gives PIC
#     codegen without defining the macro.
#
# -include time.h
#     2.1.28 (Feb 2022) is the newest release and predates GCC 14 promoting implicit function
#     declarations to errors; cram.c, digestmd5.c and saslutil.c call time()/clock() without
#     including <time.h>. Do NOT "fix" this with -Wno-implicit-function-declaration: an
#     implicitly declared time() is assumed to return int, which truncates time_t on 64-bit.
#
# --enable-ntlm
#     Off by default upstream, but bonsai documents and tests NTLM, and a source build on
#     Debian or Ubuntu gets it from libsasl2-modules, so a wheel without it would lose
#     working authentication. Its DES comes from libcrypto's low-level DES_* API rather
#     than EVP, so unlike DIGEST-MD5's RC4 it needs nothing from the legacy provider.
#
# DIGEST-MD5 keeps its full cipher set, so max_ssf stays 128 and auth-conf negotiates as it
#     does for a source build. RC4 fetches from OpenSSL's legacy provider, which is not
#     activated by default on any distribution, hence the provider patch below.
#
# -D_GNU_SOURCE for asprintf/memmem in the utils.
# --without-saslauthd --without-pwcheck : server-side daemons we do not ship, and they fail
#     to build for the same implicit-declaration reason.
log "Building Cyrus SASL ${CYRUS_SASL_VERSION} (static, mechanisms compiled in)"
cd "${BUILD_DIR}"
curl -fsSL "https://github.com/cyrusimap/cyrus-sasl/releases/download/cyrus-sasl-${CYRUS_SASL_VERSION}/cyrus-sasl-${CYRUS_SASL_VERSION}.tar.gz" | tar xzf -
cd "cyrus-sasl-${CYRUS_SASL_VERSION}"

# Upstream 887dbc0, released after 2.1.28. A DIGEST-MD5 cipher whose init fails leaves a NULL
# cipher context that the client installs anyway, so the bind succeeds and the first operation
# through the security layer dereferences it. The patch turns that into a bind failure.
patch -p1 < "${SOURCE_DIR}/.ci/patches/0001-digestmd5-handle-failed-cipher-init.patch"

# Activates OpenSSL 3's legacy provider, which supplies the RC4 ciphers. Not an upstream
# commit: Cyrus SASL has no provider handling at all, and distributions that keep DIGEST-MD5
# working on OpenSSL 3 carry an equivalent change of their own.
patch -p1 < "${SOURCE_DIR}/.ci/patches/0002-digestmd5-load-openssl-legacy-provider.patch"

./configure --prefix="${PREFIX}" \
    --enable-static --disable-shared \
    --enable-scram --enable-digest --enable-cram --enable-plain --enable-anon \
    --enable-ntlm \
    --enable-gssapi="${PREFIX}" --with-gss_impl=mit \
    --disable-otp --disable-srp --disable-sample \
    --without-dblib --without-saslauthd --without-pwcheck \
    --with-openssl="${PREFIX}" \
    CFLAGS="-fPIC -D_GNU_SOURCE -include time.h -I${PREFIX}/include" \
    LDFLAGS="-L${PREFIX}/lib -Wl,-rpath-link,${PREFIX}/lib" \
    LIBS="-lcrypto -lgssapi_krb5 -lkrb5"

# Cyrus SASL does not fail when it cannot find OpenSSL. It drops SCRAM entirely, prints a
# warning, and exits 0. A wheel built that way advertises mechanisms it does not have and
# fails only on the user's machine, at bind time, depending on which mechanism the server
# negotiates. The configure output is therefore treated as a hard gate that aborts the build.
log "Verifying Cyrus SASL configuration (it degrades silently and still exits 0)"
grep -q "SCRAM will be disabled" config.log && fail "SCRAM disabled: OpenSSL was not found by cyrus-sasl"
echo "  SCRAM enabled."

make -j"${JOBS}"
make install

sasl_symbols=$(nm "${PREFIX}/lib/libsasl2.a")
for mech in plain anonymous crammd5 digestmd5 scram external ntlm gssapiv2; do
    if [[ "${sasl_symbols}" != *" T ${mech}_client_plug_init"* ]]; then
        fail "mechanism ${mech} missing from libsasl2.a"
    fi
done
echo "  All eight client mechanisms present in libsasl2.a."

for cipher in enc_rc4 enc_des enc_3des; do
    if [[ "${sasl_symbols}" != *"${cipher}"* ]]; then
        fail "DIGEST-MD5 was built without ${cipher}: it cannot negotiate auth-conf"
    fi
done
if [[ "${sasl_symbols}" != *digestmd5_load_providers* ]]; then
    fail "DIGEST-MD5 has no provider load: RC4 will fetch from an inactive legacy provider"
fi
echo "  DIGEST-MD5 offers its full cipher set."

# ---------------------------------------------------------------------------------------
# OpenLDAP: shared, absorbing the static libsasl2
# ---------------------------------------------------------------------------------------
# LIBS is required here. Configure link-tests Cyrus SASL, and against a *static* libsasl2 that
# test only succeeds if the archive's own transitive dependencies are supplied. Omitting it
# makes configure report the very misleading "Could not locate Cyrus SASL".
#
# --whole-archive is deliberately NOT used. The _sasl_static_plugins[] reference chain pulls
# every mechanism object out of the archive on its own (verified). It would also break
# configure if placed in LDFLAGS, since it corrupts configure's own test compiles.
log "Building OpenLDAP ${OPENLDAP_VERSION} (shared, absorbing libsasl2.a)"
cd "${BUILD_DIR}"
curl -fsSL "https://www.openldap.org/software/download/OpenLDAP/openldap-release/openldap-${OPENLDAP_VERSION}.tgz" | tar xzf -
cd "openldap-${OPENLDAP_VERSION}"
./configure --prefix="${PREFIX}" --sysconfdir=/etc \
    --with-cyrus-sasl --with-tls=openssl \
    --disable-slapd --disable-backends --disable-overlays \
    --enable-shared --disable-static \
    CPPFLAGS="-I${PREFIX}/include" \
    LDFLAGS="-L${PREFIX}/lib -Wl,-rpath-link,${PREFIX}/lib" \
    LIBS="-lcrypto -ldl -lresolv -lgssapi_krb5 -lkrb5"
make depend
make -j"${JOBS}"
make install

# ---------------------------------------------------------------------------------------
# Verify the result before anything downstream trusts it
# ---------------------------------------------------------------------------------------
# The failure mode here is silent. A libldap that still wants a plugin directory builds and
# imports perfectly, then fails at bind time on the user's machine. These checks therefore
# inspect the produced binary directly.
log "Verifying libldap"
LIBLDAP=$(find "${PREFIX}/lib" -name 'libldap.so.*' -type f | head -1)
[ -n "${LIBLDAP}" ] || fail "libldap.so not found under ${PREFIX}/lib"

ldap_dynamic=$(readelf -d "${LIBLDAP}")
if [[ "${ldap_dynamic}" == *libsasl2* ]]; then
    fail "libldap still has a runtime libsasl2 dependency: the archive was not absorbed"
fi

ldap_undefined=$(nm -u -D "${LIBLDAP}")
if [[ "${ldap_undefined}" == *dlopen* || "${ldap_undefined}" == *dlsym* ]]; then
    fail "libldap imports dlopen/dlsym: runtime plugin loading was not eliminated"
fi

ldap_symbols=$(nm --defined-only "${LIBLDAP}")
for mech in plain anonymous crammd5 digestmd5 scram external ntlm gssapiv2; do
    if [[ "${ldap_symbols}" != *"${mech}_client_plug_init"* ]]; then
        fail "mechanism ${mech} was not absorbed into libldap"
    fi
done
# The build images ship their own OpenSSL and Kerberos, so a missing -L or a stale loader
# path resolves happily against those instead, producing a wheel that bundles whatever the
# image had rather than the pinned versions above. Nothing downstream would notice: the
# wheel imports, binds, and reports the wrong library versions only under inspection.
log "Verifying every bundled dependency resolves inside ${PREFIX}"
ldap_resolved=$(LD_LIBRARY_PATH="${PREFIX}/lib" ldd "${LIBLDAP}")
while read -r soname arrow target _; do
    [ "${arrow}" = "=>" ] || continue
    case "${soname}" in
        libssl*|libcrypto*|liblber*|libldap*|libgssapi_krb5*|libkrb5*|libk5crypto*|libcom_err*)
            case "${target}" in
                "${PREFIX}"/*) ;;
                *) fail "${soname} resolved to ${target}, not the build in ${PREFIX}" ;;
            esac
            echo "  ${soname} -> ${target}"
            ;;
    esac
done <<< "${ldap_resolved}"

# No bundled library may load code at run time. Each of them compiles an absolute plugin or
# module directory under ${PREFIX} into itself -- libldap's SASL_PATH, OpenSSL's MODULESDIR
# and ENGINESDIR, Kerberos's lib/krb5/plugins and lib/gss -- and dlopen()s from it verbatim,
# with no search and no fallback. ${PREFIX} does not exist on an installed system, so every
# one of those is a load path that nothing owns and that the wheel itself will never create.
# The capability is removed at build time rather than the paths relocated: libsasl2 is a
# static archive, OpenSSL is built no-dso, and Kerberos is built without USE_DLOPEN. All
# three are feature-test driven and would come back silently on a version bump, so assert it.
log "Verifying no bundled library can load code at run time"
for lib in "${PREFIX}"/lib/*.so.*; do
    [ -f "${lib}" ] && [ ! -L "${lib}" ] || continue
    soname=$(basename "${lib}")
    case "${soname}" in
        libssl*|libcrypto*|liblber*|libldap*|libgssapi_krb5*|libkrb5*|libk5crypto*|libcom_err*) ;;
        *) continue ;;
    esac
    if nm -u -D "${lib}" | grep -Eq '\b(dlopen|dlsym)\b'; then
        fail "${soname} imports dlopen/dlsym: it can still load code from ${PREFIX}"
    fi
    echo "  ${soname} - no dlopen/dlsym"
done

echo "  ${LIBLDAP}"
echo "  No libsasl2 dependency, no dlopen/dlsym imports, all eight mechanisms absorbed."

# Refresh the loader cache, which is what lets the wheel build link against the libldap and
# liblber installed above.
register_library_path

# Collect the upstream licenses. The wheel redistributes these libraries in binary form, and
# Cyrus SASL's license in particular requires acknowledgement in redistributions.
log "Collecting third-party licenses"
mkdir -p "${PREFIX}/licenses"
collect_license() {
    local name="$1" dir="$2" found=""
    for candidate in LICENSE LICENSE.txt COPYING COPYRIGHT NOTICE; do
        if [ -f "${dir}/${candidate}" ]; then
            cat "${dir}/${candidate}" >> "${PREFIX}/licenses/${name}.txt"
            found="yes"
        fi
    done
    [ -n "${found}" ] || fail "no license file found for ${name} in ${dir}"
    echo "  ${name}"
}
collect_license openssl    "${BUILD_DIR}/openssl-${OPENSSL_VERSION}"
collect_license cyrus-sasl "${BUILD_DIR}/cyrus-sasl-${CYRUS_SASL_VERSION}"
collect_license openldap   "${BUILD_DIR}/openldap-${OPENLDAP_VERSION}"
collect_license krb5       "${BUILD_DIR}/krb5-${KRB5_VERSION}"

# Record what was bundled, so the wheel build can report these versions at run time.
cat > "${PREFIX}/bundled-versions.env" <<EOF
BONSAI_BUNDLED_OPENSSL_VERSION=${OPENSSL_VERSION}
BONSAI_BUNDLED_CYRUS_SASL_VERSION=${CYRUS_SASL_VERSION}
BONSAI_BUNDLED_OPENLDAP_VERSION=${OPENLDAP_VERSION}
BONSAI_BUNDLED_KRB5_VERSION=${KRB5_VERSION}
EOF

log "Dependencies built into ${PREFIX}"
cat "${PREFIX}/bundled-versions.env"
