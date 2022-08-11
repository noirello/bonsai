#!/bin/bash

yum install -y zlib-devel

OPENSSL_VERSION="1.1.1q"
OPENLDAP_VERSION="2.6.3"
MIT_KRB5_VERSION="1.20"
CYRUS_SASL_VERSION="2.1.28"

SOURCE_DIR=$( cd "$(dirname "${BASH_SOURCE[0]}")"/.. ; pwd -P )

mkdir build-deps
cd build-deps/

curl -sL https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz | tar xzf -
cd openssl-${OPENSSL_VERSION}/
./config --prefix=/usr/local/ --openssldir=/usr/local/ zlib -fPIC shared
make depend
make
make install_sw
cd ..

curl -sL http://web.mit.edu/kerberos/dist/krb5/${MIT_KRB5_VERSION}/krb5-${MIT_KRB5_VERSION}.tar.gz | tar xzf -
cd krb5-${MIT_KRB5_VERSION}/src/
./configure --prefix=/usr/local/ CFLAGS=-fPIC
make
make install
cd ../..

curl -sL https://github.com/cyrusimap/cyrus-sasl/releases/download/cyrus-sasl-${CYRUS_SASL_VERSION}/cyrus-sasl-${CYRUS_SASL_VERSION}.tar.gz | tar xzf -
cd cyrus-sasl-${CYRUS_SASL_VERSION}/
./configure --prefix=/usr/local/ --enable-ntlm CFLAGS=-fPIC
make
make install

curl -sL https://www.openldap.org/software/download/OpenLDAP/openldap-release/openldap-${OPENLDAP_VERSION}.tgz | tar xzf -
cd openldap-${OPENLDAP_VERSION}/
./configure --prefix=/usr/local/ --with-tls=openssl --disable-slapd --enable-backends=no
make depend
make
make install

printf "[build_ext]\ninclude_dirs=/usr/local/include\nlibrary_dirs=/usr/local/lib" > ${SOURCE_DIR}/setup.cfg
