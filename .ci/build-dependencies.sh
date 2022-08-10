#!/bin/bash

yum install -y zlib-devel krb5-devel pam-devel cyrus-sasl-devel

OPENSSL_VERSION="1.1.1q"
OPENLDAP_VERSION="2.6.3"

mkdir build
cd build/
curl -sL https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz | tar xzf -
cd openssl-${OPENSSL_VERSION}/
./config --prefix=/usr/local/ --openssldir=/usr/local/ zlib -fPIC shared
make depend
make
make install_sw
cd ..

curl -sL https://www.openldap.org/software/download/OpenLDAP/openldap-release/openldap-${OPENLDAP_VERSION}.tgz | tar xzf -
cd openldap-${OPENLDAP_VERSION}/
./configure --with-tls=openssl --disable-slapd --enable-backends=no
make depend
make
make install
