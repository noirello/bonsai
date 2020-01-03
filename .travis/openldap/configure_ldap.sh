#!/bin/bash
set -e

generateCert () {
    openssl genrsa -out server.key 2048
    openssl req -new -key server.key -out server.csr -subj "/C=XX/CN=bonsai.test"
    openssl x509 -req -days 500 -in server.csr -CA ./tests/testenv/certs/cacert.pem -CAkey ./tests/testenv/certs/cacert.key -CAcreateserial -out server.pem -sha256
    echo "Server cert is generated..."

    mkdir -p /usr/local/var/openldap-certs

    cp ./tests/testenv/certs/cacert.pem /usr/local/var/openldap-certs/
    mv server.key /usr/local/var/openldap-certs/
    mv server.pem /usr/local/var/openldap-certs/
    echo "Moved certs..."
}

setLDAP () {
    sudo /usr/local/opt/openldap/libexec/slapd -h "ldap:// ldapi:// ldaps://"
    sleep 4
    echo "Slapd is started..."
    ps aux | grep slapd
    # Change jpeg file path.
    sed -i.bak "s|/home/ldap/test.jpeg|$TRAVIS_BUILD_DIR/tests/testenv/test.jpeg|g" ./tests/testenv/ldifs/base.ldif
    # Create base entry and populate the dictionary.
    ldapadd -x -D "cn=admin,dc=bonsai,dc=test" -w p@ssword -H ldap:/// -f ./tests/testenv/ldifs/base.ldif
    ldapadd -x -D "cn=admin,dc=bonsai,dc=test" -w p@ssword -H ldap:/// -f ./tests/testenv/ldifs/users.ldif
    ldapadd -x -D "cn=admin,dc=bonsai,dc=test" -w p@ssword -H ldap:/// -f ./tests/testenv/ldifs/referrals.ldif
    echo "Directory is populated..."
    # Set default password policy.
    ldapadd -x -D "cn=admin,dc=bonsai,dc=test" -w p@ssword -H ldap:/// -f ./tests/testenv/ldifs/ppolicy.ldif
    # Stop the slapd.
    sudo kill $(ps aux | grep /usr/local/opt/openldap/libexec/slapd | grep -v grep | awk '{print $2}')
    echo "Slapd is stopped..."
}

#Set passsword for SASL DIGEST-MD5.
setDigest () {
    echo "p@ssword" | sudo /usr/local/opt/cyrussasl/sbin/saslpasswd2 -p -c admin
    echo "p@ssword" | sudo /usr/local/opt/cyrussasl/sbin/saslpasswd2 -p -c chuck
    echo "Passwords are set..."
}

generateCert
setDigest
setLDAP