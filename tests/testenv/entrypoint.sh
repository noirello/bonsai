#!/bin/bash
set -e

# Check if the setup is already made. 
[ -f /root/.setup ] && exit 0

# Set Kerberos database.
setKerberos () {
    kdb5_util create -r BONSAI.TEST -s -W -P p@ssword
    kadmin.local -q "addprinc -pw p@ssword admin"
    kadmin.local -q "addprinc -pw p@ssword chuck"
    kadmin.local -q "ktadd -k /var/kerberos/krb5kdc/kadm5.keytab kadmin/admin"
    kadmin.local -q "ktadd -k /var/kerberos/krb5kdc/kadm5.keytab kadmin/changepw"
    kadmin.local -q "addprinc -randkey host/bonsai.test"
    kadmin.local -q "ktadd host/bonsai.test"
    kadmin.local -q "add_principal -randkey ldap/bonsai.test"
    kadmin.local -q "ktadd -keytab /etc/openldap/ldap.keytab ldap/bonsai.test"
}

# Load the LDIF files and some schema into the server.
setLDAP () {
    /usr/sbin/slapd -h "ldap:// ldapi:// ldaps://"
    sleep 2
    ldapmodify -Y EXTERNAL -H ldapi:/// -f /root/sasl.ldif
    ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/schema/cosine.ldif && ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/schema/inetorgperson.ldif && ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/schema/nis.ldif
    ldapadd -x -D "cn=admin,dc=bonsai,dc=test" -w p@ssword -H ldapi:/// -f /root/base.ldif
    # Allow VLV and server side sort.
    ldapmodify -Y EXTERNAL -H ldapi:/// -f /root/sssvlv.ldif
    # Stop the slapd. 
    ps axf | grep /usr/sbin/slapd | grep -v grep | awk '{print "kill  " $1}'| sh
}

#Set passsword for SASL DIGEST-MD5.
setDigest () {
    echo "p@ssword" | saslpasswd2 -p root
    echo "p@ssword" | saslpasswd2 -p chuck
}

setKerberos
setDigest
setLDAP

touch /root/.setup

exec "$@"
