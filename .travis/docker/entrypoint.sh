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
    chown ldap:ldap /etc/openldap/ldap.keytab
    chown ldap:ldap /var/log/kadmin.log
    chown -Rf ldap:ldap /var/kerberos/krb5kdc/
    setcap 'cap_net_bind_service=+ep' /usr/sbin/krb5kdc # Allow to open port
    setcap 'cap_net_bind_service=+ep' /usr/sbin/kadmind
}

# Load the LDIF files and some schema into the server.
setLDAP () {
    /usr/sbin/slapd -u ldap -g ldap -h "ldap:// ldapi:// ldaps://"
    sleep 2
    ldapmodify -Y EXTERNAL -H ldapi:/// -f /home/ldap/settings.ldif
    # Load schemas.
    ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/schema/cosine.ldif
    ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/schema/inetorgperson.ldif
    ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/schema/nis.ldif
    ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/schema/ppolicy.ldif
    ldapmodify -Y EXTERNAL -H ldapi:/// -f /home/ldap/schema.ldif
    # Set overlays: allow vlv, server side sort and password policy.
    ldapmodify -Y EXTERNAL -H ldapi:/// -f /home/ldap/overlays.ldif
    # Create base entry and populate the dictionary.
    ldapadd -x -D "cn=admin,dc=bonsai,dc=test" -w p@ssword -H ldapi:/// -f /home/ldap/base.ldif
    ldapadd -x -D "cn=admin,dc=bonsai,dc=test" -w p@ssword -H ldapi:/// -f /home/ldap/users.ldif
    ldapadd -x -D "cn=admin,dc=bonsai,dc=test" -w p@ssword -H ldapi:/// -f /home/ldap/referrals.ldif
    # Set default password policy.
    ldapadd -x -D "cn=admin,dc=bonsai,dc=test" -w p@ssword -H ldapi:/// -f /home/ldap/ppolicy.ldif
    # Stop the slapd. 
    ps axf | grep /usr/sbin/slapd | grep -v grep | awk '{print "kill  " $1}'| sh
    setcap 'cap_net_bind_service=+ep' /usr/sbin/slapd
}

#Set passsword for SASL DIGEST-MD5.
setDigest () {
    echo "p@ssword" | saslpasswd2 -p admin
    echo "p@ssword" | saslpasswd2 -p chuck
}

setKerberos
setDigest
setLDAP

touch /root/.setup

exec "$@"
