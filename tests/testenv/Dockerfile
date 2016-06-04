FROM fedora:latest
MAINTAINER noirello <noirello@gmail.com>

RUN dnf update -y

# OpenLDAP server and utils.
RUN dnf install -y openldap openldap-servers openldap-clients cyrus-sasl-md5 cyrus-sasl-gssapi cyrus-sasl-ntlm openssl
# Kerberos server and utils.
RUN dnf install -y krb5-server krb5-libs krb5-workstation
RUN dnf install -y supervisor

# Setting Kerberos
COPY ./krb5/kdc.conf /var/kerberos/krb5kdc/kdc.conf
COPY ./krb5/kadm5.acl /var/kerberos/krb5kdc/kadm5.acl
COPY ./krb5/krb5.conf /etc/krb5.conf

# Create a password and a salt.
RUN echo "p@ssword" > /etc/openldap/certs/password
RUN echo "qweadhfkjwol4vb11yxadsa2389223qwqweeqwe" >> /etc/openldap/certs/noise.txt

# Create a new cert database.
RUN modutil -create -dbdir /etc/openldap/certs -force
# Well, this one makes no sense but works.
RUN modutil -dbdir /etc/openldap/certs -changepw 'NSS Certificate DB' -force -newpwfile /etc/openldap/certs/password -pwfile /etc/openldap/certs/password

# Copy the root CA cert and key.
COPY ./certs/cacert.pem /root/cacert.pem
COPY ./certs/cacert.key /root/cacert.key
# Copy client cert and key.
COPY ./certs/client.pem /root/client.pem
COPY ./certs/client.key /root/client.key

# Generate pkcs12 format from the root CA cert and key.
RUN openssl pkcs12 -export -in /root/cacert.pem -inkey /root/cacert.key -out /root/cacert.p12 -name OwnCARootCert  -passin pass:p@ssword -passout pass:p@ssword
# Import into the NSS database and set trust attributest. 
RUN pk12util -i /root/cacert.p12 -d /etc/openldap/certs -k /etc/openldap/certs/password -w /etc/openldap/certs/password
RUN certutil -M -n OwnCARootCert -t TCu,Cu,Tuw -d /etc/openldap/certs/

# Import client cert into the database.
RUN openssl pkcs12 -export -in /root/client.pem -inkey /root/client.key -out /root/client.p12 -name BonsaiTestUser -passin pass:p@ssword -passout pass:p@ssword
RUN pk12util -i /root/client.p12 -d /etc/openldap/certs -k /etc/openldap/certs/password -w /etc/openldap/certs/password

# Create a new cert for the server.
RUN certutil -S -n "slapd" -s "cn=bonsai.test" -c "OwnCARootCert" -t "u,u,u" -m 1001 -v 120 -d /etc/openldap/certs -z /etc/openldap/certs/noise.txt -f /etc/openldap/certs/password

RUN chmod 644 /etc/openldap/certs/*

RUN chown -Rf ldap:ldap /var/lib/ldap

# Copy the basic LDIF files into the container.
COPY ./ldifs/base.ldif /root/base.ldif
COPY ./ldifs/sasl.ldif /root/sasl.ldif
COPY ./ldifs/sssvlv.ldif /root/sssvlv.ldif
COPY ./test.jpeg /root/test.jpeg

# Open LDAP and LDAPS port.
EXPOSE 389 636
EXPOSE 88 749

COPY ./delay.py /root/delay.py

COPY ./supervisord.conf /etc/supervisord.conf

COPY ./entrypoint.sh /root/entrypoint.sh
ENTRYPOINT ["/root/entrypoint.sh"]
CMD ["supervisord", "-c", "/etc/supervisord.conf"]
