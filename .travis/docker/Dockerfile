FROM fedora:latest
LABEL maintainer="noirello@gmail.com"

# Create group and user
RUN groupadd -g 2000 ldap && useradd -m -u 2001 -g ldap ldap

RUN dnf update -y

# For service tests and setting etwork delay
RUN dnf install -y procps iproute kernel-modules-extra
# OpenLDAP server and utils.
RUN dnf install -y openldap openldap-servers openldap-clients cyrus-sasl-md5 cyrus-sasl-gssapi cyrus-sasl-ntlm openssl
# Kerberos server and utils.
RUN dnf install -y krb5-server krb5-libs krb5-workstation
RUN dnf install -y supervisor


RUN chown -Rf ldap:ldap /etc/openldap/
RUN chown -Rf ldap:ldap /var/lib/ldap
RUN chown -Rf ldap:ldap /var/kerberos/
RUN chmod o+w /var/log/

USER ldap

# Setting Kerberos
COPY ./.travis/krb5/kdc.conf /var/kerberos/krb5kdc/kdc.conf
COPY ./.travis/krb5/kadm5.acl /var/kerberos/krb5kdc/kadm5.acl
COPY ./.travis/krb5/krb5.conf /etc/krb5.conf

# Create a password and a salt.
RUN echo "p@ssword" > /etc/openldap/certs/password
RUN echo "qweadhfkjwol4vb11yxadsa2389223qwqweeqwe" >> /etc/openldap/certs/noise.txt

# Create a new cert database.
RUN modutil -create -dbdir /etc/openldap/certs -force

# Copy the root CA cert and key.
COPY ./tests/testenv/certs/cacert.pem /home/ldap/cacert.pem
COPY ./tests/testenv/certs/cacert.key /home/ldap/cacert.key
# Copy client cert and key.
COPY ./tests/testenv/certs/client.pem /home/ldap/client.pem
COPY ./tests/testenv/certs/client.key /home/ldap/client.key

# Generate pkcs12 format from the root CA cert and key.
RUN openssl pkcs12 -export -in /home/ldap/cacert.pem -inkey /home/ldap/cacert.key -out /home/ldap/cacert.p12 -name OwnCARootCert  -passin pass:p@ssword -passout pass:p@ssword
# Import into the NSS database and set trust attributest. 
RUN pk12util -i /home/ldap/cacert.p12 -d /etc/openldap/certs -k /etc/openldap/certs/password -w /etc/openldap/certs/password
RUN certutil -M -n OwnCARootCert -t TCu,Cu,Tuw -d /etc/openldap/certs/

# Import client cert into the database.
RUN openssl pkcs12 -export -in /home/ldap/client.pem -inkey /home/ldap/client.key -out /home/ldap/client.p12 -name BonsaiTestUser -passin pass:p@ssword -passout pass:p@ssword
RUN pk12util -i /home/ldap/client.p12 -d /etc/openldap/certs -k /etc/openldap/certs/password -w /etc/openldap/certs/password

# Create a new cert for the server.
RUN certutil -S -n "slapd" -s "cn=bonsai.test" -c "OwnCARootCert" -t "u,u,u" -m 1001 -v 120 -d /etc/openldap/certs -z /etc/openldap/certs/noise.txt -f /etc/openldap/certs/password

RUN chmod 644 /etc/openldap/certs/*

# Copy the basic LDIF files into the container.
COPY ./tests/testenv/ldifs/base.ldif /home/ldap/base.ldif
COPY ./tests/testenv/ldifs/users.ldif /home/ldap/users.ldif
COPY ./tests/testenv/ldifs/sasl.ldif /home/ldap/sasl.ldif
COPY ./tests/testenv/ldifs/overlays.ldif /home/ldap/overlays.ldif
COPY ./tests/testenv/ldifs/ppolicy.ldif /home/ldap/ppolicy.ldif
COPY ./tests/testenv/ldifs/referrals.ldif /home/ldap/referrals.ldif
COPY ./tests/testenv/test.jpeg /home/ldap/test.jpeg

RUN mkdir /home/ldap/run
COPY ./.travis/docker/start_slapd.sh /home/ldap/start_slapd.sh

USER root

# Open LDAP and LDAPS port.
EXPOSE 389 636
EXPOSE 88 749

COPY ./.travis/delay.py /root/delay.py

COPY ./.travis/docker/supervisord.conf /etc/supervisord.conf

COPY ./.travis/docker/entrypoint.sh /root/entrypoint.sh
ENTRYPOINT ["/root/entrypoint.sh"]
CMD ["supervisord", "-c", "/etc/supervisord.conf"]
