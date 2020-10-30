FROM debian:buster-slim
LABEL maintainer="noirello@gmail.com"

# Create group and user
RUN groupadd -g 2000 ldap && useradd -m -u 2001 -g ldap ldap

RUN DEBIAN_FRONTEND=noninteractive apt update && apt upgrade -y
RUN DEBIAN_FRONTEND=noninteractive apt install -y \
    # For service tests and setting network delay
    procps iproute2 \
    # OpenLDAP server and utils.
    slapd ldap-utils libsasl2-modules-gssapi-mit sasl2-bin openssl \ 
    # Kerberos server and utils.
    krb5-admin-server krb5-kdc krb5-user \
    # Supervisor and Python 3
    supervisor python3

RUN chown -Rf ldap:ldap /etc/ldap/ /var/lib/ldap /var/lib/krb5kdc && chmod o+w /var/log/

USER ldap

# Setting Kerberos
COPY --chown=ldap:ldap ./.ci/krb5/kdc.conf ./.ci/krb5/kadm5.acl /etc/krb5kdc/
COPY --chown=ldap:ldap ./.ci/krb5/krb5.conf /etc/krb5.conf

# Copy the root CA cert and key.
COPY --chown=ldap:ldap ./tests/testenv/certs/cacert.pem /etc/ldap/certs/cacert.pem
COPY --chown=ldap:ldap ./tests/testenv/certs/cacert.key /home/ldap/cacert.key
# Copy client cert and key.
COPY --chown=ldap:ldap ./tests/testenv/certs/client.pem \
                       ./tests/testenv/certs/client.key \
                       /home/ldap/

# Generate server cert.
RUN openssl genrsa -out /etc/ldap/certs/server.key 2048 && \
    openssl req -new -key /etc/ldap/certs/server.key -out /home/ldap/server.csr -subj "/C=XX/CN=bonsai.test" && \
    openssl x509 -req -days 500 -in /home/ldap/server.csr -CA /etc/ldap/certs/cacert.pem \
    -CAkey /home/ldap/cacert.key -CAcreateserial -out /etc/ldap/certs/server.pem -sha256

# Copy the basic LDIF files  and test.jpeg into the container.
COPY ./tests/testenv/ldifs/base.ldif \
     ./tests/testenv/ldifs/users.ldif \
     ./tests/testenv/ldifs/settings.ldif \
     ./tests/testenv/ldifs/overlays.ldif \
     ./tests/testenv/ldifs/ppolicy.ldif \
     ./tests/testenv/ldifs/referrals.ldif \
     ./tests/testenv/ldifs/schema.ldif \
     ./tests/testenv/test.jpeg \
     /home/ldap/

COPY ./.ci/docker/start_slapd.sh /home/ldap/start_slapd.sh

RUN mkdir /home/ldap/run
VOLUME /home/ldap/run

USER root

# Set ownership and access righta for certs.
RUN chown -R ldap:ldap /etc/ldap/certs/ && chmod 644 /etc/ldap/certs/*

# Open LDAP, LDAPS, Kerberos and delay script ports.
EXPOSE 389 636 88 749 8000

COPY ./.ci/delay.py /root/delay.py
COPY ./.ci/docker/supervisord.conf /etc/supervisord.conf

COPY ./.ci/docker/entrypoint.sh /root/entrypoint.sh
RUN chmod +x /root/entrypoint.sh
RUN chmod +x /home/ldap/start_slapd.sh

ENTRYPOINT ["/root/entrypoint.sh"]
CMD ["supervisord", "-c", "/etc/supervisord.conf"]
