#!/bin/bash
set -e

# This env var setting does not work with bullseye.
export KRB5_KTNAME='FILE:/etc/ldap/ldap.keytab'
exec /usr/sbin/slapd -u ldap -g ldap -h 'ldap:// ldaps:// ldapi://%2Fhome%2Fldap%2Frun%2Fldapi' -d -1
