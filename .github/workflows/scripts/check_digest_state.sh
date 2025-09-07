#!/usr/bin/env bash

/usr/local/opt/openldap/bin/ldapwhoami -Y DIGEST-MD5 -H ldap://bonsai.test -U admin -w p@ssword

# This means SIGSEGV
if [ $? -eq 139 ]; then
    echo "WARNING: Simple ldapwhoami with DIGEST-MD5 failed, setting BONSAI_NO_SSF env var"
    echo "BONSAI_NO_SSF=1" >> $GITHUB_ENV
    # Rerun the command with SSF turned off
    /usr/local/opt/openldap/bin/ldapwhoami -Y DIGEST-MD5 -O maxssf=0 -H ldap://bonsai.test -U admin -w p@ssword
else
    echo "INFO: Simple ldapwhoami with DIGEST-MD5 has been succesful"
fi