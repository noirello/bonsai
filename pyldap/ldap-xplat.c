#include "ldap-xplat.h"

#include "utils.h"

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__)

/* It does what it says: no verification on the server cert. */
BOOLEAN _cdecl noverify(PLDAP Connection, PCCERT_CONTEXT *ppServerCert) {
	return 1;
}

int LDAP_initialization(LDAP **ld, PyObject *url, int tls_option) {
	int rc;
	int portnum;
	char *hoststr = NULL;
	const int version = LDAP_VERSION3;
	const int tls_settings = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_SERVERNAME_CHECK;
	PyObject *scheme = PyObject_GetAttrString(url, "scheme");
	PyObject *host = PyObject_GetAttrString(url, "host");
	PyObject *port = PyObject_GetAttrString(url, "port");

	if (scheme == NULL || host == NULL || port == NULL) return -1;

	hoststr = PyObject2char(host);
	portnum = PyLong_AsLong(port);
	Py_DECREF(host);
	Py_DECREF(port);

	if (hoststr == NULL) return -1;

	if (PyUnicode_CompareWithASCIIString(scheme, "ldaps") == 0) {
		*ld = ldap_sslinit(hoststr, portnum, 1);
	} else {
		*ld = ldap_init(hoststr, portnum);
	}
	Py_DECREF(scheme);
	if (ld == NULL) return -1;
	ldap_set_option(*ld, LDAP_OPT_PROTOCOL_VERSION, &version);
	switch (tls_option) {
		case -1:
			/* Cert policy is not set, nothing to do.*/
			break;
		case 2:
		case 4:
			/* Cert policy is demand or try, then standard procedure. */
			break;
		case 0:
		case 3:
			/* Cert policy is never or allow, then set TLS settings. */
			ldap_set_option(*ld, 0x43, &tls_settings);
			ldap_set_option(*ld, LDAP_OPT_SERVER_CERTIFICATE, &noverify);
			break;
	}
	rc = ldap_connect(*ld, NULL);
	return rc;
}

int LDAP_bind_s(LDAP *ld, char *mech, char* binddn, char *pswstr, char *authcid, char *realm, char *authzid) {
	int rc;
	int method = -1;
	SEC_WINNT_AUTH_IDENTITY creds;

	creds.User = (unsigned char*)authcid;
	if (authcid != NULL) creds.UserLength = (unsigned long)strlen(authcid);
	else creds.UserLength = 0;
	creds.Password = (unsigned char*)pswstr;
	if (pswstr != NULL) creds.PasswordLength = (unsigned long)strlen(pswstr);
	else creds.PasswordLength = 0;
	/* Is SASL realm equivalent with Domain? */
	creds.Domain = (unsigned char*)realm;
	if (realm != NULL) creds.DomainLength = (unsigned long)strlen(realm);
	else creds.DomainLength = 0;
	creds.Flags = SEC_WINNT_AUTH_IDENTITY_ANSI;

	/* Mechanism is set use SEC_WINNT_AUTH_IDENTITY. */
	if (strcmp(mech, "SIMPLE") != 0) {
		if (strcmpi(mech, "DIGEST-MD5") == 0) {
			method = LDAP_AUTH_DIGEST;
		} else {
			method = LDAP_AUTH_SASL;
		}
		// TODO: it's depricated. Should use ldap_sasl_bind_sA instead?
		rc = ldap_bind_sA(ld, binddn, (PCHAR)&creds, method);
	} else {
		rc = ldap_simple_bind_sA(ld, binddn, pswstr);
	}

	return rc;
}

int LDAP_unbind(LDAP *ld) {
	return ldap_unbind(ld);
}

int LDAP_abandon(LDAP *ld, int msgid) {
	return ldap_abandon(ld, msgid);
}

#else

int LDAP_initialization(LDAP **ld, PyObject *url, int tls_option) {
	int rc;
	char *addrstr;
	const int version = LDAP_VERSION3;

	PyObject *addr = PyObject_CallMethod(url, "get_address", NULL);
	if (addr == NULL) return -1;
	addrstr = PyObject2char(addr);
	Py_DECREF(addr);
	if (addrstr == NULL) return -1;

	rc = ldap_initialize(ld, addrstr);
	if (rc != LDAP_SUCCESS) return rc;

	ldap_set_option(*ld, LDAP_OPT_PROTOCOL_VERSION, &version);
	if (tls_option != -1) {
		ldap_set_option(*ld, LDAP_OPT_X_TLS_REQUIRE_CERT, &tls_option);
		/* Set TLS option globally. */
		ldap_set_option(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT, &tls_option);
	}
	return rc;
}

int LDAP_bind(LDAP *ld, ldapConnectionInfo *info, LDAPMessage *result, int *msgid) {
	int rc;
	LDAPControl	**sctrlsp = NULL;
	struct berval passwd;
	const char *rmech = NULL;

	/* Mechanism is set, use SASL interactive bind. */
	if (strcmp(info->mech, "SIMPLE") != 0) {
		if (info->passwd == NULL) info->passwd = "";
		rc = ldap_sasl_interactive_bind(ld, info->binddn, info->mech, sctrlsp, NULL, LDAP_SASL_QUIET, sasl_interact, info, result, &rmech, msgid);
	} else {
		if (info->passwd  == NULL) {
			passwd.bv_len = 0;
		} else {
			passwd.bv_len = strlen(info->passwd );
		}
		passwd.bv_val = info->passwd ;
		rc = ldap_sasl_bind(ld, info->binddn, LDAP_SASL_SIMPLE, &passwd, sctrlsp, NULL, msgid);
	}

	return rc;
}

int LDAP_unbind(LDAP *ld) {
	return ldap_unbind_ext((ld), NULL, NULL);
}

int LDAP_abandon(LDAP *ld, int msgid ) {
	return ldap_abandon_ext(ld, msgid, NULL, NULL);
}

/*  This function is based on the OpenLDAP liblutil's sasl.c source
    file for creating a lutilSASLdefaults struct with default values based on
    the given parameters or client's options. */
void *
create_conn_info(LDAP *ld, char *mech, PyObject *creds) {
	ldapConnectionInfo *defaults = NULL;
	PyObject *tmp = NULL;
	char *authcid = NULL;
	char *authzid = NULL;
	char *binddn = NULL;
	char *passwd = NULL;
	char *realm = NULL;

	/* Get credential information, if it's given. */
	if (PyTuple_Check(creds) && PyTuple_Size(creds) > 1) {
		if (strcmp(mech, "SIMPLE") == 0) {
			tmp = PyTuple_GetItem(creds, 0);
			binddn = PyObject2char(tmp);
		} else {
			tmp = PyTuple_GetItem(creds, 0);
			authcid = PyObject2char(tmp);
			tmp = PyTuple_GetItem(creds, 2);
			realm = PyObject2char(tmp);
		}
		tmp = PyTuple_GetItem(creds, 1);
		passwd = PyObject2char(tmp);
	}

	defaults = ber_memalloc(sizeof(ldapConnectionInfo));
	if(defaults == NULL) return (void *)PyErr_NoMemory();

	defaults->mech = mech ? ber_strdup(mech) : NULL;
	defaults->realm = realm ? ber_strdup(realm) : NULL;
	defaults->authcid = authcid ? ber_strdup(authcid) : NULL;
	defaults->passwd = passwd ? ber_strdup(passwd) : NULL;
	defaults->authzid = authzid ? ber_strdup(authzid) : NULL;

	if (defaults->mech == NULL) {
		ldap_get_option(ld, LDAP_OPT_X_SASL_MECH, &defaults->mech);
	}
	if (defaults->realm == NULL) {
		ldap_get_option(ld, LDAP_OPT_X_SASL_REALM, &defaults->realm);
	}
	if (defaults->authcid == NULL) {
		ldap_get_option(ld, LDAP_OPT_X_SASL_AUTHCID, &defaults->authcid);
	}
	if (defaults->authzid == NULL) {
		ldap_get_option(ld, LDAP_OPT_X_SASL_AUTHZID, &defaults->authzid);
	}
	defaults->resps = NULL;
	defaults->nresps = 0;
	defaults->binddn = binddn;

	return defaults;
}

/*	This function is based on the lutil_sasl_interact() function, which can
    be found in the OpenLDAP liblutil's sasl.c source. I did some simplification
    after some google and stackoverflow reasearches, and hoping to not cause
    any problems. */
int
sasl_interact(LDAP *ld, unsigned flags, void *defs, void *in) {
    sasl_interact_t *interact = (sasl_interact_t*)in;
    const char *dflt = interact->defresult;
    ldapConnectionInfo *defaults = (ldapConnectionInfo *)defs;

	while (interact->id != SASL_CB_LIST_END) {
		switch(interact->id) {
			case SASL_CB_GETREALM:
				if (defaults) dflt = defaults->realm;
				break;
			case SASL_CB_AUTHNAME:
				if (defaults) dflt = defaults->authcid;
				break;
			case SASL_CB_PASS:
				if (defaults) dflt = defaults->passwd;
				break;
			case SASL_CB_USER:
				if (defaults) dflt = defaults->authzid;
				break;
			case SASL_CB_NOECHOPROMPT:
				break;
			case SASL_CB_ECHOPROMPT:
				break;
		}

		interact->result = (dflt && *dflt) ? dflt : (char*)"";
		interact->len = strlen( (char*)interact->result );

		interact++;
	}
	return LDAP_SUCCESS;
}
#endif
