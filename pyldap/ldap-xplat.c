#include "ldap-xplat.h"

#include "utils.h"

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__)

/* It does what it says: no verification on the server cert. */
BOOLEAN _cdecl
noverify(PLDAP Connection, PCCERT_CONTEXT *ppServerCert) {
	return 1;
}

static void
set_cert_policy(LDAP *ld, int cert_policy) {
	const int tls_settings = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_SERVERNAME_CHECK;

	switch (cert_policy) {
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
		ldap_set_option(ld, 0x43, &tls_settings);
		ldap_set_option(ld, LDAP_OPT_SERVER_CERTIFICATE, &noverify);
		break;
	}
}

/* Finish the initialisation by checking the result of the separate thread for TLS.
   The `misc` parameter is a pointer to the thread's  data structure that contains the
   LDAP struct. The initialised LDAP struct is passed to the `ld` parameter. */
int
LDAP_finish_init(int async, void *thread, void *misc, LDAP **ld) {
	int rc = -1;

	/* Sanity check. */
	if (misc == NULL || thread == NULL) return -1;

	if (async) {
		rc = WaitForSingleObject((HANDLE)thread, 10);
	} else {
		rc = WaitForSingleObject((HANDLE)thread, INFINITE);
	}
	switch (rc) {
	case WAIT_TIMEOUT:
		break;
	case WAIT_OBJECT_0:
		if (((ldapThreadData *)misc)->retval != LDAP_SUCCESS) {
			/* The ldap_connect is failed. Set a Python error. */
			set_exception(NULL, ((ldapThreadData *)misc)->retval);
			return -1;
		}
		/* Set the new LDAP struct and clean up the mess. */
		*ld = ((ldapThreadData *)misc)->ld;
		free(misc);
		CloseHandle((HANDLE)thread);
		return 1;
	default:
		/* The thread is failed. */
		PyErr_BadInternalCall();
		return -1;
	}
	return 0;
}

static int
ldap_thread_bind(void *params) {
	int rc = 0;
	char *binddn = NULL;
	ldap_conndata_t *data = (ldap_conndata_t *)params;
	sasl_defaults_t defaults;

	defaults.authcid = data->authcid;
	defaults.passwd = data->passwd;
	defaults.realm = data->realm;

	if (strcmp(data->mech, "SIMPLE") != 0) {
		if (data->binddn == NULL) binddn = "";
		else binddn = data->binddn;
		rc = ldap_sasl_sspi_bind_s(data->ld, binddn, data->mech, NULL, NULL, &defaults);
	} else {
		rc = ldap_simple_bind_s(data->ld, data->binddn, data->passwd);
	}
	if (data->sock != -1) {
		/* Send a signal through an internal socketpair. */
		if (send(data->sock, "s", 1, 0) == -1) rc = -1;
	}

	return rc;
}

/* Create a separate thread for binding to the server. Results of asynchronous
SASL function call cannot be parsed (because of some kind of bug in WinLDAP). */
int
LDAP_bind(LDAP *ld, ldap_conndata_t *info, LDAPMessage *result, int *msgid) {

	info->ld = ld;
	info->thread = (void *)CreateThread(NULL, 0, ldap_thread_bind, (void *)info, 0, NULL);

	return LDAP_SUCCESS;
}

#else

static void
set_cert_policy(LDAP *ld, int cert_policy) {
	ldap_set_option(ld, LDAP_OPT_X_TLS_REQUIRE_CERT, &cert_policy);
	/* Set TLS option globally. */
	ldap_set_option(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT, &cert_policy);
}

/* Check on the initialisation thread and set cert policy. The `misc`
   parameter is never used (on Linux plaform). The pointer of initialised
   LDAP struct is passed to the `ld` parameter. Return 1 if the initialisation
   thread is finished, 0 if it is still in progress, and -1 for error. */
int
LDAP_finish_init(int async, void *thread, void *misc, LDAP **ld) {
	int rc = -1;
	ldapThreadData *val = (ldapThreadData *)misc;
	struct timespec ts;

	ts.tv_nsec = 100;
	ts.tv_sec = 0;

	/* Sanity check. */
	if (thread == NULL || val == NULL) return -1;

	if (async) {
		/* Polling thread state. Warning: this function is not portable (_np). */
		rc = pthread_timedjoin_np(*(pthread_t *)thread, NULL, &ts);
	} else {
		/* Block until thread is finished. */
		rc = pthread_join(*(pthread_t *)thread, NULL);
	}
	switch (rc) {
	case ETIMEDOUT:
		break;
	case 0:
		/* Thread is finished. */
		if (val->retval != LDAP_SUCCESS) {
			set_exception(NULL, val->retval);
			return -1;
		}
		/* Set initialised LDAP struct pointer. */
		*ld = val->ld;
		if (val->url != NULL) free(val->url);
		free(val);
		return 1;
	default:
		/* The thread is failed. */
		PyErr_BadInternalCall();
		return -1;
	}
	return 0;
}

int
LDAP_bind(LDAP *ld, ldap_conndata_t *info, LDAPMessage *result, int *msgid) {
	int rc;
	LDAPControl	**sctrlsp = NULL;
	struct berval passwd;

	/* Mechanism is set, use SASL interactive bind. */
	if (strcmp(info->mech, "SIMPLE") != 0) {
		if (info->passwd == NULL) info->passwd = "";
		rc = ldap_sasl_interactive_bind(ld, info->binddn, info->mech, sctrlsp, NULL, LDAP_SASL_QUIET, sasl_interact, info, result, &(info->rmech), msgid);
	} else {
		if (info->passwd  == NULL) {
			passwd.bv_len = 0;
		} else {
			passwd.bv_len = strlen(info->passwd );
		}
		passwd.bv_val = info->passwd ;
		rc = ldap_sasl_bind(ld, info->binddn, LDAP_SASL_SIMPLE, &passwd, sctrlsp, NULL, msgid);
	}

	ldap_msgfree(result);

	return rc;
}

/*	This function is based on the lutil_sasl_interact() function, which can
    be found in the OpenLDAP liblutil's sasl.c source. I did some simplification
    after some google and stackoverflow researches, and hoping to not cause
    any problems. */
int
sasl_interact(LDAP *ld, unsigned flags, void *defs, void *in) {
    sasl_interact_t *interact = (sasl_interact_t*)in;
    const char *dflt = interact->defresult;
	ldap_conndata_t *defaults = (ldap_conndata_t *)defs;

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

char *
_ldap_get_opt_errormsg(LDAP *ld) {
	char *opt = NULL;

	ldap_get_option(ld, LDAP_OPT_DIAGNOSTIC_MESSAGE, &opt);

	return opt;
}
#endif

/*  This function is based on the OpenLDAP liblutil's sasl.c source
file for creating a lutilSASLdefaults struct with default values based on
the given parameters or client's options. */
void *
create_conn_info(char *mech, SOCKET sock, PyObject *creds) {
	ldap_conndata_t *defaults = NULL;
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

	defaults = malloc(sizeof(ldap_conndata_t));
	if (defaults == NULL) return (void *)PyErr_NoMemory();

	defaults->mech = mech ? strdup(mech) : NULL;
	defaults->realm = realm;
	defaults->authcid = authcid;
	defaults->passwd = passwd;
	defaults->authzid = authzid;

	defaults->binddn = binddn;
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__)
	defaults->thread = NULL;
	defaults->ld = NULL;
	defaults->sock = sock;
#else
	defaults->resps = NULL;
	defaults->nresps = 0;
	defaults->rmech = NULL;
#endif

	return defaults;
}

/* Updates after initialised LDAP struct. */
int
update_conn_info(LDAP *ld, ldap_conndata_t *info) {
	return 0;
}

/* Dealloc an ldapConnectionInfo struct. */
void
dealloc_conn_info(ldap_conndata_t* info) {
	if (info->authcid) free(info->authcid);
	if (info->authzid) free(info->authzid);
	if (info->binddn) free(info->binddn);
	if (info->mech) free(info->mech);
	if (info->passwd) free(info->passwd);
	if (info->realm) free(info->realm);
	free(info);
}

/* Thread function. The ldap_initialize function opens the LDAP client's
config file on Unix and ldap_start_tls_s blocks for create SSL context on Windows,
thus to avoid the I/O blocking in the main (Python) thread the initialisation
is done in a separate (POSIX and Windows) thread. A signal is sent through an
internal socketpair when the thread is finished, thus select() can be used on
the socket descriptor. */
void *
ldap_init_thread(void *params) {
	int rc = -1;
	const int version = LDAP_VERSION3;
	ldapThreadData *ldap_params = (ldapThreadData *)params;

	if (ldap_params != NULL) {
		rc = ldap_initialize(&(ldap_params->ld), ldap_params->url);
		if (rc != LDAP_SUCCESS) {
			ldap_params->retval = rc;
			return NULL;
		}
		/* Set version to LDAPv3. */
		ldap_set_option(ldap_params->ld, LDAP_OPT_PROTOCOL_VERSION, &version);
		if (ldap_params->cert_policy != -1) {
			set_cert_policy(ldap_params->ld, ldap_params->cert_policy);
		}
		if (ldap_params->tls == 1) {
			/* Start TLS if it's required. */
			rc = ldap_start_tls_s(ldap_params->ld, NULL, NULL);
		}
		ldap_params->retval = rc;
		if (ldap_params->sock != -1) {
			/* Send a signal through an internal socketpair. */
			if (send(ldap_params->sock, "s", 1, 0) == -1) {
				/* Signaling is failed. */
				ldap_params->retval = -1;
			}
		}
	}
	return NULL;
}

/* Initialise an LDAP struct, and create a separate thread for building up TLS connection.
The thread's pointer and the data struct's pointer that contains the LDAP struct is
passed to the `thread` and `misc` parameters respectively. */
int
LDAP_start_init(PyObject *url, int has_tls, int cert_policy, SOCKET sock, void **thread, void **misc) {
	int rc = 0;
        char *addrstr = NULL;
	ldapThreadData *data = NULL;
	PyObject *addr = NULL;

	data = (ldapThreadData *)malloc(sizeof(ldapThreadData));
	if (data == NULL) return -1;

	/* Get URL address information from the LDAPClient's LDAPURL object. */
	addr = PyObject_CallMethod(url, "get_address", NULL);
	if (addr == NULL) return -1;
	addrstr = PyObject2char(addr);
	Py_DECREF(addr);
	if (addrstr == NULL) return -1;

	data->ld = NULL;
	data->url = addrstr;
	data->tls = has_tls;
	data->cert_policy = cert_policy;
	data->sock = sock;
	/* Create the separate thread. */
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__)
	*thread = (void *)CreateThread(NULL, 0, (int(*)(void*))&ldap_init_thread, (void *)data, 0, NULL);
	if (*thread == NULL) {
		free(data);
		PyErr_BadInternalCall();
		return -1;
	}
#else
        *thread = (pthread_t *)malloc(sizeof(pthread_t));
	if (*thread == NULL) {
		free(data);
		PyErr_NoMemory();
		return -1;
	}
	rc = pthread_create((pthread_t *)thread, NULL, ldap_init_thread, data);
#endif
	*misc = (void *)data;
	return rc;
}
