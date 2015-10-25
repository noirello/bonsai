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

static void
set_certificates(LDAP *ld, char *cacertdir, char *cacert, char *clientcert, char *clientkey) {

}

/* Finish the initialisation by checking the result of the separate thread for TLS.
   The `misc` parameter is a pointer to the thread's  data structure that contains the
   LDAP struct. The initialised LDAP struct is passed to the `ld` parameter. */
int
_ldap_finish_init_thread(char async, XTHREAD thread, int *timeout, void *misc, LDAP **ld) {
	int rc = -1;
	int retval = 0;
	SYSTEMTIME st;
	FILETIME ft;
	ULONGLONG start_time;
	ULONGLONG end_time;
	ldapInitThreadData *val = (ldapInitThreadData *)misc;

	GetSystemTime(&st);
	SystemTimeToFileTime(&st, &ft);
	/* Current time in 100-nanosec. */
	start_time = (((ULONGLONG)ft.dwHighDateTime) << 32) + ft.dwLowDateTime;

	/* Sanity check. */
	if (val == NULL || thread == NULL) return -1;

	if (async) {
		rc = WaitForSingleObject(thread, 10);
	} else {
		rc = WaitForSingleObject(thread, *timeout);
	}

	switch (rc) {
	case WAIT_TIMEOUT:
		if (async == 0) {
			TerminateThread(thread, -1);
			set_exception(NULL, LDAP_TIMEOUT);
			retval = -1;
			goto end;
		}
		return 0;
	case WAIT_OBJECT_0:
		if (async == 0 && *timeout != -1) {
			GetSystemTime(&st);
			SystemTimeToFileTime(&st, &ft);
			/* Current time in 100-nanosec. */
			end_time = (((ULONGLONG)ft.dwHighDateTime) << 32) + ft.dwLowDateTime;
			/* Deduct the passed time from the overall timeout. */
			*timeout -= (int)((end_time - start_time) / 10000);
			if (*timeout < 0) *timeout = 0;
		}
		if (val->retval != LDAP_SUCCESS) {
			/* The ldap_connect is failed. Set a Python error. */
			set_exception(NULL, val->retval);
			retval = -1;
			goto end;
		}
		/* Set the new LDAP struct. */
		*ld = val->ld;
		retval = 1;
		goto end;
	default:
		/* The thread is failed. */
		PyErr_BadInternalCall();
		retval = -1;
		goto end;
	}
end:
	/* Clean up the mess. */
	CloseHandle(thread);
	if (val->url) free(val->url);
	if (val->ca_cert) free(val->ca_cert);
	if (val->ca_cert_dir) free(val->ca_cert_dir);
	if (val->client_cert) free(val->client_cert);
	if (val->client_key) free(val->client_key);
	free(val);
	return retval;
}

static int WINAPI
ldap_thread_bind(void *params) {
	int rc = 0;
	char *binddn = NULL;
	ldap_conndata_t *data = (ldap_conndata_t *)params;
	sasl_defaults_t defaults;

	defaults.authcid = data->authcid;
	defaults.passwd = data->passwd;
	defaults.realm = data->realm;
	defaults.authzid = data->authzid;

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
_ldap_bind(LDAP *ld, ldap_conndata_t *info, LDAPMessage *result, int *msgid) {

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

static void
set_certificates(LDAP *ld, char *cacertdir, char *cacert, char *clientcert, char *clientkey) {
	const int true = 1;

	if (cacertdir == NULL || strcmp(cacertdir, "") != 0) {
		ldap_set_option(ld, LDAP_OPT_X_TLS_CACERTDIR, cacertdir);
	}
	if (cacert == NULL || strcmp(cacert, "") != 0) {
		ldap_set_option(ld, LDAP_OPT_X_TLS_CACERTFILE, cacert);
	}
	if (clientcert == NULL || strcmp(clientcert, "") != 0) {
		ldap_set_option(ld, LDAP_OPT_X_TLS_CERTFILE, clientcert);
	}
	if (clientkey == NULL || strcmp(clientkey, "") != 0) {
		ldap_set_option(ld, LDAP_OPT_X_TLS_KEYFILE, clientkey);
	}
	/* Force libldap to create new context for the connection. */
	ldap_set_option(ld, LDAP_OPT_X_TLS_NEWCTX, &true);
}

#if defined(__APPLE__)

/* Drop in replacement for pthread_mutext_timedlock for Mac OS X system. */
static int
_pthread_mutex_timedlock(pthread_mutex_t *mutex, struct timespec *abs_timeout) {
	int rc = -1;
	struct timeval timenow;
	struct timespec rest;

	/* Set 10ms for sleeping time. */
	rest.tv_sec = 0;
	rest.tv_nsec = 10000000;

	do {
		rc = pthread_mutex_trylock(mutex);

		gettimeofday(&timenow, NULL);

		if (timenow.tv_sec >= abs_timeout->tv_sec &&
				(timenow.tv_usec * 1000) >= abs_timeout->tv_nsec) {
			return ETIMEDOUT;
		}
		/* Little sleep to avoid hammering on the lock. */
		nanosleep(&rest, NULL);
	} while (rc == EBUSY);

	return rc;
}
#else
static int
_pthread_mutex_timedlock(pthread_mutex_t *mutex, struct timespec *abs_timeout) {
	return pthread_mutex_timedlock(mutex, abs_timeout);
}
#endif

/* Check on the initialisation thread and set cert policy. The `misc`
   parameter is never used (on Linux plaform). The pointer of initialised
   LDAP struct is passed to the `ld` parameter. Return 1 if the initialisation
   thread is finished, 0 if it is still in progress, and -1 for error. */
int
_ldap_finish_init_thread(char async, XTHREAD thread, int *timeout, void *misc, LDAP **ld) {
	int rc = 0;
	ldapInitThreadData *val = (ldapInitThreadData *)misc;
	struct timespec ts;
	struct timeval now;
	struct timespec rest;
	int wait_msec = 100;
	long long nanosecs = 0;
	unsigned long long start_time, end_time;
	int retval = 0;

	/* Sanity check. */
	if (val == NULL) return -1;

	if (async || *timeout == -1) {
		wait_msec = 100;
	} else {
		wait_msec = *timeout;
	}

	/* Create absolute time. */
	rc = gettimeofday(&now, NULL);
	if (rc != 0) {
		PyErr_BadInternalCall();
		retval = -1;
		goto end;
	}
	ts.tv_sec = now.tv_sec;
	nanosecs = (now.tv_usec + 1000UL * wait_msec) * 1000UL;
	while (nanosecs >= 1000000000) {
		/* Nanosecs are over 1 second. */
		ts.tv_sec += 1;
		nanosecs -= 1000000000;
	}
	ts.tv_nsec = (long)nanosecs;

	/* Waiting on thread to release the lock. */
	rc = _pthread_mutex_timedlock(val->mux, &ts);

	switch (rc) {
	case ETIMEDOUT:
		if (async == 0 && *timeout != -1) {
			set_exception(NULL, LDAP_TIMEOUT);
			if (val->ld) free(val->ld);
			retval = -1;
			goto end;
		}
		return 0;
	case 0:
		if (val->flag == 0) {
			/* Premature locking, thread function is not finished. */
			pthread_mutex_unlock(val->mux);
			/* Set 5ms for sleeping time. */
			rest.tv_sec = 0;
			rest.tv_nsec = 5000000;
			/* Take a nap, try to avoid constantly locking from the main thread. */
			nanosleep(&rest, NULL);
			if (*timeout != -1) {
				*timeout -= 5;
				if (*timeout < 0) *timeout = 0;
			}
			return 0;
		}
		/* Block until thread is finished, but if it's async already
		   waited enough on releasing the lock. */
		rc = pthread_join(thread, NULL);
		/* Thread is finished. */
		if (val->retval != LDAP_SUCCESS) {
			set_exception(NULL, val->retval);
			if (val->ld) free(val->ld);
			retval = -1;
			goto end;
		}
		if (*timeout != -1) {
			/* Calculate passed time in milliseconds. */
			start_time = (unsigned long long)(now.tv_sec) * 1000
					+ (unsigned long long)(now.tv_usec) / 1000;

			gettimeofday(&now, NULL);
			end_time = (unsigned long long)(now.tv_sec) * 1000
							+ (unsigned long long)(now.tv_usec) / 1000;
			/* Deduct the passed time from the overall timeout. */
			*timeout -= (end_time - start_time);
			if (*timeout < 0) *timeout = 0;
		}
		/* Set initialised LDAP struct pointer. */
		*ld = val->ld;
		retval = 1;
		goto end;
	default:
		/* The thread is failed. */
		PyErr_BadInternalCall();
		retval = -1;
		goto end;
	}
end:
	/* Clean-up. */
	if (val->url) free(val->url);
	if (val->ca_cert) free(val->ca_cert);
	if (val->ca_cert_dir) free(val->ca_cert_dir);
	if (val->client_cert) free(val->client_cert);
	if (val->client_key) free(val->client_key);
	pthread_mutex_destroy(val->mux);
	free(val->mux);
	free(val);
	return retval;
}

int
_ldap_bind(LDAP *ld, ldap_conndata_t *info, LDAPMessage *result, int *msgid) {
	int rc;
	LDAPControl	**sctrlsp = NULL;
	struct berval passwd;

	/* Mechanism is set, use SASL interactive bind. */
	if (strcmp(info->mech, "SIMPLE") != 0) {
		if (info->passwd == NULL) info->passwd = "";
		rc = ldap_sasl_interactive_bind(ld, info->binddn, info->mech, sctrlsp, NULL,
				LDAP_SASL_QUIET, sasl_interact, info, result, &(info->rmech), msgid);
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
			tmp = PyTuple_GetItem(creds, 3);
			authzid = PyObject2char(tmp);
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
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__)
static int WINAPI
#else
static void *
#endif
ldap_init_thread_func(void *params) {
	int rc = -1;
	const int version = LDAP_VERSION3;
	ldapInitThreadData *ldap_params = (ldapInitThreadData *)params;

	if (ldap_params == NULL) {
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__)
		return 0;
#else
		return NULL;
#endif
	}

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__)
#else
	pthread_mutex_lock(ldap_params->mux);
	/* Lock already acquired by this thread, flag can be set now. */
	ldap_params->flag = 1;
#endif
	rc = ldap_initialize(&(ldap_params->ld), ldap_params->url);
	if (rc != LDAP_SUCCESS) {
		ldap_params->retval = rc;
		goto end;
	}
	/* Set version to LDAPv3. */
	ldap_set_option(ldap_params->ld, LDAP_OPT_PROTOCOL_VERSION, &version);
	if (ldap_params->cert_policy != -1) {
		set_cert_policy(ldap_params->ld, ldap_params->cert_policy);
	}
	/* Set CA cert dir, CA cert and client cert. */
	set_certificates(ldap_params->ld, ldap_params->ca_cert_dir,
			ldap_params->ca_cert, ldap_params->client_cert,
			ldap_params->client_key);
	if (ldap_params->tls == 1) {
		/* Start TLS if it's required. */
		rc = ldap_start_tls_s(ldap_params->ld, NULL, NULL);
	}
	ldap_params->retval = rc;
	if (ldap_params->sock != -1) {
		/* Send a signal through an internal socketpair. */
		if (send(ldap_params->sock, "s", 1, 0) == -1) {
			/* Signalling is failed. */
			ldap_params->retval = -1;
		}
	}
end:
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__)
	return 0;
#else
	pthread_mutex_unlock(ldap_params->mux);
	return NULL;
#endif
}

/*  Create a platform-independent initialisation thread.
    On success it returns the thread, on failure it sets the
    `error` parameter to -1;
*/
XTHREAD
create_init_thread(void *param, int *error) {
	int rc = 0;
	XTHREAD thread;
	ldapInitThreadData *data = (ldapInitThreadData *)param;

	*error = 0;
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__)
	thread = (void *)CreateThread(NULL, 0, ldap_init_thread_func, (void *)data, 0, NULL);
	if (thread == NULL) rc = -1;
#else
	data->flag = 0;
	data->mux = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
	if (data->mux == NULL) {
		PyErr_NoMemory();
		*error = -1;
		return -1;
	}

	rc = pthread_mutex_init(data->mux, NULL);
	if (rc != 0) {
		PyErr_BadInternalCall();
		*error = -1;
		return -1;
	}

	rc = pthread_create(&thread, NULL, ldap_init_thread_func, data);
#endif
	if (rc != 0) *error = rc;

	return thread;
}
