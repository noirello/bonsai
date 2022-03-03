#include "ldap-xplat.h"

#include "utils.h"

#ifdef WIN32

/* It does what it says: no verification on the server cert. */
BOOLEAN _cdecl
noverify(PLDAP Connection, PCCERT_CONTEXT *ppServerCert) {
    return 1;
}

static void
set_cert_policy(LDAP *ld, int cert_policy) {
    const int tls_settings = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_SERVERNAME_CHECK;

    DEBUG("set_cert_policy (ld:%p, cert_policy:%d)", ld, cert_policy);
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

    DEBUG("_ldap_finish_init_thread (async:%d, thread:%p, timeout:%d, misc:%p)",
        async, thread, *timeout, misc);
    if (async) {
        rc = WaitForSingleObject(thread, 10);
    } else {
        rc = WaitForSingleObject(thread, *timeout);
    }

    switch (rc) {
    case WAIT_TIMEOUT:
        if (async == 0) {
            TerminateThread(thread, -1);
            CloseHandle(thread);
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
    free(val->url);
    free(val->sasl_sec_props);
    free(val);
    return retval;
}

static int WINAPI
ldap_thread_bind(void *params) {
    int rc = 0;
    char *binddn = NULL;
    ldap_conndata_t *data = (ldap_conndata_t *)params;
    sasl_defaults_t defaults;

    DEBUG("ldap_thread_bind (params:%p)", params);
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
_ldap_bind(LDAP *ld, ldap_conndata_t *info, char ppolicy, LDAPMessage *result, int *msgid) {

    DEBUG("_ldap_bind (ld:%p, info:%p, ppolicy:%d, result:%p, msgid:%d)",
            ld, info, ppolicy, result, *msgid);
    info->ld = ld;
    info->thread = (void *)CreateThread(NULL, 0, ldap_thread_bind, (void *)info, 0, NULL);

    return LDAP_SUCCESS;
}

int
_ldap_parse_passwordpolicy_control(LDAP *ld, LDAPControl **ctrls, ber_int_t *expire,
    ber_int_t *grace, unsigned int *error) {
    return ldap_parse_passwordpolicy_control(ld, ctrls, expire, grace, error);
}

void 
_ldap_control_free(LDAPControl *ctrl) {
    free(ctrl->ldctl_value.bv_val);
    free(ctrl);
}

#else

#ifdef HAVE_KRB5

static int
create_krb5_cred(krb5_context ctx, char *realm, char *user, char *password,
                 char *ktname, krb5_ccache *ccache, gss_cred_id_t *gsscred,
                 char **errmsg) {
    int rc = 0, len = 0;
    unsigned int minor_stat = 0, major_stat = 0;
    const char *errmsg_tmp = NULL;
    const char *cctype = NULL;
    char *cname = NULL;
    krb5_ccache defcc = NULL;
    krb5_creds creds;
    krb5_principal princ = NULL;
    krb5_keytab keytab = NULL;
    gss_key_value_element_desc elems[2];
    gss_key_value_set_desc store;
    gss_name_t sname = NULL;
    gss_buffer_desc pr_name;

    pr_name.value = NULL;
    pr_name.length = 0;

    store.count = 0;
    store.elements = elems;

    if (user == NULL || realm == NULL) return 1;
    len = strlen(realm);

    if (len == 0 || strlen(user) == 0) return 0;

    DEBUG("create_krb5_cred (ctx:%p, realm:%s, user:%s, password:%s, ktname: %s,"
        " ccache:%p, gsscred:%p)", ctx, realm, user, "****", ktname, ccache, gsscred);

    rc = krb5_cc_default(ctx, &defcc);
    if (rc != 0) goto end;

    cctype = krb5_cc_get_type(ctx, defcc);

    rc = krb5_cc_new_unique(ctx, cctype, NULL, ccache);
    if (rc != 0) goto end;

    rc = krb5_build_principal(ctx, &princ, len, realm, user, NULL);
    if (rc != 0) goto end;

    rc = krb5_cc_initialize(ctx, *ccache, princ);
    if (rc != 0) goto end;

    if (password != NULL && strlen(password) > 0) {
        rc = krb5_get_init_creds_password(ctx, &creds, princ, password,
                                          0, NULL, 0, NULL, NULL);
        if (rc != 0) goto end;

        rc = krb5_cc_store_cred(ctx, *ccache, &creds);
        if (rc != 0) goto end;

        rc = krb5_cc_get_full_name(ctx, *ccache, &cname);
        if (rc != 0) goto end;
        
        store.elements[store.count].key = "ccache";
        store.elements[store.count].value = cname;
        store.count++;
    } else if (ktname != NULL && strlen(ktname) > 0) {
        rc = krb5_kt_resolve(ctx, ktname, &keytab);
        if (rc != 0) goto end;

        rc = krb5_get_init_creds_keytab(ctx, &creds, princ, keytab, 0, NULL, NULL);
        if (rc != 0) goto end;
        
        rc = krb5_cc_store_cred(ctx, *ccache, &creds);
        if (rc != 0) goto end;

        rc = krb5_cc_get_full_name(ctx, *ccache, &cname);
        if (rc != 0) goto end;

        store.elements[store.count].key = "client_keytab";
        store.elements[store.count].value = ktname;
        store.count++;

        store.elements[store.count].key = "ccache";
        store.elements[store.count].value = cname;
        store.count++;

        rc = krb5_unparse_name(ctx, princ, (char**)&pr_name.value);
        if (rc != 0) goto end;
        pr_name.length = strlen(pr_name.value);

        major_stat = gss_import_name(&minor_stat, &pr_name,
                                     GSS_KRB5_NT_PRINCIPAL_NAME, &sname);
        if (major_stat != 0) goto end;
    }

    // Does not work with GSS-SPENGO.
    //major_stat = gss_krb5_import_cred(&minor_stat, *ccache, princ, NULL, gsscred);
    major_stat = gss_acquire_cred_from(&minor_stat, sname, 0, GSS_C_NO_OID_SET,
                                       GSS_C_INITIATE, &store, gsscred,
                                       NULL, NULL);

end:
    if (keytab != NULL) krb5_kt_close(ctx, keytab);
    if (princ != NULL) krb5_free_principal(ctx, princ);
    if (defcc != NULL) krb5_cc_close(ctx, defcc);
    if (cname != NULL) free(cname);
    if (pr_name.value != NULL) krb5_free_unparsed_name(ctx, pr_name.value);
    if (sname != NULL) {
        major_stat = gss_release_name(&minor_stat, &sname);
    }

    if (rc != 0) {
        /* Create error message with the error code. */
        errmsg_tmp = krb5_get_error_message(ctx, rc);
        if (errmsg != NULL && errmsg_tmp != NULL) {
            len = strlen(errmsg_tmp) + 26;
            *errmsg = (char *)malloc(len);
            if (*errmsg == NULL) {
                krb5_free_error_message(ctx, errmsg_tmp);
                return -1;
            }
            snprintf(*errmsg, len,"%s. (KRB5_ERROR 0x%08x)", errmsg_tmp, rc);
        }
        krb5_free_error_message(ctx, errmsg_tmp);
    }
    if (major_stat != 0) return major_stat;
    return rc;
}

static int
remove_krb5_cred(krb5_context ctx, krb5_ccache ccache, gss_cred_id_t *gsscred) {
    int rc = 0;
    unsigned int minor_stat = 0;

    DEBUG("remove_krb5_cred (ctx:%p, cchache:%p, gsscred:%p)",
        ctx, ccache, gsscred);
    rc = gss_release_cred(&minor_stat, gsscred);
    if (rc != 0) return minor_stat;

    if (ccache != NULL) rc = krb5_cc_destroy(ctx, ccache);
    if (ctx != NULL) krb5_free_context(ctx);

    return rc;
}

#endif

static void
set_cert_policy(LDAP *ld, int cert_policy) {
    DEBUG("set_cert_policy (ld:%p, cert_policy:%d)", ld, cert_policy);
    ldap_set_option(ld, LDAP_OPT_X_TLS_REQUIRE_CERT, &cert_policy);
    /* Set TLS option globally. */
    ldap_set_option(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT, &cert_policy);
}

#ifdef MACOSX

/* Drop in replacement for pthread_mutext_timedlock for Mac OS X system. */
static int
_pthread_mutex_timedlock(pthread_mutex_t *mutex, struct timespec *abs_timeout) {
    int rc = -1;
    struct timeval timenow;
    struct timespec rest;

    /* Set 10ms for sleeping time. */
    rest.tv_sec = 0;
    rest.tv_nsec = 10000000;

    DEBUG("%s", "_pthread_mutex_timedlock");
    while ((rc = pthread_mutex_trylock(mutex)) == EBUSY) {

        gettimeofday(&timenow, NULL);

        if (timenow.tv_sec > abs_timeout->tv_sec || 
            (timenow.tv_sec == abs_timeout->tv_sec &&
            (timenow.tv_usec * 1000) >= abs_timeout->tv_nsec)) {
            return ETIMEDOUT;
        }
        /* Little sleep to avoid hammering on the lock. */
        nanosleep(&rest, NULL);
    }

    return rc;
}
#else
static int
_pthread_mutex_timedlock(pthread_mutex_t *mutex, struct timespec *abs_timeout) {
    DEBUG("%s", "_pthread_mutex_timedlock");
    return pthread_mutex_timedlock(mutex, abs_timeout);
}
#endif

/* Check on the initialisation thread and set cert policy. The `misc`
   parameter is never used (on Linux platform). The pointer of initialised
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

    DEBUG("_ldap_finish_init_thread (async:%d, thread:%lu, timeout:%d, misc:%p)",
            async, thread, *timeout, misc);
    if (async) {
        wait_msec = 100;
    } else if (*timeout == -1) {
        /* When no timeout is set, then set 60 seconds for waiting on thread. */
        wait_msec = 60000;
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
        if (async == 0) {
            pthread_cancel(thread);
            set_exception(NULL, LDAP_TIMEOUT);
            free(val->ld);
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
#ifdef HAVE_KRB5
            if (val->info->errmsg != NULL) {
                PyObject *error = get_error_by_code(0x31);
                if (error == NULL) goto end;
                PyErr_SetString(error, val->info->errmsg);
                Py_DECREF(error);
            } else {
                set_exception(NULL, val->retval);
            }
#else
            set_exception(NULL, val->retval);
#endif
            free(val->ld);
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
    free(val->url);
    free(val->sasl_sec_props);
    pthread_mutex_destroy(val->mux);
    free(val->mux);
    free(val);
    return retval;
}

int
_ldap_bind(LDAP *ld, ldap_conndata_t *info, char ppolicy, LDAPMessage *result, int *msgid) {
    int rc;
    LDAPControl **server_ctrls = NULL;
    LDAPControl *ppolicy_ctrl = NULL;
    struct berval passwd;

    DEBUG("_ldap_bind (ld:%p, info:%p, ppolicy:%d, result:%p, msgid:%d)",
            ld, info, ppolicy, result, *msgid);
    if (ppolicy == 1) {
        rc = ldap_create_passwordpolicy_control(ld, &ppolicy_ctrl);
        if (rc != LDAP_SUCCESS) return rc;

        server_ctrls = (LDAPControl **)malloc(sizeof(LDAPControl *) * (1 + 1));
        if (server_ctrls == NULL) return LDAP_NO_MEMORY;

        server_ctrls[0] = ppolicy_ctrl;
        server_ctrls[1] = NULL;
    }

    /* Mechanism is set, use SASL interactive bind. */
    if (strcmp(info->mech, "SIMPLE") != 0) {
        if (info->passwd == NULL) info->passwd = "";
        rc = ldap_sasl_interactive_bind(ld, info->binddn, info->mech, server_ctrls, NULL,
                LDAP_SASL_QUIET, sasl_interact, info, result, &(info->rmech), msgid);
    } else {
        if (info->passwd == NULL) {
            passwd.bv_len = 0;
        } else {
            passwd.bv_len = strlen(info->passwd);
        }
        passwd.bv_val = info->passwd;
        rc = ldap_sasl_bind(ld, info->binddn, LDAP_SASL_SIMPLE, &passwd, server_ctrls,
                NULL, msgid);
    }

    if (ppolicy_ctrl != NULL) ldap_control_free(ppolicy_ctrl);

    free(server_ctrls);
    ldap_msgfree(result);

    return rc;
}

/*  This function is based on the lutil_sasl_interact() function, which can
    be found in the OpenLDAP liblutil's sasl.c source. I did some simplification
    after some google and stackoverflow researches, and hoping to not cause
    any problems. */
int
sasl_interact(LDAP *ld, unsigned flags, void *defs, void *in) {
    sasl_interact_t *interact = (sasl_interact_t*)in;
    const char *dflt = interact->defresult;
    ldap_conndata_t *defaults = (ldap_conndata_t *)defs;

    DEBUG("sasl_interact (ld:%p, flags:%u, defs:%p, in:%p)", ld, flags, defs, in);
#ifdef HAVE_KRB5
    int rc = 0;
    if (defaults->request_tgt == 1) {
        rc = ldap_set_option(ld, LDAP_OPT_X_SASL_GSS_CREDS,
            (void *)defaults->gsscred);
        if (rc != 0) return -1;
    }
#endif
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

    if (ld == NULL) return NULL;
    ldap_get_option(ld, LDAP_OPT_DIAGNOSTIC_MESSAGE, &opt);

    return opt;
}

int
_ldap_parse_passwordpolicy_control(LDAP *ld, LDAPControl *ctrl,
    ber_int_t *expire, ber_int_t *grace, unsigned int *error) {

    if (ctrl == NULL) return LDAP_CONTROL_NOT_FOUND;

    return ldap_parse_passwordpolicy_control(ld, ctrl, expire, grace, error);

}

void
_ldap_control_free(LDAPControl *ctrl) {
    ldap_control_free(ctrl);
}

#endif

/*  This function is based on the OpenLDAP liblutil's sasl.c source
file for creating a lutilSASLdefaults struct with default values based on
the given parameters or client's options. */
void *
create_conn_info(char *mech, SOCKET sock, PyObject *creds) {
    ldap_conndata_t *defaults = NULL;
    char *authcid = NULL;
    char *authzid = NULL;
    char *binddn = NULL;
    char *passwd = NULL;
    char *realm = NULL;
    char *ktname = NULL;

    DEBUG("create_conn_info (mech:%s, sock:%d, creds:%p)", mech, (int)sock, creds);
    /* Get credential information, if it's given. */
    if (PyDict_Check(creds)) {
        if (strcmp(mech, "SIMPLE") == 0) {
            binddn = PyObject2char(PyDict_GetItemString(creds, "user"));
        } else {
            authcid = PyObject2char(PyDict_GetItemString(creds, "user"));
            realm = PyObject2char(PyDict_GetItemString(creds, "realm"));
            authzid = PyObject2char(PyDict_GetItemString(creds, "authz_id"));
            ktname = PyObject2char(PyDict_GetItemString(creds, "keytab"));
        }
        passwd = PyObject2char(PyDict_GetItemString(creds, "password"));
    }

    defaults = malloc(sizeof(ldap_conndata_t));
    if (defaults == NULL) {
        free(passwd);
        free(binddn);
        free(realm);
        free(authcid);
        free(authzid);
        free(ktname);
        return (void *)PyErr_NoMemory();
    }

    defaults->mech = mech ? strdup(mech) : NULL;
    defaults->realm = realm;
    defaults->authcid = authcid;
    defaults->passwd = passwd;
    defaults->authzid = authzid;

    defaults->binddn = binddn;
#ifdef WIN32
    defaults->thread = NULL;
    defaults->ld = NULL;
    defaults->sock = sock;
#else
    defaults->resps = NULL;
    defaults->nresps = 0;
    defaults->rmech = NULL;
#ifdef HAVE_KRB5
    defaults->ctx = NULL;
    defaults->ccache = NULL;
    defaults->gsscred = GSS_C_NO_CREDENTIAL;
    defaults->errmsg = NULL;
    defaults->request_tgt = 0;
    defaults->ktname = ktname;
#endif
#endif

    return defaults;
}

/* Dealloc an ldapConnectionInfo struct. */
void
dealloc_conn_info(ldap_conndata_t* info) {
    DEBUG("dealloc_conn_info (info:%p)", info);
    free(info->authcid);
    free(info->authzid);
    free(info->binddn);
    free(info->mech);
    free(info->passwd);
    free(info->realm);
#ifdef HAVE_KRB5
    if (info->gsscred != GSS_C_NO_CREDENTIAL || info->ctx != NULL) {
        remove_krb5_cred(info->ctx, info->ccache, &(info->gsscred));
    }
    free(info->errmsg);
    free(info->ktname);
#endif
    free(info);
}

/* Thread function. The ldap_initialize function opens the LDAP client's
config file on Unix and ldap_start_tls_s blocks for create SSL context on Windows,
thus to avoid the I/O blocking in the main (Python) thread the initialisation
is done in a separate (POSIX and Windows) thread. A signal is sent through an
internal socketpair when the thread is finished, thus select() can be used on
the socket descriptor. */
#ifdef WIN32
static int WINAPI
#else
static void *
#endif
ldap_init_thread_func(void *params) {
    int rc = -1;
    const int version = LDAP_VERSION3;
    ldapInitThreadData *data = (ldapInitThreadData *)params;
    void *ref_opt = NULL;

    DEBUG("ldap_init_thread_func (params:%p)", params);
    if (data == NULL) {
#ifdef WIN32
        return 0;
#else
        return NULL;
#endif
    }
#ifndef WIN32
    pthread_mutex_lock(data->mux);
    /* Lock already acquired by this thread, flag can be set now. */
    data->flag = 1;
#endif
    rc = ldap_initialize(&(data->ld), data->url);
    if (rc != LDAP_SUCCESS) {
        data->retval = rc;
        goto end;
    }
    /* Set version to LDAPv3. */
    ldap_set_option(data->ld, LDAP_OPT_PROTOCOL_VERSION, &version);
    ref_opt = data->referrals ? LDAP_OPT_ON : LDAP_OPT_OFF;
    ldap_set_option(data->ld, LDAP_OPT_REFERRALS, ref_opt);
    if (data->cert_policy != -1) {
        set_cert_policy(data->ld, data->cert_policy);
    }
#ifndef WIN32
    /* SASL security poperties settings on available on Unix. */
    if (data->sasl_sec_props != NULL) {
        DEBUG("set sasl sec properties: %s", data->sasl_sec_props);
        rc = ldap_set_option(data->ld, LDAP_OPT_X_SASL_SECPROPS, (void *)data->sasl_sec_props);
        if (rc != LDAP_SUCCESS) {
            data->retval = rc;
            goto end;
        }
    }
#endif

#if !defined(WIN32) && LDAP_VENDOR_VERSION > 20443
    /* The asynchronous connection build only works on unix systems from
       version 2.4.44 */
    DEBUG("set connecting async: %d", _g_asyncmod);
    if (_g_asyncmod) {
        struct timeval tv;
        tv.tv_sec = 0;
        /* Set asynchronous connect for OpenLDAP. */
        ldap_set_option(data->ld, LDAP_OPT_CONNECT_ASYNC, LDAP_OPT_ON);
        ldap_set_option(data->ld, LDAP_OPT_NETWORK_TIMEOUT, &tv);
    }
#endif

#ifdef HAVE_KRB5
    if (data->info->request_tgt == 1) {
        rc = create_krb5_cred(data->info->ctx, data->info->realm,
                data->info->authcid, data->info->passwd, data->info->ktname,
                &(data->info->ccache), &(data->info->gsscred),
                &(data->info->errmsg));
        if (rc != 0) {
            data->retval = rc;
        }
    }
#endif
end:
    if (data->sock != -1) {
        /* Send a signal through an internal socketpair. */
        if (send(data->sock, "s", 1, 0) == -1) {
            /* Signalling is failed. */
            data->retval = -1;
        }
    }
    DEBUG("ldap_init_thread_func [retval:%d]", data->retval);
#ifdef WIN32
    return 0;
#else
    pthread_mutex_unlock(data->mux);
    return NULL;
#endif
}

/*  Create a platform-independent initialisation thread.
    On success it returns 0 and sets the thread parameter,
    on failure returns -1.
*/
int
create_init_thread(void *param, ldap_conndata_t *info, XTHREAD *thread) {
    int rc = 0;
    ldapInitThreadData *data = (ldapInitThreadData *)param;
    
    DEBUG("create_init_thread (ld:%p, info:%p, thread:%lu)", param, info, *thread);
#ifdef WIN32
    *thread = CreateThread(NULL, 0, ldap_init_thread_func, (void *)data, 0, NULL);
    if (*thread == NULL) rc = -1;
#else
    data->mux = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
    if (data->mux == NULL) {
        PyErr_NoMemory();
        return -1;
    }

    rc = pthread_mutex_init(data->mux, NULL);
    if (rc != 0) {
        PyErr_BadInternalCall();
        return -1;
    }
    pthread_mutex_lock(data->mux);
    data->flag = 0;
#ifdef HAVE_KRB5
    data->info = info;
    if (data->info->mech != NULL && (strcmp("GSSAPI", data->info->mech) == 0 ||
            strcmp("GSS-SPNEGO", data->info->mech) == 0)
            && data->info->realm != NULL && strlen(data->info->realm) != 0
            && data->info->authcid != NULL && strlen(data->info->authcid) != 0) {
        data->info->request_tgt = 1;
        rc = krb5_init_context(&(data->info->ctx));
        if (rc != 0) return -1;
    }
#endif
    pthread_mutex_unlock(data->mux);

    rc = pthread_create(thread, NULL, ldap_init_thread_func, data);
#endif
    if (rc != 0) return -1;

    return 0;
}

/* Create an LDAP_SERVER_EXTENDED_DN control. */
int _ldap_create_extended_dn_control(LDAP *ld, int format, LDAPControl **edn_ctrl) {
    int rc = -1;
    BerElement *ber = NULL;
    struct berval *value = NULL;
    LDAPControl *ctrl = NULL;

    ber = ber_alloc_t(LBER_USE_DER);
    if (ber == NULL) return LDAP_NO_MEMORY;
    
    /* Transcode the data into a berval struct. */
    ber_printf(ber, "{i}", format);
    rc = ber_flatten(ber, &value);
    ber_free(ber, 1);
    if (rc != 0) return rc;

    rc = ldap_control_create(LDAP_SERVER_EXTENDED_DN_OID, 0, value, 1, &ctrl);
    ber_bvfree(value);

    if (rc != LDAP_SUCCESS) return rc;

    *edn_ctrl = ctrl;
    return LDAP_SUCCESS;
}

/* Create an LDAP_SERVER_SD_FLAGS control. */
int _ldap_create_sd_flags_control(LDAP *ld, int flags, LDAPControl **edn_ctrl) {
    int rc = -1;
    BerElement *ber = NULL;
    struct berval *value = NULL;
    LDAPControl *ctrl = NULL;

    ber = ber_alloc_t(LBER_USE_DER);
    if (ber == NULL) return LDAP_NO_MEMORY;
    
    /* Transcode the data into a berval struct. */
    ber_printf(ber, "{i}", flags);
    rc = ber_flatten(ber, &value);
    ber_free(ber, 1);
    if (rc != 0) return rc;

    rc = ldap_control_create(LDAP_SERVER_SD_FLAGS_OID, 0, value, 1, &ctrl);
    ber_bvfree(value);

    if (rc != LDAP_SUCCESS) return rc;

    *edn_ctrl = ctrl;
    return LDAP_SUCCESS;
}
