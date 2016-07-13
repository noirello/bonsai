/*
 * ldap-xplat.h
 *
 *  Created on: 12 Jun 2015
 *      Author: noirello
 */

#ifndef PYLDAP_LDAP_XPLAT_H_
#define PYLDAP_LDAP_XPLAT_H_

#include <Python.h>

#ifdef WIN32
//MS Windows

#include <WinSock2.h>

#include "wldap-utf8.h"

#define XTHREAD HANDLE

#else
//Unix
#include <ldap.h>
#include <lber.h>
#include <sasl/sasl.h>
#include <sys/time.h>
#include <pthread.h>
#include <sys/socket.h>

#ifdef HAVE_KRB5
#include <krb5.h>
#include <gssapi.h>
#include <gssapi/gssapi_krb5.h>
#endif

#define SOCKET int
#define XTHREAD pthread_t

int sasl_interact(LDAP *ld, unsigned flags, void *defaults, void *in);
char *_ldap_get_opt_errormsg(LDAP *ld);
#endif

typedef struct ldap_conndata_s {
    char *binddn;
    char *mech;
    char *realm;
    char *authcid;
    char *passwd;
    char *authzid;
#ifdef WIN32
    /* For the Windows's thread. */
    LDAP *ld;
    HANDLE thread;
    SOCKET sock;
#else
#ifdef HAVE_KRB5
    krb5_context ctx;
    krb5_ccache ccache;
    gss_cred_id_t gsscred;
    char *errmsg;
    char request_tgt;
#endif
    char **resps;
    int nresps;
    const char *rmech;
#endif
} ldap_conndata_t;

typedef struct ldap_thread_data_s {
    LDAP *ld;
    char *url;
    int tls;
    int cert_policy;
    char *ca_cert_dir;
    char *ca_cert;
    char *client_cert;
    char *client_key;
    int retval;
    SOCKET sock;
#ifdef WIN32
#else
    /* For the POSIX's thread. */
    pthread_mutex_t *mux;
    int flag;
    ldap_conndata_t *info;
#endif
} ldapInitThreadData;

int _ldap_finish_init_thread(char async, XTHREAD thread, int *timeout, void *misc, LDAP **ld);
int _ldap_bind(LDAP *ld, ldap_conndata_t *info, char ppolicy, LDAPMessage *result, int *msgid);

int create_init_thread(void *param, ldap_conndata_t *info, XTHREAD *thread);
void *create_conn_info(char *mech, SOCKET sock, PyObject *creds);
void dealloc_conn_info(ldap_conndata_t* info);

#endif /* PYLDAP_LDAP_XPLAT_H_ */
