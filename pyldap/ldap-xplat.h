/*
 * ldap-xplat.h
 *
 *  Created on: 12 Jun 2015
 *      Author: noirello
 */

#ifndef PYLDAP_LDAP_XPLAT_H_
#define PYLDAP_LDAP_XPLAT_H_

#include <Python.h>

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__)
//MS Windows

#include "wldap-utf8.h"

typedef struct ldap_conndata_s {
	char *binddn;
	char *mech;
	char *realm;
	char *authcid;
	char *passwd;
	char *authzid;
	/* For the thread. */
	LDAP *ld;
	HANDLE thread;
} ldap_conndata_t;


#else
//Unix
#include <ldap.h>
#include <lber.h>
#include <sasl/sasl.h>
#include <sys/time.h>
#include <pthread.h>

typedef struct ldap_conndata_s {
	char *binddn;
	char *mech;
	char *realm;
	char *authcid;
	char *passwd;
	char *authzid;
	char **resps;
	int nresps;
	const char *rmech;
} ldap_conndata_t;

int sasl_interact(LDAP *ld, unsigned flags, void *defaults, void *in);
char *_ldap_get_opt_errormsg(LDAP *ld);
#endif

typedef struct ldap_thread_data_s {
	LDAP *ld;
	char *url;
	int tls;
	int cert_policy;
	int retval;
} ldapThreadData;

int LDAP_start_init(PyObject *url, int has_tls, int cert_policy, void **thread, void **misc);
int LDAP_finish_init(int async, void *thread, void *misc, LDAP **ld);
int LDAP_bind(LDAP *ld, ldap_conndata_t *info, LDAPMessage *result, int *msgid);

void *create_conn_info(char *mech, PyObject *creds);
int update_conn_info(LDAP *ld, ldap_conndata_t *info);
void dealloc_conn_info(ldap_conndata_t* info);

#endif /* PYLDAP_LDAP_XPLAT_H_ */
