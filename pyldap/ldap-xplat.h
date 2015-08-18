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

#include <WinSock2.h>

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
	SOCKET sock;
} ldap_conndata_t;


#else
//Unix
#include <ldap.h>
#include <lber.h>
#include <sasl/sasl.h>
#include <sys/time.h>
#include <pthread.h>
#include <sys/socket.h>

#define SOCKET int

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
	SOCKET sock;
} ldapThreadData;

int LDAP_start_init(PyObject *url, int has_tls, int cert_policy, SOCKET sock, void **thread, void **misc);
int LDAP_finish_init(int async, void *thread, void *misc, LDAP **ld);
int LDAP_bind(LDAP *ld, ldap_conndata_t *info, LDAPMessage *result, int *msgid);

void *create_conn_info(char *mech, SOCKET sock, PyObject *creds);
int update_conn_info(LDAP *ld, ldap_conndata_t *info);
void dealloc_conn_info(ldap_conndata_t* info);

#endif /* PYLDAP_LDAP_XPLAT_H_ */
