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

#include <windows.h>
#include <winldap.h>
#include <winber.h>

#define SECURITY_WIN32 1

#include <security.h>
#include <Sspi.h>

#define attributeType sk_attrtype
#define orderingRule sk_matchruleoid
#define reverseOrder sk_reverseorder

#define attributeType sk_attrtype
#define timeval l_timeval

#define ldap_rename ldap_rename_ext

typedef struct ldapConnectionInfo_s {
	char *binddn;
	char *mech;
	char *authzid;
	SEC_WINNT_AUTH_IDENTITY *creds;
	CredHandle *credhandle;
	CtxtHandle *ctxhandle;
	char *targetName;
} ldapConnectionInfo;

int ldap_start_tls(LDAP *ld, LDAPControl **serverctrls, LDAPControl **clientctrls, int *msgidp);

#else
//Unix
#include <ldap.h>
#include <lber.h>
#include <sasl/sasl.h>
#include <sys/time.h>
#include <pthread.h>

typedef struct ldap_connection_info_s {
	char *binddn;
	char *mech;
	char *realm;
	char *authcid;
	char *passwd;
	char *authzid;
	char **resps;
	int nresps;
	const char *rmech;
} ldapConnectionInfo;

typedef struct ldap_thread_data_s {
	LDAP *ld;
	char *url;
	int retval;
} ldapThreadData;

int sasl_interact(LDAP *ld, unsigned flags, void *defaults, void *in);

#endif

int LDAP_start_init(PyObject *url, void *thread);
int LDAP_finish_init(int async, void *thread, int cert_policy, LDAP **ld);
int LDAP_bind(LDAP *ld, ldapConnectionInfo *info, LDAPMessage *result, int *msgid);
int LDAP_unbind(LDAP *ld);
int LDAP_abandon(LDAP *ld, int msgid);

void *create_conn_info(LDAP *ld, char *mech, PyObject *creds);
void dealloc_conn_info(ldapConnectionInfo* info);

#endif /* PYLDAP_LDAP_XPLAT_H_ */
