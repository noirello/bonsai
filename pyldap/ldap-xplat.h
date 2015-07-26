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

#define UNICODE 1

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

#define USTR wchar_t
#define CONVERTTO(str, x) convert_to_wcs(str, x)
#define CONVERTFROM(str, x) convert_to_mbs(str, x)
#define ustrcat(x, y) wcscat(x, y)
#define ustrcpy(x, y) wcscpy(x, y)
#define ustrcmp(x, y) wcscmp(x, y)
#define ustrlen(x) wcslen(x)
#define ustrfree(x) free(x)

#define _ldap_rename ldap_rename_extA

typedef struct ldapConnectionInfo_s {
	USTR *binddn;
	USTR *mech;
	USTR *authzid;
	SEC_WINNT_AUTH_IDENTITY *creds;
	CredHandle *credhandle;
	CtxtHandle *ctxhandle;
	USTR *targetName;
	/* For the thread. */
	LDAP *ld;
	HANDLE thread;
} ldapConnectionInfo;

typedef struct ldap_thread_data_s {
	LDAP *ld;
	int tls;
	int cert_policy;
	int retval;
} ldapThreadData;

char *convert_to_mbs(wchar_t *tmp, int freeit);
wchar_t *convert_to_wcs(char *tmp, int freeit);

#else
//Unix
#include <ldap.h>
#include <lber.h>
#include <sasl/sasl.h>
#include <sys/time.h>
#include <pthread.h>

#define USTR char
#define CONVERTTO(str, x) (str)
#define CONVERTFROM(str, x) (str)
#define ustrcat(x, y) strcat(x, y)
#define ustrcpy(x, y) strcpy(x, y)
#define ustrcmp(x, y) strcmp(x, y)
#define ustrlen(x) strlen(x)
#define TEXT(str) (str)
#define ustrfree(str) ()

#define _ldap_rename ldap_rename

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
	int tls ;
	int cert_policy;
	int retval;
} ldapThreadData;

int sasl_interact(LDAP *ld, unsigned flags, void *defaults, void *in);

#endif

int LDAP_start_init(PyObject *url, int has_tls, int cert_policy, void **thread, void **misc);
int LDAP_finish_init(int async, void *thread, void *misc, LDAP **ld);
int LDAP_bind(LDAP *ld, ldapConnectionInfo *info, LDAPMessage *result, int *msgid);
int LDAP_unbind(LDAP *ld);
int LDAP_abandon(LDAP *ld, int msgid);

void *create_conn_info(char *mech, PyObject *creds);
int update_conn_info(LDAP *ld, ldapConnectionInfo *info);
void dealloc_conn_info(ldapConnectionInfo* info);

PyObject *PyUnicode_FromUSTR(USTR *str);

#endif /* PYLDAP_LDAP_XPLAT_H_ */
