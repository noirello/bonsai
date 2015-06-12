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

#define attributeType sk_attrtype
#define orderingRule sk_matchruleoid
#define reverseOrder sk_reverseorder

#define attributeType sk_attrtype
#define timeval l_timeval

#define ldap_rename ldap_rename_ext

#else
//Unix
#include <ldap.h>
#include <lber.h>
#include <sasl/sasl.h>
#include <sys/time.h>

typedef struct lutil_sasl_defaults_s {
	char *mech;
	char *realm;
	char *authcid;
	char *passwd;
	char *authzid;
	char **resps;
	int nresps;
} lutilSASLdefaults;

void *create_sasl_defaults(LDAP *ld, char *mech, char *realm, char *authcid, char *passwd, char *authzid);
int sasl_interact(LDAP *ld, unsigned flags, void *defaults, void *in);

#endif

int LDAP_initialization(LDAP **ld, PyObject *url, int tls_option);
int LDAP_bind(LDAP *ld, char *mech, char* binddn, char *pswstr, char *authcid, char *realm, char *authzid);
int LDAP_unbind(LDAP *ld);
int LDAP_abandon(LDAP *ld, int msgid);

#endif /* PYLDAP_LDAP_XPLAT_H_ */
