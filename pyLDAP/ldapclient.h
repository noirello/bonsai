#ifndef LDAPCLIENT_H_
#define LDAPCLIENT_H_

#include <sys/time.h>

#include <Python.h>
#include "structmember.h"

//MS Windows
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__)

#include <windows.h>
#include <winldap.h>

//Unix
#else
#include <ldap.h>

#endif

typedef struct {
	PyObject_HEAD
	PyObject *uri;
	LDAP *ld;
	int connected;
	int tls;
} LDAPClient;

extern PyTypeObject LDAPClientType;

int LDAPClient_DelEntryStringDN(LDAPClient *self, char *dnstr);

#endif /* LDAPCLIENT_H_ */
