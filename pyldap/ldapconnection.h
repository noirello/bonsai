#ifndef LDAPCONNECTION_H_
#define LDAPCONNECTION_H_

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
	char *base;
	char *filter;
	char **attrs;
	struct timeval *timeout;
	int scope;
	int attrsonly;
	int sizelimit;
} SearchParams;

typedef struct {
	PyObject_HEAD
	PyObject *client;
	PyObject *buffer;
	LDAP *ld;
	struct berval *cookie;
	SearchParams *search_params;
	int async;
	int page_size;
} LDAPConnection;

extern PyTypeObject LDAPConnectionType;

int LDAPConnection_DelEntryStringDN(LDAPConnection *self, char *dnstr);

#endif /* LDAPCONNECTION_H_ */
