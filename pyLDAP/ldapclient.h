#ifndef LDAPCLIENT_H_
#define LDAPCLIENT_H_

#include <sys/time.h>

#include <Python.h>
#include "structmember.h"

#include <ldap.h>

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
