#ifndef LDAPCONNECTION_H_
#define LDAPCONNECTION_H_

#define PY_SSIZE_T_CLEAN

#include <Python.h>
#include "structmember.h"

#include "utils.h"

typedef struct {
    PyObject_HEAD
    PyObject *client;
    PyObject *pending_ops;
    LDAP *ld;
    char closed;
    char async;
    char ppolicy;
    char managedsait;
    SOCKET csock;
    PyObject *socketpair;
} LDAPConnection;

extern PyTypeObject LDAPConnectionType;

int LDAPConnection_IsClosed(LDAPConnection *self);
int LDAPConnection_Searching(LDAPConnection *self, ldapsearchparams *params, PyObject *iterator);

#endif /* LDAPCONNECTION_H_ */
