#ifndef LDAPCONNECTITER_H_
#define LDAPCONNECTITER_H_

#define PY_SSIZE_T_CLEAN

#include <Python.h>

#include "ldap-xplat.h"
#include "ldapconnection.h"

#ifndef WIN32
#include <poll.h>
#endif

typedef struct {
    PyObject_HEAD
    LDAPConnection *conn;
    ldap_conndata_t *info;
    /*
        0 - starting state
        1 - initialising LDAP struct is in progress
        2 - building TLS connection is in progress
        3 - TLS is checked
        4 - binding is in progress
        5 - binding is finished
    */
    char state;
    char tls;
    int message_id;
    XTHREAD init_thread;
#ifdef WIN32
    HANDLE tls_id;
#else
    int tls_id;
#endif
    void *init_thread_data;
    int timeout;
} LDAPConnectIter;

extern PyTypeObject LDAPConnectIterType;

LDAPConnectIter *LDAPConnectIter_New(LDAPConnection *conn, ldap_conndata_t *info, SOCKET sock);
PyObject *LDAPConnectIter_Next(LDAPConnectIter *self, int timeout);

#endif /* LDAPCONNECTITER_H_ */
