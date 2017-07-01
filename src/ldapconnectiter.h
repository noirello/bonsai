/*
 * ldapconnectiter.h
 *
 *  Created on: 22 Jun 2015
 *      Author: noirello
 */

#ifndef PYLDAP_LDAPCONNECTITER_H_
#define PYLDAP_LDAPCONNECTITER_H_

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
    char bind_inprogress;
    char init_finished;
    char tls;
    char tls_inprogress;
    int message_id;
    XTHREAD init_thread;
    void *init_thread_data;
    int timeout;
} LDAPConnectIter;

extern PyTypeObject LDAPConnectIterType;

LDAPConnectIter *LDAPConnectIter_New(LDAPConnection *conn, ldap_conndata_t *info, SOCKET sock);
PyObject *LDAPConnectIter_Next(LDAPConnectIter *self, int timeout);

#endif /* PYLDAP_LDAPCONNECTITER_H_ */
