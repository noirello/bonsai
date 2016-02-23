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

typedef struct {
    PyObject_HEAD
    LDAPConnection *conn;
    ldap_conndata_t *info;
    unsigned short int bind_inprogress;
    unsigned short int init_finished;
    int message_id;
    XTHREAD init_thread;
    void *init_thread_data;
    int timeout;
} LDAPConnectIter;

extern PyTypeObject LDAPConnectIterType;

LDAPConnectIter *LDAPConnectIter_New(LDAPConnection *conn, ldap_conndata_t *info, SOCKET sock);
PyObject *LDAPConnectIter_Next(LDAPConnectIter *self, int timeout);

#endif /* PYLDAP_LDAPCONNECTITER_H_ */
