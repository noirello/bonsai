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
    void *thread;
    void *data;
} LDAPConnectIter;

extern PyTypeObject LDAPConnectIterType;

LDAPConnectIter *LDAPConnectIter_New(LDAPConnection *conn,  ldap_conndata_t *info);
PyObject *LDAPConnectIter_Next(LDAPConnectIter *self);

#endif /* PYLDAP_LDAPCONNECTITER_H_ */
