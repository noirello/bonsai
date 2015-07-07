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
    ldapConnectionInfo *info;
    unsigned short int bind_inprogress;
    unsigned short int init_finished;
    int message_id;
    int async;
    void *thread;
    void *data;
} LDAPConnectIter;

extern PyTypeObject LDAPConnectIterType;

LDAPConnectIter *LDAPConnectIter_New(LDAPConnection *conn,  ldapConnectionInfo *info,  int async);

#endif /* PYLDAP_LDAPCONNECTITER_H_ */
