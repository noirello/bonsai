/*
 * ldapoperaton.h
 *
 *  Created on: 13 Jun 2015
 *      Author: noirello
 */

#ifndef PYLDAP_LDAPOPERATION_H_
#define PYLDAP_LDAPOPERATION_H_

#include <Python.h>
#include "structmember.h"
#include "ldapconnection.h"

typedef struct {
    PyObject_HEAD
    PyObject *message_ids;
    LDAPConnection *conn;
    unsigned short type;
    void *data;
} LDAPOperation;

extern PyTypeObject LDAPOperationType;

LDAPOperation *LDAPOperation_New(LDAPConnection *conn, unsigned short type, void *data);
int LDAPOperation_Proceed(LDAPConnection *conn, int msgid, unsigned short type, void *data);
int LDAPOperation_AppendMsgId(LDAPConnection *conn, int id, int new_msgid);
int LDAPOperation_GetFirstMsgId(LDAPConnection *conn, int id);
void *LDAPOperation_GetData(LDAPConnection *conn, int id);
int LDAPOperation_Remove(LDAPConnection *conn, int id);

#endif /* PYLDAP_LDAPOPERATION_H_ */
