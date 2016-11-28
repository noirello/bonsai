/*
 * ldapsearchiter.h
 *
 *  Created on: Mar 3, 2014
 *      Author: noirello
 */

#ifndef LDAPSEARCHITER_H_
#define LDAPSEARCHITER_H_

#include <Python.h>
#include "structmember.h"
#include "ldapconnection.h"

typedef struct {
    PyObject_HEAD
    PyObject *buffer;
    LDAPConnection *conn;
    ldapsearchparams *params;
    struct berval *cookie;
    int page_size;
    LDAPVLVInfo *vlv_info;
    char auto_acquire;
} LDAPSearchIter;

extern PyTypeObject LDAPSearchIterType;

LDAPSearchIter *LDAPSearchIter_New(LDAPConnection *conn);

#endif /* LDAPSEARCHITER_H_ */
