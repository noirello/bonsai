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
    struct berval *cookie;
    char *base;
    char *filter;
    char **attrs;
    struct timeval *timeout;
    int scope;
    int attrsonly;
    int sizelimit;
} LDAPSearchIter;

extern PyTypeObject LDAPSearchIterType;

LDAPSearchIter *LDAPSearchIter_New(LDAPConnection *conn);
int LDAPSearchIter_SetParams(LDAPSearchIter *self, char **attrs, int attrsonly,
		char *base, char *filter, int scope, int sizelimit, int timeout);

#endif /* LDAPSEARCHITER_H_ */
