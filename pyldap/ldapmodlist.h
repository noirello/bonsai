/*
 * ldapmodlist.h
 *
 *  Created on: 7 Nov 2014
 *      Author: noirello
 */

#ifndef PYLDAP_LDAPMODLIST_H_
#define PYLDAP_LDAPMODLIST_H_

#include <Python.h>
#include "structmember.h"

#include "ldap-xplat.h"

typedef struct {
	PyObject_HEAD
	LDAPMod **mod_list;
	Py_ssize_t last;
	Py_ssize_t size;
	PyObject *entry;
} LDAPModList;

extern PyTypeObject LDAPModListType;

LDAPModList *LDAPModList_New(PyObject *entry, Py_ssize_t size);
int LDAPModList_Add(LDAPModList *self, int mod_op, PyObject *key, PyObject *value);
PyObject *LDAPModList_Pop(LDAPModList *self);
int LDAPModList_Empty(LDAPModList *self);

#endif /* PYLDAP_LDAPMODLIST_H_ */
