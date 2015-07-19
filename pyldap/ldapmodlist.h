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
	LDAPModA **mod_list;
	unsigned short int last;
	unsigned short int size;
	PyObject *entry;
} LDAPModList;

extern PyTypeObject LDAPModListType;

LDAPModList *LDAPModList_New(PyObject *entry, unsigned short int size);
int LDAPModList_Add(LDAPModList *self, int mod_op, PyObject *key, PyObject *value);
PyObject *LDAPModList_Pop(LDAPModList *self);
int LDAPModList_Empty(LDAPModList *self);

#endif /* PYLDAP_LDAPMODLIST_H_ */
