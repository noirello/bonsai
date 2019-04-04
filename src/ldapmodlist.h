#ifndef LDAPMODLIST_H_
#define LDAPMODLIST_H_

#define PY_SSIZE_T_CLEAN

#include <Python.h>

#include "ldap-xplat.h" /* OpenLDAP/WinLDAP headers. */

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

#endif /* LDAPMODLIST_H_ */
