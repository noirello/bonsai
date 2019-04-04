#ifndef LDAPENTRY_H_
#define LDAPENTRY_H_

#define PY_SSIZE_T_CLEAN

#include <Python.h>

#include "ldapconnection.h"
#include "ldapmodlist.h"

typedef struct {
    PyDictObject dict;
    PyObject *dn;
    PyObject *deleted;
    LDAPConnection *conn;
} LDAPEntry;

extern PyTypeObject LDAPEntryType;

PyObject *LDAPEntry_AddOrModify(LDAPEntry *self, int mod);
int LDAPEntry_Rollback(LDAPEntry *self, LDAPModList* mods);
LDAPModList *LDAPEntry_CreateLDAPMods(LDAPEntry *self);
LDAPEntry *LDAPEntry_FromLDAPMessage(LDAPMessage *entrymsg, LDAPConnection *conn);
PyObject *LDAPEntry_GetItem(LDAPEntry *self, PyObject *key);
int LDAPEntry_SetItem(LDAPEntry *self, PyObject *key, PyObject *value);
int LDAPEntry_SetConnection(LDAPEntry *self, LDAPConnection *conn);
int LDAPEntry_SetDN(LDAPEntry *self, PyObject *value);

#endif /* LDAPENTRY_H_ */
