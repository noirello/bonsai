#ifndef LDAPENTRY_H_
#define LDAPENTRY_H_

#include <Python.h>
#include "structmember.h"

//MS Windows
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__)

#include <windows.h>
#include <winldap.h>

//Unix
#else
#include <ldap.h>

#endif

#include "ldapconnection.h"
#include "ldapvaluelist.h"

typedef struct {
    PyDictObject dict;
    PyObject *dn;
    PyObject *dntype;
    UniqueList *attributes;
    UniqueList *deleted;
    LDAPConnection *conn;
} LDAPEntry;

extern PyTypeObject LDAPEntryType;

LDAPEntry *LDAPEntry_New(void);
PyObject *LDAPEntry_AddOrModify(LDAPEntry *self, int mod);
int LDAPEntry_Check(PyObject *obj);
LDAPMod **LDAPEntry_CreateLDAPMods(LDAPEntry *self);
void LDAPEntry_DismissLDAPMods(LDAPEntry *self, LDAPMod **mods);
LDAPEntry *LDAPEntry_FromLDAPMessage(LDAPMessage *entrymsg, LDAPConnection *conn);
int LDAPEntry_UpdateFromDict(LDAPEntry *self, PyObject *dict);
int LDAPEntry_UpdateFromSeq2(LDAPEntry *self, PyObject *seq);
PyObject *LDAPEntry_GetItem(LDAPEntry *self, PyObject *key);
PyObject *LDAPEntry_GetItemString(LDAPEntry *self, const char *key);
int LDAPEntry_SetItem(LDAPEntry *self, PyObject *key, PyObject *value);
int LDAPEntry_SetConnection(LDAPEntry *self, LDAPConnection *conn);
int LDAPEntry_SetStringDN(LDAPEntry *self, char *value);

#endif /* LDAPENTRY_H_ */
