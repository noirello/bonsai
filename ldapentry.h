#ifndef LDAPENTRY_H_
#define LDAPENTRY_H_

#include <Python.h>
#include "structmember.h"

#include <ldap.h>

#include "ldapclient.h"
#include "ldapvaluelist.h"

typedef struct {
    PyDictObject dict;
    PyObject *dn;
    PyObject *attributes;
    LDAPValueList *deleted;
    LDAPClient *client;
} LDAPEntry;

extern PyTypeObject LDAPEntryType;

LDAPEntry *LDAPEntry_New(void);
int LDAPEntry_Check(PyObject *obj);
LDAPMod **LDAPEntry_CreateLDAPMods(LDAPEntry *self);
void LDAPEntry_DismissLDAPMods(LDAPEntry *self, LDAPMod **mods);
LDAPEntry *LDAPEntry_FromLDAPMessage(LDAPMessage *entrymsg, LDAPClient *client);
int LDAPEntry_UpdateFromDict(LDAPEntry *self, PyObject *dict);
int LDAPEntry_UpdateFromSeq2(LDAPEntry *self, PyObject *seq);
PyObject *LDAPEntry_GetItem(LDAPEntry *self, PyObject *key);
PyObject *LDAPEntry_GetItemString(LDAPEntry *self, const char *key);
int LDAPEntry_SetItem(LDAPEntry *self, PyObject *key, PyObject *value);
int LDAPEntry_SetClient(LDAPEntry *self, LDAPClient *client);
int LDAPEntry_SetStringDN(LDAPEntry *self, char *value);

#endif /* LDAPENTRY_H_ */
