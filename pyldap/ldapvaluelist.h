#ifndef LDAPVALUELIST_H_
#define LDAPVALUELIST_H_

#include <Python.h>
#include "structmember.h"

#include "uniquelist.h"

typedef struct {
	UniqueList list;
	UniqueList *added;
	UniqueList *deleted;
	/* Status :
	     - 0: unchanged,
	     - 1: added or deleted item to list,
	     - 2: replaced the whole list.
	*/
	unsigned short int status;
} LDAPValueList;

extern PyTypeObject LDAPValueListType;

LDAPValueList *LDAPValueList_New(void);
int LDAPValueList_Append(LDAPValueList *self, PyObject *newitem);
int LDAPValueList_Check(PyObject *obj);
int LDAPValueList_Extend(LDAPValueList *self, PyObject *b);
int LDAPValueList_Insert(LDAPValueList *self, Py_ssize_t where, PyObject *newitem);
int LDAPValueList_Remove(LDAPValueList *self, PyObject *value);
int LDAPValueList_SetItem(LDAPValueList *self, Py_ssize_t i, PyObject *newitem);
int LDAPValueList_SetSlice(LDAPValueList *self, Py_ssize_t ilow, Py_ssize_t ihigh, PyObject *itemlist);

#endif /* LDAPVALUELIST_H_ */
