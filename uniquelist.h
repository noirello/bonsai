#ifndef UNIQUELIST_H_
#define UNIQUELIST_H_

#include <Python.h>
#include "structmember.h"

#include <ldap.h>

typedef struct {
	PyListObject list;
} UniqueList;

extern PyTypeObject UniqueListType;

UniqueList *UniqueList_New(void);
int UniqueList_Append(UniqueList *self, PyObject *newitem);
int UniqueList_Check(PyObject *obj);
int UniqueList_Extend(UniqueList *self, PyObject *b);
int UniqueList_Insert(UniqueList *self, Py_ssize_t where, PyObject *newitem);
int UniqueList_Remove_wFlg(UniqueList *self, PyObject *value);
int UniqueList_Remove(UniqueList *self, PyObject *value);
int UniqueList_SetItem(UniqueList *self, Py_ssize_t i, PyObject *newitem);
int UniqueList_SetSlice(UniqueList *self, Py_ssize_t ilow, Py_ssize_t ihigh, PyObject *itemlist);

#endif /* UNIQUELIST_H_ */
