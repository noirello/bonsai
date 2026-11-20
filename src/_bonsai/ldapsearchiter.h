#ifndef LDAPSEARCHITER_H_
#define LDAPSEARCHITER_H_

#define PY_SSIZE_T_CLEAN

#include <Python.h>

#include "ldapconnection.h"

typedef struct {
    PyObject_HEAD
    PyObject *buffer;
    Py_ssize_t buffer_pos;
    LDAPConnection *conn;
    ldapsearchparams *params;
    struct berval *cookie;
    int page_size;
    LDAPVLVInfo *vlv_info;
    char auto_acquire;
    char has_iter_anext;
} LDAPSearchIter;

extern PyTypeObject LDAPSearchIterType;

LDAPSearchIter *LDAPSearchIter_New(LDAPConnection *conn);

#endif /* LDAPSEARCHITER_H_ */
