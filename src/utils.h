#ifndef UTILS_H_
#define UTILS_H_
#include <Python.h>

#include "ldap-xplat.h"

char *lowercase(char *str);
struct berval *create_berval(char *value);
PyObject *berval2PyObject(struct berval *bval, int keepbytes);
char *PyObject2char(PyObject *obj);
struct berval **PyList2BervalList(PyObject *list);
char **PyList2StringList(PyObject *list);
LDAPSortKey **PyList2LDAPSortKeyList(PyObject *list);
int lower_case_match(PyObject *o1, PyObject *o2);
PyObject *load_python_object(char *module_name, char *object_name);
PyObject *get_error_by_code(int code);
void set_exception(LDAP *ld, int code);
int add_to_pending_ops(PyObject *pending_ops, int msgid,  PyObject *item);
int get_socketpair(PyObject *client, PyObject **tup, SOCKET *csock, SOCKET *ssock);
void close_socketpair(PyObject *tup);
#endif /* UTILS_H_ */
