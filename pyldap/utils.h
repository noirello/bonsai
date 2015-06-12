#ifndef UTILS_H_
#define UTILS_H_
#include <Python.h>

#include "ldap-xplat.h"

char *lowercase(char *str);
struct berval *createBerval(char *value);
PyObject *berval2PyObject(struct berval *bval, int keepbytes);
LDAPMod *createLDAPModFromItem(int mod_op, PyObject *key, PyObject *value);
char *PyObject2char(PyObject *obj);
struct berval **PyList2BervalList(PyObject *list);
char **PyList2StringList(PyObject *list);
LDAPSortKey **PyList2LDAPSortKeyList(PyObject *list);
int lowerCaseMatch(PyObject *o1, PyObject *o2);
PyObject *load_python_object(char *module_name, char *object_name);
PyObject *get_error(char *error_name);
PyObject *get_error_by_code(int code);
int addToPendingOps(PyObject *pending_ops, int msgid,  PyObject *item);

#endif /* UTILS_H_ */
