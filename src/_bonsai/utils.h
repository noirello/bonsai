#ifndef UTILS_H_
#define UTILS_H_

#define PY_SSIZE_T_CLEAN

#include <Python.h>

#include "ldap-xplat.h"

typedef struct {
    char *base;
    char *filter;
    char **attrs;
    double timeout;
    int scope;
    int attrsonly;
    int sizelimit;
    LDAPSortKey **sort_list;
} ldapsearchparams;

extern PyObject *LDAPDNObj;
extern PyObject *LDAPEntryObj;
extern PyObject *LDAPValueListObj;
extern char _g_debugmod;
extern char _g_asyncmod;

#define DEBUG(fmt, ...) \
    do { if (_g_debugmod) { \
        fprintf(stdout, "DBG: "); \
        fprintf(stdout, fmt, __VA_ARGS__); \
        fprintf(stdout, "\n");} } while (0)

char *lowercase(char *str);
struct berval *create_berval(char *value, long int len);
PyObject *berval2PyObject(struct berval *bval, int keepbytes);
int PyObject2char_withlength(PyObject *obj, char **output, long int *len);
char *PyObject2char(PyObject *obj);
struct berval **PyList2BervalList(PyObject *list);
char **PyList2StringList(PyObject *list);
LDAPSortKey **PyList2LDAPSortKeyList(PyObject *list);
int lower_case_match(PyObject *o1, PyObject *o2);
PyObject *load_python_object(char *module_name, char *object_name);
PyObject *get_error_by_code(int code);
void set_exception(LDAP *ld, int code);
int add_to_pending_ops(PyObject *pending_ops, int msgid, PyObject *item);
PyObject *get_from_pending_ops(PyObject *pending_ops, int msgid);
int del_from_pending_ops(PyObject *pending_ops, int msgid);
int get_socketpair(PyObject *client, PyObject **tup, SOCKET *csock, SOCKET *ssock);
void close_socketpair(PyObject *tup);
int set_search_params(ldapsearchparams *params, char **attrs, int attrsonly,
        char *base, char *filter, int len, int scope, int sizelimit, double timeout,
        LDAPSortKey **sort_list);
void free_search_params(ldapsearchparams *params);
int create_ppolicy_control(LDAP *ld, LDAPControl **returned_ctrls,
        PyObject **ctrl_obj,  unsigned int *pperr);
void set_ppolicy_err(unsigned int pperr, PyObject *ctrl_obj);
int uniqueness_check(PyObject *list, PyObject *value);
int uniqueness_remove(PyObject *list, PyObject *value);
PyObject *unique_contains(PyObject *list, PyObject *value);
int get_ldapvaluelist_status(PyObject *lvl);
int set_ldapvaluelist_status(PyObject *lvl, int status);

#endif /* UTILS_H_ */
