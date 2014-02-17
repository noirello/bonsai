#ifndef UTILS_H_
#define UTILS_H_
#include <Python.h>

//MS Windows
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__)

#include <windows.h>
#include <winldap.h>

//Unix
#else
#include <ldap.h>
#include <lber.h>
#include <sasl/sasl.h>

#endif

typedef struct lutil_sasl_defaults_s {
	char *mech;
	char *realm;
	char *authcid;
	char *passwd;
	char *authzid;
	char **resps;
	int nresps;
} lutilSASLdefaults;

char *lowercase(char *str);
struct berval *createBerval(char *value);
PyObject *berval2PyObject(struct berval *bval, int keepbytes);
LDAPMod *createLDAPModFromItem(int mod_op, PyObject *key, PyObject *value);
char *PyObject2char(PyObject *obj);
struct berval **PyList2BervalList(PyObject *list);
char **PyList2StringList(PyObject *list);
int lowerCaseMatch(PyObject *o1, PyObject *o2);
PyObject *load_python_object(char *module_name, char *object_name);
PyObject *get_error(char *error_name);
PyObject *get_error_by_code(int code);

int _LDAP_initialization(LDAP **ld, PyObject *url);
int _LDAP_bind_s(LDAP *ld, char *mech, char* binddn, char *pswstr, char *authcid, char *realm, char *authzid);
int _LDAP_unbind(LDAP *ld);

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__)

int ldap_whoami_s(LDAP *ld, struct berval **authzid, LDAPControl **sctrls, LDAPControl **cctrls);

#else

void *create_sasl_defaults(LDAP *ld, char *mech, char *realm, char *authcid, char *passwd, char *authzid);
int sasl_interact(LDAP *ld, unsigned flags, void *defaults, void *in);

#endif

#endif /* UTILS_H_ */
