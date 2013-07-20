#ifndef UTILS_H_
#define UTILS_H_
#include <Python.h>

#include <ldap.h>
#include <lber.h>
#include <sasl/sasl.h>

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
PyObject *berval2PyObject(struct berval *bval);
LDAPMod *createLDAPModFromItem(int mod_op, PyObject *key, PyObject *value);
char *PyObject2char(PyObject *obj);
struct berval **PyList2BervalList(PyObject *list);
char **PyList2StringList(PyObject *list);
int lowerCaseMatch(PyObject *o1, PyObject *o2);
PyObject *load_python_object(char *module_name, char *object_name);
void *create_sasl_defaults(LDAP *ld, char *mech, char *realm, char *authcid, char *passwd, char *authzid);
int sasl_interact(LDAP *ld, unsigned flags, void *defaults, void *in);

#endif /* UTILS_H_ */
