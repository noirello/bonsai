#include "utils.h"

/*	Converts char* to a lower-case form. Returns with the lower-cased char *. */
char *
lowercase(char *str) {
	int i;

	if (str == NULL) return NULL;

	for(i = 0; str[i]; i++){
		str[i] = tolower(str[i]);
	}
	return str;
}

/* Create a berval structure from a char*. */
struct berval *
createBerval(char *value) {
	struct berval *bval = NULL;
	bval = malloc(sizeof(struct berval));
	if (bval == NULL) return NULL;
	bval->bv_len = strlen(value);
	bval->bv_val = value;
	return bval;
}

/*	Converts a berval structure to a Python bytearray or if it's possible to string. */
PyObject *
berval2PyObject(struct berval *bval) {
	PyObject *bytes;
	PyObject *obj;

	bytes = PyBytes_FromStringAndSize(bval->bv_val, bval->bv_len);
	if (bytes == NULL) {
		PyErr_BadInternalCall();
		return NULL;
	}
	obj = PyUnicode_FromEncodedObject(bytes, NULL, NULL);
	/* Unicode converting is failed, set bytearray to return value. */
	if (obj == NULL) {
		obj = bytes;
	} else {
		Py_DECREF(bytes);
	}
	/* Check for errors. */
	if (PyErr_Occurred()) {
		/* Should be a reason why there is nothing about
		   PyExc_UnicodeDecodeError in the official documentation. */
		if (PyErr_ExceptionMatches(PyExc_UnicodeDecodeError) == 1) {
			/* UnicodeDecode error is excepted and will be ignored.*/
			PyErr_Clear();
		}
	}
	return obj;
}

LDAPMod *
createLDAPModFromItem(int mod_op, PyObject *key, PyObject *value) {
	LDAPMod *mod;

	mod = (LDAPMod *)malloc(sizeof(LDAPMod));
	if (mod == NULL) return NULL;

	mod->mod_op = mod_op;
	mod->mod_type = PyObject2char(key);
	mod->mod_vals.modv_bvals = PyList2BervalList(value);
	return mod;
}

/*	Converts Python simple objects (String, Long, Float, Boolean, Bytes, and None) to C string.
	If the `obj` is none of these types raise BadInternalCall() error and return NULL.
*/
char *
PyObject2char(PyObject *obj) {
	char *str = NULL;
	char *tmp = NULL;
	const wchar_t *wstr;
	Py_ssize_t length = 0;
	const unsigned int len = 24; /* The max length that a number's char* representation can be. */

	if (obj == NULL) return NULL;

	/* If Python objects is a None return an empty("") char*. */
	if (obj == Py_None) {
		str = (char *)malloc(sizeof(char));
		str[0] = '\0';
		return str;
	}
	if (PyUnicode_Check(obj)) {
		/* Python string converting. From Python 3.3 could be use PyUnicode_AsUTF8AndSize(). */
		wstr = PyUnicode_AsWideCharString(obj, &length);
		str = (char *)malloc(sizeof(char) * (length + 1));
		if (str == NULL) return (char *)PyErr_NoMemory();
		wcstombs(str, wstr, length);
		/* Put the delimiter at the end. */
		str[length] = '\0';
	} else if (PyLong_Check(obj)) {
		/* Python integer converting. Could be longer, literally. */
		long int inum = PyLong_AsLong(obj);
		tmp = malloc(sizeof(char) * len);
		if (tmp == NULL) return (char *)PyErr_NoMemory();
		sprintf(tmp, "%ld", inum);
	} else if (PyFloat_Check(obj)) {
		/* Python floating point number converting. */
		double dnum = PyFloat_AsDouble(obj);
		tmp = malloc(sizeof(char) * len);
		if (tmp == NULL) return (char *)PyErr_NoMemory();
		sprintf(tmp, "%lf", dnum);
	} else if (PyBool_Check(obj)) {
		/* Python boolean converting to number representation (0 or 1). */
		if (obj == Py_True) {
			str = "1";
		} else {
			str = "0";
		}
	} else if (PyBytes_Check(obj)) {
		/* Python bytes converting. */
		tmp = PyBytes_AsString(obj);
		if (tmp == NULL) return NULL;
		str = (char *)malloc(sizeof(char) * (strlen(tmp) + 1));
		strcpy(str, tmp);
		return str;
	} else {
		PyErr_BadInternalCall();
		return NULL;
	}
	/* In case of converting numbers, optimizing the memory allocation. */
	if (tmp != NULL) {
		str = strdup(tmp);
		free(tmp);
	}
	return str;
}

struct berval **
PyList2BervalList(PyObject *list) {
	int i = 0;
	char *strvalue;
	struct berval **berval_arr = NULL;
	PyObject *iter;
	PyObject *item;

	if (list == NULL || !PyList_Check(list)) return NULL;

	berval_arr = (struct berval **)malloc(sizeof(struct berval *) * ((int)PyList_Size(list) + 1));
	iter = PyObject_GetIter(list);
	if (iter == NULL) return NULL;

	for (item = PyIter_Next(iter); item != NULL; item = PyIter_Next(iter)) {
		strvalue = PyObject2char(item);
		berval_arr[i++] = createBerval(strvalue);
		Py_DECREF(item);
	}
	Py_DECREF(iter);
	berval_arr[i] = NULL;
	return berval_arr;
}

/*	Converts Python list to a C string list. Retruns NULL if it's failed. */
char **
PyList2StringList(PyObject *list) {
	int i = 0;
	char **strlist;
	PyObject *iter;
	PyObject *item;

	if (list == NULL || !PyList_Check(list)) return NULL;

	strlist = malloc(sizeof(char*) * ((int)PyList_Size(list) + 1));
	iter = PyObject_GetIter(list);
	if (iter == NULL) return NULL;

	for (item = PyIter_Next(iter); item != NULL; item = PyIter_Next(iter)) {
		strlist[i++] = PyObject2char(item);
		Py_DECREF(item);
	}
	Py_DECREF(iter);
	strlist[i] = NULL;
	return strlist;
}

/*	Compare lower-case representations of two Python objects.
	Returns 1 they are matched, -1 if it's failed, and 0 otherwise. */
int
lowerCaseMatch(PyObject *o1, PyObject *o2) {
	int match = 0;
	char *str1 = lowercase(PyObject2char(o1));
	char *str2 = lowercase(PyObject2char(o2));

	if (str1 == NULL || str2 == NULL) return -1;

	if (strcmp(str1, str2) == 0) match = 1;

	free(str1);
	free(str2);

	return match;
}

/*	Load the `object_name` Python object from the `module_name` Python module.
	Returns the object or Py_None if it's failed.
 */
PyObject *
load_python_object(char *module_name, char *object_name) {
	PyObject *module, *object;

	module = PyImport_ImportModule(module_name);
	if (module == NULL) {
		PyErr_Format(PyExc_ImportError, "The import of %s is failed.", module_name);
		return Py_None;
	}

	object = PyObject_GetAttrString(module, object_name);
    if (object == NULL) {
    	PyErr_Format(PyExc_ImportError, "%s is not found in %s module.", object_name, module_name);
    	Py_DECREF(module);
    	return Py_None;
    }

    Py_DECREF(module);
    return object;
}

PyObject *
get_error(char *error_name) {
	return load_python_object("pyLDAP.errors", error_name);
}

void *
create_sasl_defaults(LDAP *ld, char *mech, char *realm, char *authcid, char *passwd, char *authzid) {
	lutilSASLdefaults *defaults;

	defaults = ber_memalloc(sizeof(lutilSASLdefaults));
	if(defaults == NULL) return (void *)PyErr_NoMemory();

	defaults->mech = mech ? ber_strdup(mech) : NULL;
	defaults->realm = realm ? ber_strdup(realm) : NULL;
	defaults->authcid = authcid ? ber_strdup(authcid) : NULL;
	defaults->passwd = passwd ? ber_strdup(passwd) : NULL;
	defaults->authzid = authzid ? ber_strdup(authzid) : NULL;

	if (defaults->mech == NULL) {
		ldap_get_option(ld, LDAP_OPT_X_SASL_MECH, &defaults->mech);
	}
	if (defaults->realm == NULL) {
		ldap_get_option(ld, LDAP_OPT_X_SASL_REALM, &defaults->realm);
	}
	if (defaults->authcid == NULL) {
		ldap_get_option(ld, LDAP_OPT_X_SASL_AUTHCID, &defaults->authcid);
	}
	if (defaults->authzid == NULL) {
		ldap_get_option(ld, LDAP_OPT_X_SASL_AUTHZID, &defaults->authzid);
	}
	defaults->resps = NULL;
	defaults->nresps = 0;

	return defaults;
}

static int
sasl_interaction(unsigned flags, sasl_interact_t *interact, lutilSASLdefaults *defaults) {
	const char *dflt = interact->defresult;

	switch(interact->id) {
		case SASL_CB_GETREALM:
			if (defaults) dflt = defaults->realm;
			break;
		case SASL_CB_AUTHNAME:
			if (defaults) dflt = defaults->authcid;
			break;
		case SASL_CB_PASS:
			if (defaults) dflt = defaults->passwd;
			break;
		case SASL_CB_USER:
			if (defaults) dflt = defaults->authzid;
			break;
		case SASL_CB_NOECHOPROMPT:
			break;
		case SASL_CB_ECHOPROMPT:
			break;
	}
	/* TODO CHECK OUT !!!*/
	if (interact->len > 0) {
		/* duplicate */
		char *p = (char *)interact->result;
		interact->result = defaults->resps[defaults->nresps++];
		/* zap */
		memset( p, '\0', interact->len );
	} else {
		/* input must be empty */
		interact->result = dflt;
		interact->len = strlen(interact->result);
	}

	return LDAP_SUCCESS;
}

int
sasl_interact(LDAP *ld, unsigned flags, void *defaults, void *in) {
	int rc = 0;
	sasl_interact_t *interact = in;

	while (interact->id != SASL_CB_LIST_END) {
		rc = sasl_interaction(flags, interact, defaults);
		if (rc) return rc;
		interact++;
	}
	return LDAP_SUCCESS;
}
