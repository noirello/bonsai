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
create_berval(char *value) {
	struct berval *bval = NULL;
	bval = malloc(sizeof(struct berval));
	if (bval == NULL) return NULL;
	bval->bv_len = (unsigned long)strlen(value);
	bval->bv_val = value;
	return bval;
}

/*	Converts a berval structure to a Python bytearray or if it's possible
	to string, bool or long (LDAP has no support for float as far as I know).
 	If `keepbytes` param is non-zero, then return bytearray anyway. */
PyObject *
berval2PyObject(struct berval *bval, int keepbytes) {
	PyObject *bytes = NULL;
	PyObject *obj = NULL;

	if (keepbytes == 0) {
		/* Check that the value is a boolean True. */
		if (strcmp(bval->bv_val, "TRUE") == 0) {
			Py_RETURN_TRUE;
		}
		/* Check that the value is a boolean False. */
		if (strcmp(bval->bv_val, "FALSE") == 0) {
			Py_RETURN_FALSE;
		}
		/* Try to convert into Long. */
		obj = PyLong_FromString(bval->bv_val, NULL, 0);
		if (obj == NULL ||  PyErr_Occurred()) {
			if (PyErr_ExceptionMatches(PyExc_ValueError) == 1) {
				/* ValueError is excepted and will be ignored.*/
				PyErr_Clear();
			}
		} else {
			return obj;
		}
	}

	bytes = PyBytes_FromStringAndSize(bval->bv_val, bval->bv_len);
	if (bytes == NULL) {
		PyErr_BadInternalCall();
		return NULL;
	}

	if (keepbytes) return bytes;

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
			/* UnicodeDecode error is excepted and will be ignored. */
			PyErr_Clear();
		}
	}
	return obj;
}

/*	Converts any Python objects to C string.
 	For string object it uses UTF-8 encoding to convert bytes first,
 	then char *. For None object returns empty string, for bool it returns
 	TRUE or FALSE C strings.
*/
char *
PyObject2char(PyObject *obj) {
	char *str = NULL;
	char *tmp = NULL;
	PyObject *tmpobj = NULL;

	if (obj == NULL) return NULL;

	/* If Python object is a None return an empty("") char*. */
	if (obj == Py_None) {
		str = (char *)malloc(sizeof(char));
		str[0] = '\0';
		return str;
	}

	if (PyBytes_Check(obj)) {
		/* Get the buffer of the Python bytes. */
		tmp = PyBytes_AsString(obj);
		if (tmp == NULL) return NULL;
		/* Copy the content of the buffer to avoid invalid freeing. */
		str = strdup(tmp);
	} else if (PyUnicode_Check(obj)) {
		/* Use UTF-8 encoding on Python string to get bytes. */
		tmpobj = PyUnicode_AsUTF8String(obj);
		if (tmpobj == NULL) return NULL;

		str = PyObject2char(tmpobj);
		Py_DECREF(tmpobj);
	} else if (PyBool_Check(obj)) {
		/* Python boolean converting to TRUE or FALSE ( see RFC4517 3.3.3). */
		if (obj == Py_True) {
			str = "TRUE";
		} else {
			str = "FALSE";
		}
	} else {
		tmpobj = PyObject_Str(obj);
		if (tmpobj == NULL) {
			PyErr_BadInternalCall();
			return NULL;
		}

		str = PyObject2char(tmpobj);
		Py_DECREF(tmpobj);
	}
	return str;
}

/* Create a berval list from a Python list by converting the list element
   using PyObject2char. Returns NULL if the parameter is not a list or NULL. */
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
		berval_arr[i++] = create_berval(strvalue);
		Py_DECREF(item);
	}
	Py_DECREF(iter);
	berval_arr[i] = NULL;
	return berval_arr;
}

/*	Converts Python list to a C string list. Returns NULL if it's failed. */
char **
PyList2StringList(PyObject *list) {
	int i = 0;
	char **strlist;
	PyObject *iter;
	PyObject *item;

	if (list == NULL || !PyList_Check(list)) return NULL;

	strlist = malloc(sizeof(char*) * ((int)PyList_Size(list) + 1));
	if (strlist == NULL) return NULL;

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

/*	Create a null delimitered LDAPSortKey list from a Python list which
 	contains tuples of attribute name aad reverse order. */
LDAPSortKeyA **
PyList2LDAPSortKeyList(PyObject *list) {
	int i = 0;
	char *attr = NULL;
	LDAPSortKeyA **sortlist;
	LDAPSortKeyA *elem;
	PyObject *iter;
	PyObject *item;
	PyObject *tmp = NULL;

	if (list == NULL || !PyList_Check(list)) return NULL;

	sortlist = malloc(sizeof(LDAPSortKeyA*) * ((int)PyList_Size(list) + 1));
	if (sortlist == NULL) return NULL;

	iter = PyObject_GetIter(list);
	if (iter == NULL) return NULL;

	for (item = PyIter_Next(iter); item != NULL; item = PyIter_Next(iter)) {
		if (!PyTuple_Check(item) || PyTuple_Size(item) != 2) return NULL;

		/* Get attribute's name and reverse order from the tuple. */
		tmp = PyTuple_GetItem(item, 0); /* Returns borrowed ref. */
		if (tmp == NULL) return NULL;
		attr = PyObject2char(tmp);
		if (attr == NULL) return NULL;
		tmp = PyTuple_GetItem(item, 1);
		if (tmp == NULL) return NULL;

		/* Malloc and set LDAPSortKey struct. */
		elem = (LDAPSortKeyA *)malloc(sizeof(LDAPSortKeyA));
		elem->attributeType = attr;
		elem->orderingRule = NULL;

		/* If the second tuple element is True reverseOrder will be 1,
		   otherwise 0. */
		elem->reverseOrder = PyObject_IsTrue(tmp);
		sortlist[i++] = elem;

		Py_DECREF(item);
	}
	Py_DECREF(iter);
	sortlist[i] = NULL;
	return sortlist;
}

/*	Compare lower-case representations of two Python objects.
	Returns 1 they are matched, -1 if it's failed, and 0 otherwise. */
int
lower_case_match(PyObject *o1, PyObject *o2) {
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
		return NULL;
	}

	object = PyObject_GetAttrString(module, object_name);
	if (object == NULL) {
		PyErr_Format(PyExc_ImportError, "%s is not found in %s module.", object_name, module_name);
		Py_DECREF(module);
		return NULL;
	}

	Py_DECREF(module);
	return object;
}

/* Get an error by name from the pyldap.errors Python module. */
PyObject *
get_error(char *error_name) {
	return load_python_object("pyldap.errors", error_name);
}

/* Get an error by code calling the get_error function from
   the pyldap.errors Python module. */
PyObject *
get_error_by_code(int code) {
	PyObject *error;
	PyObject *get_error = load_python_object("pyldap.errors", "__get_error");
	if (get_error == NULL) return NULL;

	error = PyObject_CallFunction(get_error, "(i)", code);

	return error;
}

/* Set a Python exception using the return code from an LDAP function.
   If it's possible append additional error message from the LDAP session. */
void
set_exception(LDAP *ld, int code) {
	int err = -1;
	size_t len = 0;
	USTR *opt_errorstr = NULL;
	USTR *errorstr = NULL;
	USTR *concat_msg = NULL;
	PyObject *ldaperror = NULL;
	PyObject *errormsg = NULL;

	if (code == 0) {
		/* Getting the error code from the session. */
		/* 0x31: LDAP_OPT_RESULT_CODE or LDAP_OPT_ERROR_NUMBER */
		ldap_get_option(ld, 0x0031, &err);
	} else {
		/* Use the parameter for error code. */
		err = code;
	}
	ldaperror = get_error_by_code(err);
	/* Get additional error message from the session. */
	ldap_get_option(ld, LDAP_OPT_ERROR_STRING, &opt_errorstr);
	errorstr = ldap_err2string(err);
	if (errorstr == NULL) goto error;

	if (opt_errorstr != NULL && ustrcmp(errorstr, opt_errorstr) != 0) {
		len = (ustrlen(errorstr) + ustrlen(opt_errorstr) + 3);
		concat_msg = (wchar_t *)malloc(sizeof(wchar_t) * len);
		concat_msg[0] = TEXT('\0');
		ustrcat(concat_msg, errorstr);
		ustrcat(concat_msg, TEXT(". "));
		ustrcat(concat_msg, opt_errorstr);
		concat_msg[len - 1] = TEXT('\0');
		errormsg = PyUnicode_FromUSTR(concat_msg, len);
		free(concat_msg);
		//TODO: ldap_memfree(opt_errorstr);
	} else {
		errormsg = PyUnicode_FromUSTR(errorstr, ustrlen(errorstr));
	}
	if (errormsg == NULL) goto error;

	PyErr_SetObject(ldaperror, errormsg);
	Py_DECREF(errormsg);
	Py_DECREF(ldaperror);
	return;
error:
	PyErr_BadInternalCall();
	Py_DECREF(ldaperror);
	return;
}

/* Add a pending LDAP operations to a dictionary. The key is the
 * corresponding message id,  the value depends on the type of operation. */
int
add_to_pending_ops(PyObject *pending_ops, int msgid,  PyObject *item)  {
       char msgidstr[8];
       sprintf(msgidstr, "%d", msgid);
       if (PyDict_SetItemString(pending_ops, msgidstr, item) != 0) {
               PyErr_BadInternalCall();
               return -1;
       }
       return 0;
}
