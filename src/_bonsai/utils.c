#include "utils.h"

/*  Converts char* to a lower-case form. Returns with the lower-cased char *. */
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
create_berval(char *value, long int len) {
    struct berval *bval = NULL;

    bval = malloc(sizeof(struct berval));
    if (bval == NULL) return NULL;
    if (len < 0) {
        bval->bv_len = (unsigned long)strlen(value);
    } else {
        bval->bv_len = (unsigned long)len;
    }
    bval->bv_val = value;
    return bval;
}

/*  Converts a berval structure to a Python bytearray or if it's possible
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

/*  Converts any Python objects to C string for `output` with length.
    For string object it uses UTF-8 encoding to convert bytes first,
    then char *. For None object sets empty string, for bool it sets
    TRUE or FALSE C strings.
*/
int
PyObject2char_withlength(PyObject *obj, char **output, long int *len) {
    int rc = 0;
    long int size = 0;
    char *tmp = NULL;
    PyObject *tmpobj = NULL;

    if (obj == NULL) return -1;

    /* If Python object is a None return an empty("") char*. */
    if (obj == Py_None) {
        *output = strdup("");
        if (len != NULL) *len = 0;
        return 0;
    }

    if (PyBytes_Check(obj)) {
        /* Get the buffer of the Python bytes. */
        rc = PyBytes_AsStringAndSize(obj, &tmp, (Py_ssize_t *)&size);
        if (rc != 0) return -1;
        /* Copy the content of the buffer to avoid invalid freeing. */
        *output = (char *)malloc(size + 1);
        if (*output == NULL) return -1;
        memcpy(*output, tmp, size + 1);

        if (len != NULL) *len = size;

    } else if (PyUnicode_Check(obj)) {
        /* Use UTF-8 encoding on Python string to get bytes. */
        tmpobj = PyUnicode_AsUTF8String(obj);
        if (tmpobj == NULL) return -1;

        rc = PyObject2char_withlength(tmpobj, output, len);
        Py_DECREF(tmpobj);
    } else if (PyBool_Check(obj)) {
        /* Python boolean converting to TRUE or FALSE (see RFC4517 3.3.3). */
        if (obj == Py_True) {
            *output = strdup("TRUE");
            if (len != NULL) *len = 4;
        } else {
            *output = strdup("FALSE");
            if (len != NULL) *len = 5;
        }
    } else {
        tmpobj = PyObject_Str(obj);
        if (tmpobj == NULL) {
            PyErr_BadInternalCall();
            return -1;
        }

        rc = PyObject2char_withlength(tmpobj, output, len);
        Py_DECREF(tmpobj);
    }
    return rc;
}

/* Converts any Python objects to C string. */
char *
PyObject2char(PyObject *obj) {
    int rc = 0;
    char *str = NULL;

    rc = PyObject2char_withlength(obj, &str, NULL);
    if (rc != 0) return NULL;
    else return str;
}

/* Create a berval list from a Python list by converting the list element
   using PyObject2char. Returns NULL if the parameter is not a list or NULL. */
struct berval **
PyList2BervalList(PyObject *list) {
    int i = 0, rc = 0;
    long int len = 0;
    char *strvalue;
    struct berval **berval_arr = NULL;
    PyObject *iter;
    PyObject *item;

    if (list == NULL || !PyList_Check(list)) return NULL;

    berval_arr = (struct berval **)malloc(sizeof(struct berval *) * ((int)PyList_Size(list) + 1));
    if (berval_arr == NULL) return NULL;

    iter = PyObject_GetIter(list);
    if (iter == NULL) {
        free(berval_arr);
        return NULL;
    }

    for (item = PyIter_Next(iter); item != NULL; item = PyIter_Next(iter)) {
        rc = PyObject2char_withlength(item, &strvalue, &len);
        Py_DECREF(item);
        if (rc != 0) goto end;
        berval_arr[i++] = create_berval(strvalue, len);
    }
end:
    Py_DECREF(iter);
    berval_arr[i] = NULL;
    return berval_arr;
}

/*  Converts Python list to a C string list. Returns NULL if it's failed. */
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
    if (iter == NULL) {
        free(strlist);
        return NULL;
    }

    for (item = PyIter_Next(iter); item != NULL; item = PyIter_Next(iter)) {
        strlist[i++] = PyObject2char(item);
        Py_DECREF(item);
    }
    Py_DECREF(iter);
    strlist[i] = NULL;
    return strlist;
}

/*  Create a null delimitered LDAPSortKey list from a Python list which
    contains tuples of attribute name aad reverse order. */
LDAPSortKey **
PyList2LDAPSortKeyList(PyObject *list) {
    int i = 0;
    char *attr = NULL;
    LDAPSortKey **sortlist;
    LDAPSortKey *elem;
    PyObject *iter;
    PyObject *item;
    PyObject *tmp = NULL;

    if (list == NULL || !PyList_Check(list)) return NULL;

    sortlist = malloc(sizeof(LDAPSortKey*) * ((int)PyList_Size(list) + 1));
    if (sortlist == NULL) return NULL;

    iter = PyObject_GetIter(list);
    if (iter == NULL) {
        free(sortlist);
        return NULL;
    }

    for (item = PyIter_Next(iter); item != NULL; item = PyIter_Next(iter)) {
        /* Mark the end of the list first, it's important for error-handling. */
        sortlist[i] = NULL;
        if (!PyTuple_Check(item) || PyTuple_Size(item) != 2) goto error;

        /* Get attribute's name and reverse order from the tuple. */
        tmp = PyTuple_GetItem(item, 0); /* Returns borrowed ref. */
        if (tmp == NULL) goto error;
        attr = PyObject2char(tmp);
        if (attr == NULL) goto error;
        tmp = PyTuple_GetItem(item, 1);
        if (tmp == NULL) {
            free(attr);
            goto error;
        }

        /* Malloc and set LDAPSortKey struct. */
        elem = (LDAPSortKey *)malloc(sizeof(LDAPSortKey));
        if (elem == NULL) {
            free(attr);
            goto error;
        }

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
error:
    Py_DECREF(iter);
    Py_XDECREF(item);
    /* Free all successfully allocated item. */
    for (i = 0; sortlist[i] != NULL; i++) {
        free(sortlist[i]->attributeType);
        free(sortlist[i]);
    }
    free(sortlist);
    return NULL;
}

/*  Compare lower-case representations of two Python objects.
    Returns 1 they are matched, -1 if it's failed, and 0 otherwise. */
int
lower_case_match(PyObject *o1, PyObject *o2) {
    int match = 0;
    char *str1 = NULL;
    char *str2 = NULL;

    str1 = lowercase(PyObject2char(o1));
    if (str1 == NULL) return -1;

    str2 = lowercase(PyObject2char(o2));
    if (str2 == NULL) {
        free(str1);
        return -1;
    }

    if (strcmp(str1, str2) == 0) match = 1;

    free(str1);
    free(str2);

    return match;
}

/*  Load the `object_name` Python object from the `module_name` Python module.
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

/* Get an error by code calling the get_error function from
   the bonsai.errors Python module. */
PyObject *
get_error_by_code(int code) {
    PyObject *error;
    PyObject *get_error_func = load_python_object("bonsai.errors", "_get_error");
    if (get_error_func == NULL) return NULL;

    error = PyObject_CallFunction(get_error_func, "(i)", code);
    Py_DECREF(get_error_func);

    return error;
}

/* Set a Python exception using the return code from an LDAP function.
   If it's possible append additional error message from the LDAP session. */
void
set_exception(LDAP *ld, int code) {
    int err = -1;
    char *opt_errorstr = NULL;
    char *errorstr = NULL;
    PyObject *ldaperror = NULL;
    PyObject *errormsg = NULL;

    /* Check that an error is already set. */
    if (PyErr_Occurred()) return;

    if (code == 0) {
        /* Getting the error code from the session. */
        /* 0x31: LDAP_OPT_RESULT_CODE or LDAP_OPT_ERROR_NUMBER */
        ldap_get_option(ld, 0x0031, &err);
    } else {
        /* Use the parameter for error code. */
        err = code;
    }

    ldaperror = get_error_by_code(err);
    if (ldaperror == NULL) return;

    /* Get additional error message from the session. */
    opt_errorstr = _ldap_get_opt_errormsg(ld);
    errorstr = ldap_err2string(err);

    if (errorstr != NULL && strlen(errorstr) > 0) {
        if (opt_errorstr != NULL && strlen(opt_errorstr) > 0) {
            if (strcmp(errorstr, opt_errorstr) != 0) {
                errormsg = PyUnicode_FromFormat("%s. %s", errorstr, opt_errorstr);
                goto end;
            }
        }
        /* Optional string is empty or equals to the error string. */
        errormsg = PyUnicode_FromFormat("%s.", errorstr);
    } else if (opt_errorstr != NULL && strlen(opt_errorstr) > 0) {
        errormsg = PyUnicode_FromFormat("%s.", opt_errorstr);
    }
end:
    if (errormsg != NULL) {
        PyErr_SetObject(ldaperror, errormsg);
        Py_DECREF(errormsg);
    } else {
        PyErr_SetString(ldaperror, "");
    }
    if (opt_errorstr) ldap_memfree(opt_errorstr);
    Py_DECREF(ldaperror);
}

/* Add a pending LDAP operations to a dictionary. The key is the
 * corresponding message id, the value depends on the type of operation. */
int
add_to_pending_ops(PyObject *pending_ops, int msgid, PyObject *item) {
    PyObject *key = NULL;

    key = PyLong_FromLong((long int)msgid);
    if (key == NULL) return -1;

    if (PyDict_SetItem(pending_ops, key, item) != 0) {
        Py_DECREF(key);
        PyErr_BadInternalCall();
        return -1;
    }
    if (item != Py_None) Py_DECREF(item);
    Py_DECREF(key);

    return 0;
}

/* Get a pending LDAP operations from a dictionary. The key is the
 * corresponding message id, the return value depends on the type
 * of operation. */
PyObject *
get_from_pending_ops(PyObject *pending_ops, int msgid) {
    PyObject *key = NULL;
    PyObject *item = NULL;

    key = PyLong_FromLong((long int)msgid);
    if (key == NULL) return NULL;

    item = PyDict_GetItem(pending_ops, key);
    Py_DECREF(key);

    Py_XINCREF(item);
    return item;
}

/* Delete a pending LDAP operations from a dictionary. The key is the
 * corresponding message id, on error returns non-zero value. */
int
del_from_pending_ops(PyObject *pending_ops, int msgid) {
    PyObject *key = NULL;

    key = PyLong_FromLong((long int)msgid);
    if (key == NULL) return -1;

    if (PyDict_DelItem(pending_ops, key) != 0) {
        Py_DECREF(key);
        PyErr_BadInternalCall();
        return -1;
    }
    Py_DECREF(key);

    return 0;
}

/* Get a socketpair in `tup` by calling socket.socketpair(). The socket
   descriptors are set to `csock` and `ssock` parameters respectively.
   If the function call is failed, it returns with -1. */
int
get_socketpair(PyObject **tup, SOCKET *csock, SOCKET *ssock) {
    PyObject *tmp = NULL;

    tmp = load_python_object("socket", "socketpair");
    if (tmp == NULL) return -1;

    *tup = PyObject_CallObject(tmp, NULL);
    if (*tup == NULL) {
        Py_DECREF(tmp);
        return -1;
    }
    Py_DECREF(tmp);
    /* Sanity check. */
    if (PyTuple_Check(*tup) && PyTuple_Size(*tup) == 2) {
        tmp = PyTuple_GetItem(*tup, 0);
        if (tmp == NULL) goto error;

        /* Get the socket descriptor for the first one. */
        tmp = PyObject_CallMethod(tmp, "fileno", NULL);
        if (tmp == NULL) goto error;
        *ssock = (SOCKET)PyLong_AsLong(tmp);
        Py_DECREF(tmp);

        tmp = PyTuple_GetItem(*tup, 1);
        if (tmp == NULL) goto error;
        /* Get the socket descriptor for the second one. */
        tmp = PyObject_CallMethod(tmp, "fileno", NULL);
        if (tmp == NULL) goto error;
        *csock = (SOCKET)PyLong_AsLong(tmp);
        Py_DECREF(tmp);
    }
    return 0;
error:
    Py_DECREF(*tup);
    return -1;
}

/* Close and dispose the dummy sockets in the socketpair. */
void
close_socketpair(PyObject *tup) {
    PyObject *tmp = NULL;
    PyObject *ret = NULL;

    /* Sanity check. */
    if (tup != NULL && PyTuple_Check(tup) && PyTuple_Size(tup) == 2) {
        tmp = PyTuple_GetItem(tup, 0);
        if (tmp) {
            ret = PyObject_CallMethod(tmp, "close", NULL);
            if (ret) Py_DECREF(ret);
        }

        tmp = PyTuple_GetItem(tup, 1);
        if (tmp) {
            ret = PyObject_CallMethod(tmp, "close", NULL);
            if (ret) Py_DECREF(ret);
        }
    }
}

/* Set the parameters of an ldapsearchparams struct. */
int
set_search_params(ldapsearchparams *params, char **attrs, int attrsonly,
        char *base, char *filter, int len, int scope, int sizelimit, double timeout, 
        LDAPSortKey **sort_list) {

    params->attrs = attrs;
    params->attrsonly = attrsonly;

    /* Copying base string and filter string, because there is no
     guarantee that someone will not free them prematurely. */
    params->base = (char *)malloc(sizeof(char) * (strlen(base)+1));
    strcpy(params->base, base);

    /* If empty filter string is given, set to NULL. */
    if (filter == NULL || len == 0) {
        params->filter = NULL;
    } else {
        params->filter = (char *)malloc(sizeof(char) * (len + 1));
        memcpy(params->filter, filter, len + 1);
    }
    params->scope = scope;
    params->sizelimit = sizelimit;
    params->timeout = timeout;

    params->sort_list = sort_list;

    return 0;
}

/* Free an ldapsearchparam struct. */
void
free_search_params(ldapsearchparams *params) {
    int i = 0;

    if (params != NULL) {
        free(params->base);
        free(params->filter);
        if (params->attrs != NULL) {
            for (i = 0; params->attrs[i] != NULL; i++) {
                free(params->attrs[i]);
            }
            free(params->attrs);
        }
        /* Free LDAPSortKey list. */
        if (params->sort_list != NULL) {
            for (i = 0; params->sort_list[i] != NULL; i++) {
                free(params->sort_list[i]->attributeType);
                free(params->sort_list[i]);
            }
            free(params->sort_list);
        }
    }
}

int
create_ppolicy_control(LDAP *ld, LDAPControl **returned_ctrls,
        PyObject **ctrl_obj, unsigned int *pperr) {
    int rc = 0;
    int expire = 1;
    int grace = -1;

    rc = _ldap_parse_passwordpolicy_control(ld, ldap_control_find(
        LDAP_CONTROL_PASSWORDPOLICYRESPONSE, returned_ctrls, NULL),
        &expire, &grace, pperr);
    if (rc == LDAP_CONTROL_NOT_FOUND) return 0;
    if (rc != LDAP_SUCCESS) return -1;
    /* Create ppolicy ctrl dict. */
    *ctrl_obj = Py_BuildValue("{s,s,s,i,s,i}",
            "oid", LDAP_CONTROL_PASSWORDPOLICYRESPONSE,
            "expire", expire,
            "grace", grace);
    if (*ctrl_obj == NULL) return -1;

    return 1;
}

void
set_ppolicy_err(unsigned int pperr, PyObject *ctrl_obj) {
    PyObject *ldaperror = NULL;

    ldaperror = get_error_by_code(-200 - pperr);
    if (ldaperror == NULL) return;
    PyObject_SetAttrString(ldaperror, "control", ctrl_obj);
    PyErr_SetNone(ldaperror);
    Py_DECREF(ldaperror);
}

int
uniqueness_check(PyObject *list, PyObject *value) {
    int rc = 0;
    PyObject *iter = NULL;
    PyObject *item = NULL;

    iter = PyObject_GetIter(list);
    if (iter == NULL) return -1;

    for (item = PyIter_Next(iter); item != NULL; item = PyIter_Next(iter)) {
        rc = lower_case_match(item, value);
        if (rc != 0) goto end;
        Py_DECREF(item);
    }

end:
    Py_DECREF(iter);
    Py_XDECREF(item);
    return rc;
}

/* Remove an item from the list without set an error.
   Return 0 if item is not in the list, 1 if item is successfully removed
   and -1 for error. */
int
uniqueness_remove(PyObject *list, PyObject *value) {
    int cmp;
    Py_ssize_t i;

    for (i = 0; i < Py_SIZE(list); i++) {
        cmp = lower_case_match(PyList_GET_ITEM(list, i), value);
        if (cmp > 0) {
            if (PyList_SetSlice(list, i, i+1, NULL) == 0) {
                return 1;
            }
            return -1;
        } else if (cmp < 0) return -1;
    }
    return 0;
}

/* Check that the `value` is in the `list` by converting both the
   value and the list elements lower case C char* strings. The
   return value is a tuple of two items: the True/False that the
   `value` is in the list and the list element that is matched. */
PyObject *
unique_contains(PyObject *list, PyObject *value) {
    int rc = 0;
    PyObject *retval = NULL;
    PyObject *iter = NULL, *item = NULL;

    iter = PyObject_GetIter(list);
    if (iter == NULL) return NULL;

    for (item = PyIter_Next(iter); item != NULL; item = PyIter_Next(iter)) {
        rc = lower_case_match(item, value);
        if (rc == -1) goto end;
        if (rc == 1) {
            /* Item found, build the return value of (True, item). */
            retval = Py_BuildValue("(OO)", Py_True, item);
            goto end;
        }
        Py_DECREF(item);
    }
    /* No item found, return (False, None). */
    retval = Py_BuildValue("(OO)", Py_False, Py_None);
end:
    Py_DECREF(iter);
    Py_XDECREF(item);
    return retval;
}

int
get_ldapvaluelist_status(PyObject *lvl) {
    int status = -1;
    PyObject *tmp = NULL;

    tmp = PyObject_GetAttrString(lvl, "status");
    if (tmp == NULL) return -1;

    status = (int)PyLong_AsSize_t(tmp);
    Py_DECREF(tmp);

    return status;
}

int
set_ldapvaluelist_status(PyObject *lvl, int status) {
    int rc = 0;
    PyObject *tmp = NULL;

    tmp = PyLong_FromLong((long int)status);
    if (tmp == NULL) return -1;

    rc = PyObject_SetAttrString(lvl, "status", tmp);
    Py_DECREF(tmp);

    return rc;
}
