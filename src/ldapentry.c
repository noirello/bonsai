#include "utils.h"
#include "uniquelist.h"
#include "ldapentry.h"

/* Clear all object in the LDAPEntry. */
static int
ldapentry_clear(LDAPEntry *self) {
    PyObject *tmp;

    tmp = (PyObject *)self->conn;
    self->conn = NULL;
    Py_XDECREF(tmp);

    tmp = (PyObject *)self->deleted;
    self->deleted = NULL;
    Py_XDECREF(tmp);

    tmp = self->dn;
    self->dn = NULL;
    Py_XDECREF(tmp);
    PyDict_Type.tp_clear((PyObject*)self);

    return 0;
}

/*  Deallocate the LDAPEntry. */
static void
ldapentry_dealloc(LDAPEntry *self) {
    ldapentry_clear(self);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static int
ldapentry_traverse(LDAPEntry *self, visitproc visit, void *arg) {
    Py_VISIT(self->dn);
    Py_VISIT(self->deleted);
    return 0;
}

/*  Create a new LDAPEntry object. */
static PyObject *
ldapentry_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
    LDAPEntry *self;

    self = (LDAPEntry *)PyDict_Type.tp_new(type, args, kwds);
    if (self != NULL) {
        /* Set DN for an empty string. */
        self->dn = PyUnicode_FromString("");
        if (self->dn == NULL) {
            Py_DECREF(self);
            return NULL;
        }
        /* Set an empty list for deleted attributes. */
        self->deleted = UniqueList_New();
        if (self->deleted == NULL) {
            Py_DECREF(self);
            return NULL;
        }
    }
    return (PyObject *)self;
}

/*  Initialising LDAPEntry. */
static int
ldapentry_init(LDAPEntry *self, PyObject *args, PyObject *kwds) {
    PyObject *conn = NULL;
    PyObject *tmp;
    static char *kwlist[] = {"dn", "conn", NULL};
    char *dnstr;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "s|O", kwlist, &dnstr, &conn)) {
        return -1;
    }

    if (LDAPEntry_SetStringDN(self, dnstr) != 0) return -1;

    if (conn != NULL && conn != Py_None && PyObject_IsInstance(conn, (PyObject *)&LDAPConnectionType) != 1) {
        PyErr_SetString(PyExc_TypeError, "Connection must be an LDAPConnection type.");
        return -1;
    }

    /* Just like in the Python doc example. */
    if (conn && conn != Py_None) {
        tmp = (PyObject *)self->conn;
        Py_INCREF(conn);
        self->conn = (LDAPConnection *)conn;
        Py_XDECREF(tmp);
    }

    return 0;
}

/*  Returns 1 if obj is an instance of LDAPEntry, or 0 if not. On error, returns -1 and sets an exception. */
int
LDAPEntry_Check(PyObject *obj) {
    if (obj == NULL) return -1;
    return PyObject_IsInstance(obj, (PyObject *)&LDAPEntryType);
}

/*  Returns a NULL-delimitered LDAPMod list for adds new or modificates existing LDAP entries.
    It uses only those LDAPValueList, whose status is 1 - add or delete, or 2 - replace, and
    the deleted keys listed in LDAPEntry's deleted list.
*/
LDAPModList *
LDAPEntry_CreateLDAPMods(LDAPEntry *self) {
    Py_ssize_t i;
    PyObject *keys = PyMapping_Keys((PyObject *)self);
    PyObject *iter, *key;
    LDAPModList *mods = NULL;
    LDAPValueList *value;

    /* Create an LDAPModList for the LDAPEntry values and deleted attributes. */
    mods = LDAPModList_New((PyObject *)self,
            Py_SIZE(self) + Py_SIZE(self->deleted));
    if (mods == NULL) return NULL;

    if (keys == NULL) return NULL;

    iter = PyObject_GetIter(keys);
    Py_DECREF(keys);
    if (iter == NULL) return NULL;

    for (key = PyIter_Next(iter); key != NULL; key = PyIter_Next(iter)) {
        /* Return value: Borrowed reference. */
        value = (LDAPValueList *)LDAPEntry_GetItem(self, key);
        if (value == NULL) goto error;

        /* Remove empty list values. */
        if (Py_SIZE((PyObject *)value) == 0) {
            if (LDAPEntry_SetItem(self, key, NULL) != 0) {
                goto error;
            }
            value->status = 0;
        }

        if (value->status == 1) {
            /* LDAPMod for newly added attributes and values. */
            if (Py_SIZE((PyObject *)value->added) > 0) {
                if (LDAPModList_Add(mods, LDAP_MOD_ADD | LDAP_MOD_BVALUES,
                        key, (PyObject *)value->added) != 0) {
                    goto error;
                }
            }
            /* LDAPMod for deleted values. */
            if (Py_SIZE((PyObject *)value->deleted) > 0) {
                if (LDAPModList_Add(mods, LDAP_MOD_DELETE | LDAP_MOD_BVALUES,
                        key, (PyObject *)value->deleted) != 0) {
                    goto error;
                }
            }
        } else if (value->status == 2) {
            /* LDAPMod for replaced attributes. */
            if (LDAPModList_Add(mods, LDAP_MOD_REPLACE | LDAP_MOD_BVALUES,
                    key, (PyObject *)value) != 0){
                goto error;
            }
        }
        /* Change attributes' status to "not changed" (0), and clear lists. */
        value->status = 0;
        UniqueList_SetSlice(value->deleted, 0, Py_SIZE(value->deleted), NULL);
        UniqueList_SetSlice(value->added, 0, Py_SIZE(value->added), NULL);
        Py_DECREF(key);
    }
    Py_DECREF(iter);
    /* LDAPMod for deleted attributes. */
    for (i = 0; i < Py_SIZE((PyObject *)self->deleted); i++) {
        if (LDAPModList_Add(mods, LDAP_MOD_DELETE | LDAP_MOD_BVALUES,
                self->deleted->list.ob_item[i], NULL) != 0) {
            Py_DECREF(mods);
            return NULL;
        }
        Py_DECREF(self->deleted->list.ob_item[i]);
    }
    /* Delete the list. */
    Py_DECREF(self->deleted);
    self->deleted = UniqueList_New();
    return mods;

error:
    Py_DECREF(iter);
    Py_DECREF(key);
    Py_DECREF(mods);
    return NULL;
}

static PyObject *
ldapentry_status(LDAPEntry *self) {
    PyObject *keys = PyMapping_Keys((PyObject *)self);
    PyObject *iter, *key;
    PyObject *status_dict = NULL;
    PyObject *result = NULL;
    LDAPValueList *value;

    if (keys == NULL) return NULL;

    result = PyDict_New();
    if (result == NULL) return NULL;

    iter = PyObject_GetIter(keys);
    Py_DECREF(keys);
    if (iter == NULL) return NULL;

    for (key = PyIter_Next(iter); key != NULL; key = PyIter_Next(iter)) {
        /* Return value: Borrowed reference. */
        value = (LDAPValueList *)LDAPEntry_GetItem(self, key);
        if (value == NULL) goto error;

        status_dict = LDAPValueList_Status(value);
        if (status_dict == NULL) goto error;
        if (PyDict_SetItem(result, key, status_dict) != 0) {
            Py_DECREF(status_dict);
            goto error;
        }
        Py_DECREF(status_dict);
        Py_DECREF(key);
    }
    Py_DECREF(iter);

    if (PyDict_SetItemString(result, "@deleted",
            (PyObject *)self->deleted) != 0) {
        Py_DECREF(result);
    }

    return result;

error:
    Py_DECREF(iter);
    Py_DECREF(key);
    Py_DECREF(result);
    return NULL;
}

/*  Create a LDAPEntry from a LDAPMessage. */
LDAPEntry *
LDAPEntry_FromLDAPMessage(LDAPMessage *entrymsg, LDAPConnection *conn) {
    int i;
    int contain = -1;
    char *dn;
    char *attr;
    struct berval **values;
    BerElement *ber;
    UniqueList *rawval_list;
    PyObject *val = NULL, *attrobj = NULL, *tmp;
    PyObject *ldapentry_type = NULL;
    PyObject *args = NULL;
    LDAPValueList *lvl = NULL;
    LDAPEntry *self;

    /* Create an attribute list for LDAPEntry (which is implemented in Python). */
    dn = ldap_get_dn(conn->ld, entrymsg);
    if (dn == NULL) {
        set_exception(conn->ld, 0);
        return NULL;
    }
    args = Py_BuildValue("sO", dn, (PyObject *)conn);
    ldap_memfree(dn);
    if (args == NULL) return NULL;

    /* Create a new LDAPEntry, raise PyErr_NoMemory if it's failed. */
    ldapentry_type = load_python_object("bonsai.ldapentry", "LDAPEntry");
    if (ldapentry_type == NULL) {
        Py_DECREF(args);
        return NULL;
    }
    self = (LDAPEntry *)PyObject_CallObject(ldapentry_type, args);
    Py_DECREF(args);
    Py_DECREF(ldapentry_type);
    if (self == NULL) {
        return (LDAPEntry *)PyErr_NoMemory();
    }

    /* Get list of attribute's names, whose values have to keep in bytearray.*/
    rawval_list = UniqueList_New();
    tmp = PyObject_GetAttrString(conn->client, "raw_attributes");
    if (rawval_list == NULL || tmp == NULL ||
            UniqueList_Extend(rawval_list, tmp) != 0) {
        Py_DECREF(self);
        Py_XDECREF(tmp);
        return NULL;
    }
    Py_DECREF(tmp);

    /* Iterate over the LDAP attributes. */
    for (attr = ldap_first_attribute(conn->ld, entrymsg, &ber);
        attr != NULL; attr = ldap_next_attribute(conn->ld, entrymsg, ber)) {
        /* Create a string of attribute's name and add to the attributes list. */
        attrobj = PyUnicode_FromString(attr);
        if (attrobj == NULL) goto error;
        values = ldap_get_values_len(conn->ld, entrymsg, attr);
        ldap_memfree(attr);

        lvl = LDAPValueList_New();
        if (lvl == NULL) goto error;
        if (values != NULL) {
            for (i = 0; values[i] != NULL; i++) {
                /* Check attribute is in the raw_list. */
                contain = PySequence_Contains((PyObject *)rawval_list, attrobj);
                /* Convert berval to PyObject*, if it's failed skip it. */
                val = berval2PyObject(values[i], contain);
                if (val == NULL) continue;
                /* If the attribute has more value, then append to the list. */
                if (PyList_Append((PyObject *)lvl, val) != 0) {
                    Py_DECREF(lvl);
                    goto error;
                }
                Py_DECREF(val);
            }
        }
        PyDict_SetItem((PyObject *)self, attrobj, (PyObject *)lvl);
        Py_DECREF(lvl);
        ldap_value_free_len(values);
        Py_DECREF(attrobj);
    }
    /* Cleaning the mess. */
    Py_DECREF(rawval_list);
    if (ber != NULL) {
        ber_free(ber, 0);
    }
    return self;

error:
    Py_XDECREF(attrobj);
    Py_DECREF(self);
    Py_DECREF(rawval_list);
    ldap_memfree(attr);
    if (ber != NULL) {
        ber_free(ber, 0);
    }
    return (LDAPEntry *)PyErr_NoMemory();
}

/* Preform a LDAP add or modify operation depend on the `mod` parameter.
   If `mod` is 0 then add new entry, otherwise modify it. */
PyObject *
LDAPEntry_AddOrModify(LDAPEntry *self, int mod) {
    int rc = -1;
    int msgid = -1;
    char *dnstr = NULL;
    LDAPModList *mods = NULL;

    /* Get DN string. */
    dnstr = PyObject2char(self->dn);
    if (dnstr == NULL || strlen(dnstr) == 0) {
        PyErr_SetString(PyExc_AttributeError, "Missing distinguished name.");
        free(dnstr);
        return NULL;
    }

    mods = LDAPEntry_CreateLDAPMods(self);
    if (mods == NULL) {
        PyErr_SetString(PyExc_MemoryError, "Create LDAPModList is failed.");
        free(dnstr);
        return NULL;
    }

    if (mod == 0) {
        rc = ldap_add_ext(self->conn->ld, dnstr, mods->mod_list, NULL,
                NULL, &msgid);
    } else {
        rc = ldap_modify_ext(self->conn->ld, dnstr, mods->mod_list, NULL,
                NULL, &msgid);
    }
    free(dnstr);

    if (rc != LDAP_SUCCESS) {
        set_exception(self->conn->ld, rc);
        Py_DECREF(mods);
        return NULL;
    }
    /* Add new add or modify operation to the pending_ops with mod_dict. */
    if (add_to_pending_ops(self->conn->pending_ops, msgid,
            (PyObject *)mods) != 0) {
        Py_DECREF(mods);
        return NULL;
    }

    return PyLong_FromLong((long int)msgid);
}

/* Rollback the status of an ldapentry after a failed operation. The
   LDAPModList will be freed on success. */
int
LDAPEntry_Rollback(LDAPEntry *self, LDAPModList* mods) {
    int mod_op = -1;
    PyObject *key = NULL;
    PyObject *res_tuple = NULL;
    PyObject *values = NULL;
    PyObject *iter, *item;
    LDAPValueList *attr = NULL;

    while (!LDAPModList_Empty(mods)) {
        /* Get every item for the LDAPModList. */
        res_tuple = LDAPModList_Pop(mods);
        if (res_tuple == NULL) return -1;

        if (!PyArg_ParseTuple(res_tuple, "OiO:rollback",
                &key, &mod_op, &values)) return -1;

        attr = (LDAPValueList *)LDAPEntry_GetItem(self, key);
        if (attr == NULL) {
            /* If the attribute is remove from the LDAPEntry and deleted
               with the previous modifications, then prepare for resending . */
            if (values == Py_None) {
                if (UniqueList_Append(self->deleted, key) != 0) return -1;
            }
        } else {
            /* When status is `replaced`, then drop the previous changes. */
            if (attr->status != 2) {
                iter = PyObject_GetIter(values);
                if (iter == NULL) return -1;
                /* Check every item in the LDAPMod value list,
                    and append to the corresponding list for the attribute. */
                for (item = PyIter_Next(iter); item != NULL;
                        item = PyIter_Next(iter)) {
                    switch (mod_op) {
                        case LDAP_MOD_ADD:
                            /* Check that the item is not in the list already
                               to avoid errors.  */
                            if (UniqueList_Contains((UniqueList *)attr, item) == 1 &&
                                    UniqueList_Contains(attr->added, item) == 0) {
                                if (UniqueList_Append(attr->added, item) != 0) {
                                    return -1;
                                }
                            }
                            attr->status = 1;
                            break;
                        case LDAP_MOD_DELETE:
                            if (UniqueList_Contains((UniqueList *)attr, item) == 0 &&
                                    UniqueList_Contains(attr->deleted, item) == 0) {
                                if (UniqueList_Append(attr->deleted, item) != 0) {
                                    return -1;
                                }
                            }
                            attr->status = 1;
                            break;
                        case LDAP_MOD_REPLACE:
                            /* Nothing to do when the attribute's status is replaced. */
                            attr->status = 2;
                            break;
                    }
                    Py_DECREF(item);
                }
                Py_DECREF(iter);
            }
        }
        Py_DECREF(res_tuple);
    }
    Py_DECREF(mods);
    return 0;
}

/* Remove entry from the directory server,
   change all LDAPValueList status to replaced (2) */
static PyObject *
ldapentry_delete(LDAPEntry *self) {
    int msgid = -1;
    char *dnstr;
    PyObject *keys = PyMapping_Keys((PyObject *)self);
    PyObject *iter, *key;
    LDAPValueList *value;

    /* Connection must be set. */
    if (self->conn == NULL) {
        PyErr_SetString(PyExc_AttributeError, "LDAPConnection is not set.");
        return NULL;
    }

    /* Connection must be open. */
    if (LDAPConnection_IsClosed(self->conn) != 0) return NULL;

    /* Get DN string. */
    dnstr = PyObject2char(self->dn);
    if (dnstr == NULL) return NULL;

    /* Remove the entry. */
    msgid = LDAPConnection_DelEntryStringDN(self->conn, dnstr);
    if (msgid < 0) return NULL;

    if (keys == NULL) return NULL;

    iter = PyObject_GetIter(keys);
    Py_DECREF(keys);
    if (iter == NULL) return NULL;

    /* The values are kept locally, thus their
        statuses have to change to replaced . */
    for (key = PyIter_Next(iter); key != NULL; key = PyIter_Next(iter)) {
        /* Return value: Borrowed reference. */
        value = (LDAPValueList *)LDAPEntry_GetItem(self, key);
        if (value == NULL) {
            Py_DECREF(iter);
            Py_DECREF(key);
            return NULL;
        }
        value->status = 2;
        Py_DECREF(key);
    }
    Py_DECREF(iter);

    return PyLong_FromLong((long int)msgid);
}

/* Sends the modifications of the entry to the directory server. */
static PyObject *
ldapentry_modify(LDAPEntry *self) {
    /* Connection must be set. */
    if (self->conn == NULL) {
        PyErr_SetString(PyExc_AttributeError, "LDAPConnection is not set.");
        return NULL;
    }

    /* Connection must be open. */
    if (LDAPConnection_IsClosed(self->conn) != 0) return NULL;

    return LDAPEntry_AddOrModify(self, 1);
}

/*  Set distinguished name for a LDAPEntry. */
static int
ldapentry_setdn(LDAPEntry *self, PyObject *value, void *closure) {
    return LDAPEntry_SetDN(self, value);
}

/* Returns the DN of the LDAPEntry. */
static PyObject *
ldapentry_getdn(LDAPEntry *self, void *closure) {
    Py_INCREF(self->dn);
    return self->dn;
}


/* Convert a Python string or LDAPDN object into an LDAPDN object. */
static int
convert_to_ldapdn(PyObject *obj, PyObject **ldapdn) {
    PyObject *dn = NULL;
    PyObject *dntype = NULL;

    /* Import LDAPDN object. */
    dntype = load_python_object("bonsai.ldapdn", "LDAPDN");
    if (dntype == NULL) return -1;

    if (PyObject_IsInstance(obj, dntype)) {
        Py_INCREF(obj);
        dn = obj;
    } else if (PyUnicode_Check(obj)) {
        dn = PyObject_CallFunctionObjArgs(dntype, obj, NULL);
        /* Check for valid DN. */
        if (dn == NULL) {
            Py_DECREF(dntype);
            return -1;
        }
    } else {
        PyErr_SetString(PyExc_TypeError, "The DN attribute value must"
                " be an LDAPDN or a string.");
        Py_DECREF(dntype);
        return -1;
    }
    Py_DECREF(dntype);
    *ldapdn = dn;
    return 0;
}

/* Renames the entry object on the directory server, which means changing
   the DN of the entry. */
static PyObject *
ldapentry_rename(LDAPEntry *self, PyObject *args, PyObject *kwds) {
    int rc;
    int msgid = -1;
    char *newparent_str, *newrdn_str, *olddn_str;
    PyObject *newdn, *newparent, *newrdn;
    PyObject *tmp, *new_ldapdn = NULL;
    char *kwlist[] = {"newdn", NULL};

    /* Connection must be set. */
    if (self->conn == NULL) {
        PyErr_SetString(PyExc_AttributeError, "LDAPConnection is not set.");
        return NULL;
    }

    /* Connection must be open. */
    if (LDAPConnection_IsClosed(self->conn) != 0) return NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &newdn)) {
        PyErr_SetString(PyExc_AttributeError, "Wrong parameter.");
        return NULL;
    }

    /* Save old dn string. */
    tmp = PyObject_Str(self->dn);
    olddn_str = PyObject2char(tmp);
    Py_DECREF(tmp);
    if (olddn_str == NULL) return NULL;

    /* Convert the newdn object to an LDAPDN object. */
    if (convert_to_ldapdn(newdn, &new_ldapdn) != 0) {
        free(olddn_str);
        return NULL;
    }

    /* Get rdn and parent strings. */
    newrdn = PySequence_GetItem(new_ldapdn, 0);
    newparent = PySequence_GetSlice(new_ldapdn, 1, PyObject_Size(self->dn));
    if (newrdn == NULL || newparent == NULL) {
        free(olddn_str);
        Py_DECREF(tmp);
        return NULL;
    }

    newrdn_str = PyObject2char(newrdn);
    newparent_str = PyObject2char(newparent);
    Py_DECREF(newrdn);
    Py_DECREF(newparent);

    rc = ldap_rename(self->conn->ld, olddn_str, newrdn_str, newparent_str, 1, NULL, NULL, &msgid);
    /* Clean up strings. */
    free(olddn_str);
    free(newrdn_str);
    free(newparent_str);
    if (rc != LDAP_SUCCESS) {
        set_exception(self->conn->ld, rc);
        return NULL;
    }

    /* Add new rename operation to the pending_ops,
       with a tuple of the entry and the new DN. */
    tmp = Py_BuildValue("(O,O)", (PyObject *)self, new_ldapdn);
    Py_DECREF(new_ldapdn);
    if (tmp == NULL) return NULL;
    if (add_to_pending_ops(self->conn->pending_ops, msgid, tmp) != 0) {
        Py_DECREF(tmp);
        return NULL;
    }

    return PyLong_FromLong((long int)msgid);
}

static PyMethodDef ldapentry_methods[] = {
    {"delete",  (PyCFunction)ldapentry_delete,  METH_NOARGS,
            "Delete LDAPEntry on LDAP server."},
    {"modify",  (PyCFunction)ldapentry_modify,  METH_NOARGS,
            "Send LDAPEntry's modification to the LDAP server."},
    {"rename",  (PyCFunction)ldapentry_rename,  METH_VARARGS | METH_KEYWORDS,
            "Rename or remove LDAPEntry on the LDAP server."},
    {"_status",     (PyCFunction)ldapentry_status,  METH_NOARGS,
                "Get LDAPEntry's modification status." },
    {NULL, NULL, 0, NULL}  /* Sentinel */
};

/*  Searches among lower-cased keystrings to find a match with the key.
    if `del` set to 1, then also search among the deleted keys.
    Sets the `found` parameter's value to 1 if key found in the list, 0 otherwise. */
static PyObject *
searchLowerCaseKeyMatch(LDAPEntry *self, PyObject *key, int del, int* found) {
    PyObject *keys = PyDict_Keys((PyObject *)self);
    PyObject *iter = PyObject_GetIter(keys);
    PyObject *item;

    if (iter == NULL) {
        Py_DECREF(keys);
        return NULL;
    }
    *found = 0;
    /* Searching for same lowercase key among the other keys. */
    for (item = PyIter_Next(iter); item != NULL; item = PyIter_Next(iter)) {
        if (lower_case_match(item, key) == 1) {
            key = item;
            *found = 1;
            break;
        }
        Py_DECREF(item);
    }
    Py_DECREF(iter);
    Py_DECREF(keys);
    /* Searching among the deleted keys. */
    if (*found == 0 && del == 1) {
        iter = PyObject_GetIter((PyObject *)self->deleted);
        if (iter ==  NULL) return NULL;
        for (item = PyIter_Next(iter); item != NULL; item = PyIter_Next(iter)) {
            if (lower_case_match(item, key) == 1) {
                *found = 1;
                Py_DECREF(item);
                break;
            }
            Py_DECREF(item);
        }
    }
    return key;
}

/*  Returns the object (with borrowed reference) from the LDAPEntry,
    which has a case-insensitive match. */
PyObject *
LDAPEntry_GetItem(LDAPEntry *self, PyObject *key) {
    int found;
    PyObject *match = searchLowerCaseKeyMatch(self, key, 0, &found);
    return PyDict_GetItem((PyObject *)self, match);
}

/*  Set item to LDAPEntry with a case-insensitive key. */
int
LDAPEntry_SetItem(LDAPEntry *self, PyObject *key, PyObject *value) {
    int found = 0;
    int rc = 0;
    int status = 1;
    char *newkey = lowercase(PyObject2char(key));
    LDAPValueList *list;

    if (newkey == NULL) {
        PyErr_BadInternalCall();
        return -1;
    }

    /* Search for a match. */
    key = searchLowerCaseKeyMatch(self, key, 1, &found);
    if (found == 1) {
        status = 2;
    }
    if (value != NULL) {
        /* If theres an item with a `dn` key, and with a string value set to the dn attribute. */
        if (strcmp(newkey, "dn") == 0) {
            free(newkey);
            if (LDAPEntry_SetDN(self, value) != 0) return -1;
        } else {
            free(newkey);
            /* Set the new value to the item. */
            if (LDAPValueList_Check(value) == 0) {
                /* Convert value to LDAPValueList object. */
                list = LDAPValueList_New();
                if (PyList_Check(value) || PyTuple_Check(value)) {
                    LDAPValueList_Extend(list, value);
                } else {
                    LDAPValueList_Append(list, value);
                }
                rc = PyDict_SetItem((PyObject *)self, key, (PyObject *)list);
                list->status = status;
                Py_DECREF(list);
            } else {
                rc = PyDict_SetItem((PyObject *)self, key, value);
                ((LDAPValueList *)value)->status = status;
            }
            /* Avoid inconsistency. (same key in the added and the deleted list) */
            if (PySequence_Contains((PyObject *)self->deleted, key)) {
                if (UniqueList_Remove(self->deleted, key) != 0) return -1;
            }
            if (rc != 0) return rc;
        }
    } else {
        free(newkey);
        /* This means, it has to remove the item. */
        if (PyDict_DelItem((PyObject *)self, key) != 0) return -1;
        if (UniqueList_Append(self->deleted, key) != 0) return -1;
    }
    return 0;
}

/* Checks that `key` is in the LDAPEntry. */
static int
ldapentry_contains(PyObject *op, PyObject *key) {
    int found = -1;
    PyObject *obj = NULL;
    LDAPEntry *self = (LDAPEntry *)op;

    obj = searchLowerCaseKeyMatch(self, key, 0, &found);
    if (obj == NULL) return -1;

    return found;
}

static PySequenceMethods ldapentry_as_sequence = {
    0,                          /* sq_length */
    0,                          /* sq_concat */
    0,                          /* sq_repeat */
    0,                          /* sq_item */
    0,                          /* sq_slice */
    0,                          /* sq_ass_item */
    0,                          /* sq_ass_slice */
    ldapentry_contains,         /* sq_contains */
    0,                          /* sq_inplace_concat */
    0,                          /* sq_inplace_repeat */
};

static PyObject *
ldapentry_subscript(LDAPEntry *self, PyObject *key) {
    PyObject *v = LDAPEntry_GetItem(self, key);
    if (v == NULL) {
        PyErr_Format(PyExc_KeyError, "Key %R is not in the LDAPEntry.", key);
        return NULL;
    }
    Py_INCREF(v);
    return v;
}

static int
ldapentry_ass_sub(LDAPEntry *self, PyObject *key, PyObject *value) {
    if (key == NULL) return PyDict_DelItem((PyObject *)self, key);
    else return LDAPEntry_SetItem(self, key, value);
}

static PyMappingMethods ldapentry_mapping_meths = {
    0,                                  /* mp_length */
    (binaryfunc)ldapentry_subscript,    /* mp_subscript */
    (objobjargproc)ldapentry_ass_sub,   /* mp_ass_subscript */
};

/* Set LDAPConnection for a LDAPEntry. */
int
LDAPEntry_SetConnection(LDAPEntry *self, LDAPConnection *conn) {
    PyObject *tmp;

    if (conn) {
        tmp = (PyObject *)self->conn;
        Py_INCREF(conn);
        self->conn = conn;
        Py_XDECREF(tmp);
    } else {
        return -1;
    }
    return 0;
}

/*  Setter for connection attribute. */
static int
ldapentry_setconnection(LDAPEntry *self, PyObject *value, void *closure) {
    if (value == NULL) {
        PyErr_SetString(PyExc_TypeError, "Cannot delete the connection attribute.");
        return -1;
    }

    if (!PyObject_IsInstance(value, (PyObject *)&LDAPConnectionType)) {
        PyErr_SetString(PyExc_TypeError, "The connection attribute value must be an LDAPConnection.");
        return -1;
    }

    if (LDAPEntry_SetConnection(self, (LDAPConnection *)value) != 0) return -1;

    return 0;
}

/*  Getter for connection attribute. */
static PyObject *
ldapentry_getconnection(LDAPEntry *self, void *closure) {
    if (self->conn == NULL) {
        PyErr_SetString(PyExc_AttributeError, "LDAPConnection is not set.");
        return NULL;
    }
    Py_INCREF(self->conn);
    return (PyObject *)self->conn;
}

/* Set a `value` Python object as a DN for an LDAP entry. */
int
LDAPEntry_SetDN(LDAPEntry *self, PyObject *value) {
    PyObject *dn = NULL;

    if (value == NULL) {
        PyErr_SetString(PyExc_TypeError, "Cannot delete the DN attribute.");
        return -1;
    }

    if (convert_to_ldapdn(value, &dn) != 0) return -1;
    Py_DECREF(self->dn);
    self->dn = dn;

    return 0;
}

/* Set char* `value` as a DN for an LDAP entry. */
int
LDAPEntry_SetStringDN(LDAPEntry *self, char *value) {
    PyObject *dn = PyUnicode_FromString(value);
    if (dn == NULL) return -1;
    return LDAPEntry_SetDN(self, dn);
}

static PyGetSetDef ldapentry_getsetters[] = {
    {"connection",  (getter)ldapentry_getconnection,
                    (setter)ldapentry_setconnection,
                    "LDAP connection.", NULL},
    {"dn",          (getter)ldapentry_getdn,
                    (setter)ldapentry_setdn,
                    "Distinguished name", NULL},
    {NULL}  /* Sentinel */
};

PyTypeObject LDAPEntryType = {
    PyObject_HEAD_INIT(NULL)
    "_bonsai.ldapentry",      /* tp_name */
    sizeof(LDAPEntry),       /* tp_basicsize */
    0,                       /* tp_itemsize */
    (destructor)ldapentry_dealloc,       /* tp_dealloc */
    0,                       /* tp_print */
    0,                       /* tp_getattr */
    0,                       /* tp_setattr */
    0,                       /* tp_reserved */
    0,                       /* tp_repr */
    0,                       /* tp_as_number */
    &ldapentry_as_sequence,  /* tp_as_sequence */
    &ldapentry_mapping_meths,/* tp_as_mapping */
    0,                       /* tp_hash */
    0,                       /* tp_call */
    0,                       /* tp_str */
    0,                       /* tp_getattro */
    0,                       /* tp_setattro */
    0,                       /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT |
        Py_TPFLAGS_BASETYPE |
        Py_TPFLAGS_HAVE_GC, /* tp_flags */
    0,                       /* tp_doc */
    (traverseproc)ldapentry_traverse,/* tp_traverse */
    (inquiry)ldapentry_clear, /* tp_clear */
    0,                       /* tp_richcompare */
    0,                       /* tp_weaklistoffset */
    0,                       /* tp_iter */
    0,                       /* tp_iternext */
    ldapentry_methods,       /* tp_methods */
    0,                       /* tp_members */
    ldapentry_getsetters,    /* tp_getset */
    0,                       /* tp_base */
    0,                       /* tp_dict */
    0,                       /* tp_descr_get */
    0,                       /* tp_descr_set */
    0,                       /* tp_dictoffset */
    (initproc)ldapentry_init,/* tp_init */
    0,                       /* tp_alloc */
    ldapentry_new,           /* tp_new */
};
