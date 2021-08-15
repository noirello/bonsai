#include "utils.h"
#include "ldapentry.h"

/* Clear all object in the LDAPEntry. */
static int
ldapentry_clear(LDAPEntry *self) {
    DEBUG("ldapentry_clear (self:%p)", self);
    Py_CLEAR(self->conn);
    Py_CLEAR(self->deleted);
    Py_CLEAR(self->dn);
    PyDict_Type.tp_clear((PyObject*)self);

    return 0;
}

/*  Deallocate the LDAPEntry. */
static void
ldapentry_dealloc(LDAPEntry *self) {
    DEBUG("ldapentry_dealloc (self:%p)", self);
    PyObject_GC_UnTrack(self);
    ldapentry_clear(self);
    PyDict_Type.tp_dealloc((PyObject*)self);
}

static int
ldapentry_traverse(LDAPEntry *self, visitproc visit, void *arg) {
    Py_VISIT(self->dn);
    Py_VISIT(self->deleted);
    Py_VISIT(self->conn);
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
        self->deleted = PyList_New(0);
        if (self->deleted == NULL) {
            Py_DECREF(self);
            return NULL;
        }
    }
    DEBUG("ldapentry_new [self:%p]", self);
    return (PyObject *)self;
}

/*  Initialising LDAPEntry. */
static int
ldapentry_init(LDAPEntry *self, PyObject *args, PyObject *kwds) {
    PyObject *dnobj = NULL;
    PyObject *conn = NULL;
    PyObject *tmp;
    static char *kwlist[] = {"dn", "conn", NULL};

    DEBUG("ldapentry_init (self:%p)", self);
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|O", kwlist, &dnobj, &conn)) {
        return -1;
    }

    if (LDAPEntry_SetDN(self, dnobj) != 0) return -1;

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

/*  Returns a NULL-delimitered LDAPMod list for adding new or modifing existing LDAP entries.
    It uses only those LDAPValueList, whose status is 1 - add or delete, or 2 - replace, and
    the deleted keys listed in LDAPEntry's deleted list.
*/
LDAPModList *
LDAPEntry_CreateLDAPMods(LDAPEntry *self) {
    int status = -1;
    Py_ssize_t i;
    char *strkey = NULL;
    PyObject *keys = PyMapping_Keys((PyObject *)self);
    PyObject *iter = NULL, *key = NULL;
    LDAPModList *mods = NULL;
    PyObject *value = NULL;
    PyObject *added = NULL, *deleted = NULL;
    PyObject *tmp = NULL;

    if (keys == NULL) return NULL;
    /* Create an LDAPModList for the LDAPEntry values and deleted attributes. */
    mods = LDAPModList_New((PyObject *)self, Py_SIZE(self) * 2
                            + Py_SIZE(self->deleted));
    if (mods == NULL) {
        Py_DECREF(keys);
        return NULL;
    }

    iter = PyObject_GetIter(keys);
    Py_DECREF(keys);
    if (iter == NULL) goto error;

    DEBUG("LDAPEntry_CreateLDAPMods (self:%p)", self);
    for (key = PyIter_Next(iter); key != NULL; key = PyIter_Next(iter)) {
        strkey = lowercase(PyObject2char(key));
        if (strkey == NULL) goto error;

        /* Skip DN key. */
        if (strcmp(strkey, "dn") == 0) {
            free(strkey);
            continue;
        }
        free(strkey);

        /* Return value: Borrowed reference. */
        value = LDAPEntry_GetItem(self, key);
        if (value == NULL) goto error;

        /* Get LDAPValueList's status. */
        status = get_ldapvaluelist_status(value);
        if (status == -1) goto error;

        /* Get LDAPValueList's __added list. */
        added = PyObject_GetAttrString(value, "added");
        if (added == NULL) goto error;

        /* Get LDAPValueList's __deleted list. */
        deleted = PyObject_GetAttrString(value, "deleted");
        if (deleted == NULL) goto error;

        if (status == 1) {
            /* LDAPMod for newly added attributes and values. */
            if (Py_SIZE(added) > 0) {
                if (LDAPModList_Add(mods, LDAP_MOD_ADD | LDAP_MOD_BVALUES,
                        key, added) != 0) {
                    goto error;
                }
            }
            /* LDAPMod for deleted values. */
            if (Py_SIZE(deleted) > 0) {
                if (LDAPModList_Add(mods, LDAP_MOD_DELETE | LDAP_MOD_BVALUES,
                        key, deleted) != 0) {
                    goto error;
                }
            }
        } else if (status == 2) {
            /* LDAPMod for replaced attributes. */
            if (LDAPModList_Add(mods, LDAP_MOD_REPLACE | LDAP_MOD_BVALUES,
                    key, (PyObject *)value) != 0){
                goto error;
            }
        }
        /* Change attributes' status to "not changed" (0), and clear lists. */
        if (set_ldapvaluelist_status(value, 0) != 0) goto error;

        tmp = PyObject_CallMethod(added, "clear", NULL);
        if (tmp == NULL) goto error;
        Py_DECREF(tmp);

        tmp = PyObject_CallMethod(deleted, "clear", NULL);
        if (tmp == NULL) goto error;
        Py_DECREF(tmp);

        Py_DECREF(added);
        Py_DECREF(deleted);
        Py_DECREF(key);
    }
    Py_DECREF(iter);

    /* LDAPMod for deleted attributes. */
    for (i = 0; i < Py_SIZE(self->deleted); i++) {
        if (LDAPModList_Add(mods, LDAP_MOD_DELETE | LDAP_MOD_BVALUES,
                PyList_GET_ITEM(self->deleted, i), NULL) != 0) {
            Py_DECREF(mods);
            return NULL;
        }
    }

    /* Delete the list. */
    Py_DECREF(self->deleted);
    self->deleted = PyList_New(0);

    return mods;
error:
    Py_XDECREF(added);
    Py_XDECREF(deleted);
    Py_XDECREF(iter);
    Py_XDECREF(key);
    Py_DECREF(mods);
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
    PyObject *rawval_list = NULL;
    PyObject *val = NULL, *attrobj = NULL;
    PyObject *args = NULL;
    PyObject *lvl = NULL, *tmp = NULL;
    LDAPEntry *self;

    /* Create an attribute list for LDAPEntry (which is implemented in Python). */
    dn = ldap_get_dn(conn->ld, entrymsg);
    DEBUG("LDAPEntry_FromLDAPMessage (entrymsg:%p, conn:%p)[dn:%s]",
        entrymsg, conn, dn);
    if (dn == NULL) {
        set_exception(conn->ld, 0);
        return NULL;
    }
    args = Py_BuildValue("sO", dn, (PyObject *)conn);
    ldap_memfree(dn);
    if (args == NULL) return NULL;

    if (LDAPEntryObj == NULL) {
        /* Load Python-based LDAPEntry, if it's not already loaded. */
        LDAPEntryObj = load_python_object("bonsai.ldapentry", "LDAPEntry");
        if (LDAPEntryObj == NULL) return NULL;
    }
    /* Create a new LDAPEntry. */
    self = (LDAPEntry *)PyObject_CallObject(LDAPEntryObj, args);
    Py_DECREF(args);
    if (self == NULL) return NULL;

    /* Get list of attribute's names, whose values have to be kept in bytearray.*/
    rawval_list = PyObject_GetAttrString(conn->client, "raw_attributes");
    if (rawval_list == NULL) {
        Py_DECREF(self);
        return NULL;
    }

    /* Iterate over the LDAP attributes. */
    for (attr = ldap_first_attribute(conn->ld, entrymsg, &ber);
        attr != NULL; attr = ldap_next_attribute(conn->ld, entrymsg, ber)) {
        /* Create a string of attribute's name and add to the attributes list. */
        attrobj = PyUnicode_FromString(attr);
        if (attrobj == NULL) goto error;
        values = ldap_get_values_len(conn->ld, entrymsg, attr);
        ldap_memfree(attr);

        lvl = PyObject_CallFunctionObjArgs(LDAPValueListObj, NULL);
        if (lvl == NULL) goto error;
        if (values != NULL) {
            /* Check attribute is in the raw_list. */
            tmp = unique_contains(rawval_list, attrobj);
            if (tmp == NULL) goto error;
            contain = PyObject_IsTrue(PyTuple_GET_ITEM(tmp, 0));
            Py_DECREF(tmp);
            for (i = 0; values[i] != NULL; i++) {
                /* Convert berval to PyObject*, if it's failed skip it. */
                val = berval2PyObject(values[i], contain);
                if (val == NULL) continue;
                /* If the attribute has more value, then append to the list. */
                if (PyList_Append(lvl, val) != 0) {
                    Py_DECREF(lvl);
                    goto error;
                }
                Py_DECREF(val);
            }
        }
        ldap_value_free_len(values);
        if (PyDict_SetItem((PyObject *)self, attrobj, lvl) != 0) {
            Py_DECREF(lvl);
            goto error;
        }
        Py_DECREF(attrobj);
        Py_DECREF(lvl);
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
    unsigned short num_of_ctrls = 0;
    struct berval ctrl_null_value = {0, NULL};
    LDAPModList *mods = NULL;
    LDAPControl **server_ctrls = NULL;
    LDAPControl *ppolicy_ctrl = NULL;
    LDAPControl *mdi_ctrl = NULL;

    DEBUG("LDAPEntry_AddOrModify (self:%p, mod:%d)", self, mod);
    /* Get DN string. */
    dnstr = PyObject2char(self->dn);
    if (dnstr == NULL || strlen(dnstr) == 0) {
        PyErr_SetString(PyExc_ValueError, "Missing distinguished name.");
        free(dnstr);
        return NULL;
    }

    mods = LDAPEntry_CreateLDAPMods(self);
    if (mods == NULL) {
        PyErr_SetString(PyExc_MemoryError, "Create LDAPModList is failed.");
        free(dnstr);
        return NULL;
    }

    if (self->conn->ppolicy == 1) num_of_ctrls++;
    if (self->conn->managedsait == 1) num_of_ctrls++;
    if (num_of_ctrls > 0) {
        server_ctrls = (LDAPControl **)malloc(sizeof(LDAPControl *) *
                                              (num_of_ctrls + 1));
        if (server_ctrls == NULL) {
            Py_DECREF(mods);
            free(dnstr);
            return PyErr_NoMemory();
        }
        num_of_ctrls = 0;
    }

    if (self->conn->ppolicy == 1) {
        /* Create password policy control if it is set. */
        rc = ldap_create_passwordpolicy_control(self->conn->ld, &ppolicy_ctrl);
        if (rc != LDAP_SUCCESS) {
            PyErr_BadInternalCall();
            Py_DECREF(mods);
            free(dnstr);
            return NULL;
        }
        server_ctrls[num_of_ctrls++] = ppolicy_ctrl;
        server_ctrls[num_of_ctrls] = NULL;
    }

    if (self->conn->managedsait == 1) {
        /* Create ManageDsaIT dcontrol. */
        rc = ldap_control_create(LDAP_CONTROL_MANAGEDSAIT, 0, &ctrl_null_value,
                                 1, &mdi_ctrl);
        if (rc != LDAP_SUCCESS) {
            PyErr_BadInternalCall();
            Py_DECREF(mods);
            free(dnstr);
            return NULL;
        }
        server_ctrls[num_of_ctrls++] = mdi_ctrl;
        server_ctrls[num_of_ctrls] = NULL;
    }

    if (mod == 0) {
        rc = ldap_add_ext(self->conn->ld, dnstr, mods->mod_list, server_ctrls,
                NULL, &msgid);
    } else {
        rc = ldap_modify_ext(self->conn->ld, dnstr, mods->mod_list, server_ctrls,
                NULL, &msgid);
    }

    /* Clear the mess. */
    free(dnstr);
    if (ppolicy_ctrl != NULL) ldap_control_free(ppolicy_ctrl);
    if (mdi_ctrl != NULL) _ldap_control_free(mdi_ctrl);
    free(server_ctrls);

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
    int status = -1;
    PyObject *key = NULL;
    PyObject *res_tuple = NULL;
    PyObject *values = NULL;
    PyObject *iter = NULL, *item = NULL;
    PyObject *attr = NULL;
    PyObject *added = NULL, *deleted = NULL;

    DEBUG("LDAPEntry_Rollback (self:%p, mods:%p)", self, mods);
    while (!LDAPModList_Empty(mods)) {
        /* Get every item for the LDAPModList. */
        res_tuple = LDAPModList_Pop(mods);
        if (res_tuple == NULL) return -1;

        if (!PyArg_ParseTuple(res_tuple, "OiO:rollback",
                &key, &mod_op, &values)) return -1;

        attr = LDAPEntry_GetItem(self, key); /* Borrowed ref. */

        if (attr == NULL) {
            /* If the attribute is remove from the LDAPEntry and deleted
               with the previous modifications, then prepare for resending. */
            if (values == Py_None) {
                if (PyList_Append(self->deleted, key) != 0) return -1;
            }
        } else {
            /* Get LDAPValueList's status. */
            status = get_ldapvaluelist_status(attr);
            if (status == -1) return -1;

            /* Get LDAPValueList's __added list. */
            added = PyObject_GetAttrString(attr, "added");
            if (added == NULL) goto error;

            /* Get LDAPValueList's __deleted list. */
            deleted = PyObject_GetAttrString(attr, "deleted");
            if (deleted == NULL) goto error;

            /* When status is `replaced`, then drop the previous changes. */
            if (status != 2) {
                iter = PyObject_GetIter(values);
                if (iter == NULL) goto error;
                /* Check every item in the LDAPMod value list,
                    and append to the corresponding list for the attribute. */
                for (item = PyIter_Next(iter); item != NULL;
                        item = PyIter_Next(iter)) {
                    switch (mod_op) {
                        case LDAP_MOD_ADD:
                            /* Check that the item is not in the list already
                               to avoid errors.  */
                            if (uniqueness_check(attr, item) == 1 &&
                                    uniqueness_check(added, item) == 0) {
                                if (PyList_Append(added, item) != 0) {
                                    goto error;
                                }
                            }
                            if (set_ldapvaluelist_status(attr, 1) != 0) goto error;
                            break;
                        case LDAP_MOD_DELETE:
                            if (uniqueness_check(attr, item) == 0 &&
                                    uniqueness_check(deleted, item) == 0) {
                                if (PyList_Append(deleted, item) != 0) goto error;
                            }
                            if (set_ldapvaluelist_status(attr, 1) != 0) goto error;
                            break;
                        case LDAP_MOD_REPLACE:
                            /* Nothing to do when the attribute's status is replaced. */
                            if (set_ldapvaluelist_status(attr, 2) != 0) goto error;
                            break;
                    }
                    Py_DECREF(item);
                }
                Py_DECREF(iter);
            }
            Py_DECREF(added);
            Py_DECREF(deleted);
        }
        Py_DECREF(res_tuple);
    }
    return 0;

error:
    Py_XDECREF(item);
    Py_XDECREF(iter);
    Py_XDECREF(added);
    Py_XDECREF(deleted);
    Py_DECREF(res_tuple);
    return -1;
}

/* Sends the modifications of the entry to the directory server. */
static PyObject *
ldapentry_modify(LDAPEntry *self) {
    /* Connection must be open. */
    DEBUG("ldapentry_modify (self:%p)", self);
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

/* Disables modifying deleted keys. */
static int
ldapentry_setdeletedkeys(LDAPEntry *self, PyObject *value, void *closure) {
    PyErr_SetString(PyExc_ValueError, "Cannot change deleted_keys.");
    return -1;
}

/* Returns the copy of the deleted keys in the LDAPEntry. */
static PyObject *
ldapentry_getdeletedkeys(LDAPEntry *self, void *closure) {
    return PyObject_CallMethod(self->deleted, "copy", NULL);
}


/* Converts a Python string or LDAPDN object into an LDAPDN object. */
static PyObject *
convert_to_ldapdn(PyObject *obj) {
    PyObject *dn = NULL;

    if (PyObject_IsInstance(obj, LDAPDNObj)) {
        Py_INCREF(obj);
        return obj;
    } else if (PyUnicode_Check(obj)) {
        /* Call LDAPDN __init__ with the dn string. */
        dn = PyObject_CallFunctionObjArgs(LDAPDNObj, obj, NULL);
        if (dn == NULL) return NULL;
        return dn;
    } else {
        PyErr_SetString(PyExc_TypeError, "The DN attribute value must"
                " be an LDAPDN or a string.");
        return NULL;
    }
}

/* Renames the entry object on the directory server, which means changing
   the DN of the entry. */
static PyObject *
ldapentry_rename(LDAPEntry *self, PyObject *args, PyObject *kwds) {
    int rc;
    int msgid = -1;
    char *newparent_str, *newrdn_str, *olddn_str;
    PyObject *newdn, *newparent, *newrdn, *deleteold;
    PyObject *tmp, *new_ldapdn = NULL;
    char *kwlist[] = {"newdn", "delete_old_rdn", NULL};

    /* Connection must be open. */
    if (LDAPConnection_IsClosed(self->conn) != 0) return NULL;

    DEBUG("ldapentry_rename (self:%p)", self);
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OO!", kwlist, &newdn,
        &PyBool_Type, &deleteold)) {
            return NULL;
    }

    /* Save old dn string. */
    tmp = PyObject_Str(self->dn);
    olddn_str = PyObject2char(tmp);
    Py_DECREF(tmp);
    if (olddn_str == NULL) return NULL;

    /* Convert the newdn object to an LDAPDN object. */
    new_ldapdn = convert_to_ldapdn(newdn);
    if (new_ldapdn == NULL) {
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

    rc = ldap_rename(self->conn->ld, olddn_str, newrdn_str, newparent_str,
        PyObject_IsTrue(deleteold), NULL, NULL, &msgid);
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
    {"modify", (PyCFunction)ldapentry_modify, METH_NOARGS,
        "Send LDAPEntry's modification to the LDAP server."},
    {"rename", (PyCFunction)ldapentry_rename, METH_VARARGS | METH_KEYWORDS,
        "Rename or remove LDAPEntry on the LDAP server."},
    {NULL, NULL, 0, NULL}  /* Sentinel */
};

/*  Searches among lower-cased keystrings to find a match with the key.
    if `del` set to 1, then also searches among the deleted keys.
    Returns a new reference of the case-insensitive key if it's presented,
    otherwise returns NULL. */
static PyObject *
searchLowerCaseKeyMatch(LDAPEntry *self, PyObject *key, int del) {
    PyObject *keys = PyDict_Keys((PyObject *)self);
    PyObject *iter = PyObject_GetIter(keys);
    PyObject *item = NULL, *cikey = NULL;

    if (iter == NULL) {
        Py_DECREF(keys);
        return NULL;
    }

    /* Searching for same lowercase key among the other keys. */
    for (item = PyIter_Next(iter); item != NULL; item = PyIter_Next(iter)) {
        if (lower_case_match(item, key) == 1) {
            cikey = item;
            break;
        }
        Py_DECREF(item);
    }
    Py_DECREF(iter);
    Py_DECREF(keys);
    /* Searching among the deleted keys. */
    if (cikey == NULL && del == 1) {
        iter = PyObject_GetIter((PyObject *)self->deleted);
        if (iter ==  NULL) return NULL;
        for (item = PyIter_Next(iter); item != NULL; item = PyIter_Next(iter)) {
            if (lower_case_match(item, key) == 1) {
                cikey = item;
                break;
            }
            Py_DECREF(item);
        }
        Py_DECREF(iter);
    }
    return cikey;
}

/*  Returns the object (with borrowed reference) from the LDAPEntry,
    which has a case-insensitive match. */
PyObject *
LDAPEntry_GetItem(LDAPEntry *self, PyObject *key) {
    PyObject *match = NULL, *res = NULL;

    DEBUG("LDAPEntry_GetItem (self:%p, key:%p)", self, key);

    match = searchLowerCaseKeyMatch(self, key, 0);
    if (match == NULL) {
        if (PyErr_Occurred()) return NULL;
        match = key;
        Py_INCREF(match);
    }

    res = PyDict_GetItem((PyObject *)self, match);
    Py_DECREF(match);
    return res;
}

/*  Set item to LDAPEntry with a case-insensitive key. */
int
LDAPEntry_SetItem(LDAPEntry *self, PyObject *key, PyObject *value) {
    int rc = 0;
    int status = 1;
    char *newkey = lowercase(PyObject2char(key));
    PyObject *list = NULL;
    PyObject *tmp = NULL;
    PyObject *cikey = NULL; /* The actual (case-insenstive) key in the entry */

    if (newkey == NULL) {
        PyErr_BadInternalCall();
        return -1;
    }
    DEBUG("LDAPEntry_SetItem (self:%p)[key:%s]", self, newkey);

    /* Search for a match. */
    cikey = searchLowerCaseKeyMatch(self, key, 1);
    if (cikey == NULL) {
        if (PyErr_Occurred()) return -1;
        cikey = key;
        status = 1;
        Py_INCREF(cikey);
    } else {
        status = 2;
    }

    if (value != NULL) {
        /* If theres an item with a `dn` key, and with a string value set to the dn attribute. */
        if (strcmp(newkey, "dn") == 0) {
            free(newkey);
            if (LDAPEntry_SetDN(self, value) != 0) {
                Py_DECREF(cikey);
                return -1;
            }
        } else {
            free(newkey);
            /* Set the new value to the item. */
            if (PyObject_IsInstance(value, LDAPValueListObj) == 0) {
                /* Convert value to LDAPValueList object. */
                list = PyObject_CallFunctionObjArgs(LDAPValueListObj, NULL);
                if (PyList_Check(value) || PyTuple_Check(value)) {
                    tmp = PyObject_CallMethod(list, "extend", "(O)", value);
                    if (tmp == NULL) {
                        Py_DECREF(list);
                        Py_DECREF(cikey);
                        return -1;
                    }
                } else {
                    tmp = PyObject_CallMethod(list, "append", "(O)", value);
                    if (tmp == NULL) {
                        Py_DECREF(list);
                        Py_DECREF(cikey);
                        return -1;
                    }
                }
                Py_DECREF(tmp);
                rc = PyDict_SetItem((PyObject *)self, cikey, (PyObject *)list);
                if (set_ldapvaluelist_status(list, status) != 0) {
                    Py_DECREF(cikey);
                    return -1;
                }
                Py_DECREF(list);
            } else {
                rc = PyDict_SetItem((PyObject *)self, cikey, value);
                if (set_ldapvaluelist_status(value, status) != 0) {
                    Py_DECREF(cikey);
                    return -1;
                }
            }
            /* Avoid inconsistency. (same key in the added and the deleted list) */
            if (PySequence_Contains(self->deleted, cikey)) {
                if (uniqueness_remove(self->deleted, cikey) != 1) {
                    Py_DECREF(cikey);
                    return -1;
                }
            }
            if (rc != 0) {
                Py_DECREF(cikey);
                return rc;
            }
        }
    } else {
        if (strcmp(newkey, "dn") == 0) {
            free(newkey);
            PyErr_SetString(PyExc_TypeError, "Cannot delete the DN key");
            return -1;
        }
        free(newkey);
        /* This means, the item has to be removed. */
        if (PyList_Append(self->deleted, cikey) != 0) {
            Py_DECREF(cikey);
            return -1;
        }
        if (PyDict_DelItem((PyObject *)self, cikey) != 0) {
            Py_DECREF(cikey);
            return -1;
        }
    }
    Py_DECREF(cikey);
    return 0;
}

/* Checks that `key` is in the LDAPEntry. */
static int
ldapentry_contains(PyObject *op, PyObject *key) {
    PyObject *obj = NULL;
    LDAPEntry *self = (LDAPEntry *)op;

    DEBUG("ldapentry_contains (self:%p, key:%p)", self, key);
    obj = searchLowerCaseKeyMatch(self, key, 0);
    if (obj == NULL) {
        if (PyErr_Occurred()) return -1;
        else return 0;
    }

    Py_DECREF(obj);
    return 1;
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
    PyObject *val = LDAPEntry_GetItem(self, key);
    if (val == NULL) {
        PyErr_Format(PyExc_KeyError, "Key %R is not in the LDAPEntry.", key);
        return NULL;
    }
    Py_INCREF(val);
    return val;
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

    DEBUG("LDAPEntry_SetConnection (self:%p, conn:%p)", self, conn);
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
        PyErr_SetString(PyExc_ValueError, "LDAPConnection is not set.");
        return NULL;
    }
    Py_INCREF(self->conn);
    return (PyObject *)self->conn;
}

/* Set a `value` Python object as a DN for an LDAP entry. */
int
LDAPEntry_SetDN(LDAPEntry *self, PyObject *value) {
    PyObject *dn = NULL;

    DEBUG("LDAPEntry_SetDN (self:%p, value:%p)", self, value);
    if (value == NULL) {
        PyErr_SetString(PyExc_TypeError, "Cannot delete the DN attribute.");
        return -1;
    }

    dn = convert_to_ldapdn(value);
    if (dn == NULL) return -1;

    Py_DECREF(self->dn);
    self->dn = dn;
    if (PyDict_SetItemString((PyObject *)self, "dn", dn) != 0) return -1;

    return 0;
}

static PyGetSetDef ldapentry_getsetters[] = {
    {"connection",  (getter)ldapentry_getconnection,
                    (setter)ldapentry_setconnection,
                    "LDAP connection.", NULL},
    {"dn",          (getter)ldapentry_getdn,
                    (setter)ldapentry_setdn,
                    "Distinguished name", NULL},
    {"deleted_keys", (getter)ldapentry_getdeletedkeys,
                     (setter)ldapentry_setdeletedkeys,
                     "Deleted keys", NULL},
    {NULL}  /* Sentinel */
};

PyTypeObject LDAPEntryType = {
    PyVarObject_HEAD_INIT(NULL, 0)
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
