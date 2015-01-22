#include "utils.h"
#include "uniquelist.h"
#include "ldapentry.h"

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__)
#define ldap_rename ldap_rename_ext
#endif

/* Clear all object in the LDAPEntry. */
static int
LDAPEntry_clear(LDAPEntry *self) {
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
    Py_XDECREF(self->dntype);
    PyDict_Type.tp_clear((PyObject*)self);

    return 0;
}

/*	Deallocate the LDAPEntry. */
static void
LDAPEntry_dealloc(LDAPEntry *self) {
    LDAPEntry_clear(self);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static int
LDAPEntry_traverse(LDAPEntry *self, visitproc visit, void *arg) {
	Py_VISIT(self->dn);
    Py_VISIT(self->deleted);
    return 0;
}

/*	Create a new LDAPEntry object. */
static PyObject *
LDAPEntry_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
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
    	/* Import LDAPDN object. */
    	self->dntype = load_python_object("pyldap.ldapdn", "LDAPDN");
    	if (self->dntype == NULL) return NULL;
	}
    return (PyObject *)self;
}

/*	Initializing LDAPEntry. */
static int
LDAPEntry_init(LDAPEntry *self, PyObject *args, PyObject *kwds) {
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

/*	Creates a new LDAPEntry object for internal use. */
LDAPEntry *
LDAPEntry_New(void) {
	LDAPEntry *self = (LDAPEntry *)LDAPEntryType.tp_new(&LDAPEntryType, NULL, NULL);
	return self;
}

/*	Returns 1 if obj is an instance of LDAPEntry, or 0 if not. On error, returns -1 and sets an exception. */
int
LDAPEntry_Check(PyObject *obj) {
	if (obj == NULL) return -1;
	return PyObject_IsInstance(obj, (PyObject *)&LDAPEntryType);
}

/*	Returns a NULL-delimitered LDAPMod list for adds new or modificates existing LDAP entries.
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
		if (value == NULL) {
			Py_DECREF(iter);
			Py_DECREF(key);
			Py_DECREF(mods);
			return NULL;
		}

		/* Remove empty list values. */
		if (Py_SIZE((PyObject *)value) == 0) {
			if (LDAPEntry_SetItem(self, key, NULL) != 0) {
				Py_DECREF(iter);
				Py_DECREF(key);
				Py_DECREF(mods);
				return NULL;
			}
			value->status = 0;
		}

		if (value->status == 1) {
			/* LDAPMod for newly added attributes and values. */
			if (Py_SIZE((PyObject *)value->added) > 0) {
				if (LDAPModList_Add(mods, LDAP_MOD_ADD | LDAP_MOD_BVALUES,
						key, (PyObject *)value->added) != 0) {
					Py_DECREF(iter);
					Py_DECREF(key);
					Py_DECREF(mods);
					return NULL;
				}
			}
			/* LDAPMod for deleted values. */
			if (Py_SIZE((PyObject *)value->deleted) > 0) {
				if (LDAPModList_Add(mods, LDAP_MOD_DELETE | LDAP_MOD_BVALUES,
						key, (PyObject *)value->deleted) != 0) {
					Py_DECREF(iter);
					Py_DECREF(key);
					Py_DECREF(mods);
					return NULL;
				}
			}
		} else if (value->status == 2) {
			/* LDAPMod for replaced attributes. */
			if (LDAPModList_Add(mods, LDAP_MOD_REPLACE | LDAP_MOD_BVALUES,
					key, (PyObject *)value) != 0){
				Py_DECREF(iter);
				Py_DECREF(key);
				Py_DECREF(mods);
				return NULL;
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
}

static PyObject *
LDAPEntry_status(LDAPEntry *self) {
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
		if (value == NULL) {
			Py_DECREF(iter);
			Py_DECREF(key);
			Py_DECREF(result);
			return NULL;
		}

		status_dict = LDAPValueList_Status(value);
		if (status_dict == NULL) {
			Py_DECREF(iter);
			Py_DECREF(key);
			Py_DECREF(result);
			return NULL;
		}
		if (PyDict_SetItem(result, key, status_dict) != 0) {
			Py_DECREF(iter);
			Py_DECREF(key);
			Py_DECREF(status_dict);
			Py_DECREF(result);
			return NULL;
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
}

/*	Create a LDAPEntry from a LDAPMessage. */
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
	if (dn != NULL) {
		args = Py_BuildValue("sO", dn, (PyObject *)conn);
		ldap_memfree(dn);
		if (args == NULL) return NULL;
	}
	/* Create a new LDAPEntry, raise PyErr_NoMemory if it's failed. */
	ldapentry_type = load_python_object("pyldap.ldapentry", "LDAPEntry");
	if (ldapentry_type == NULL) return NULL;
	self = (LDAPEntry *)PyObject_CallObject(ldapentry_type, args);
	if (self == NULL) {
		return (LDAPEntry *)PyErr_NoMemory();
	}

	/* Get list of attribute's names, whose values have to keep in bytearray.*/
	rawval_list = UniqueList_New();
	tmp = PyObject_GetAttrString(conn->client, "_LDAPClient__raw_list");
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
		if (attrobj == NULL) {
			Py_DECREF(self);
			Py_DECREF(rawval_list);
			Py_DECREF(attrobj);
			ldap_memfree(attr);
			if (ber != NULL) {
				ber_free(ber, 0);
			}
			return (LDAPEntry *)PyErr_NoMemory();
		}
		values = ldap_get_values_len(conn->ld, entrymsg, attr);

		lvl = LDAPValueList_New();
		if (lvl == NULL){
			Py_DECREF(self);
			Py_DECREF(attrobj);
			Py_DECREF(rawval_list);
			ldap_memfree(attr);
			if (ber != NULL) {
				ber_free(ber, 0);
			}
			return (LDAPEntry *)PyErr_NoMemory();
		}
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
					Py_DECREF(self);
					Py_DECREF(attrobj);
					Py_DECREF(rawval_list);
					ldap_memfree(attr);
					if (ber != NULL) {
						ber_free(ber, 0);
					}
					return (LDAPEntry *)PyErr_NoMemory();
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
	ldap_memfree(attr);
	if (ber != NULL) {
		ber_free(ber, 0);
	}
	return self;
}

/* Preform a LDAP add or modify operation depend on the `mod` parameter.
   If `mod` is 0 then add new entry, otherwise modify it. */
PyObject *
LDAPEntry_AddOrModify(LDAPEntry *self, int mod) {
	int rc = -1;
	int msgid = -1;
	char msgidstr[8];
	char *dnstr = NULL;
	LDAPModList *mods = NULL;

	/* Get DN string. */
	dnstr = PyObject2char(self->dn);
	if (dnstr == NULL || strlen(dnstr) == 0) {
		PyErr_SetString(PyExc_AttributeError, "Missing distinguished name.");
		return NULL;
	}

	mods = LDAPEntry_CreateLDAPMods(self);
	if (mods == NULL) {
		PyErr_SetString(PyExc_MemoryError, "Create LDAPModList is failed.");
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
		PyObject *ldaperror = get_error_by_code(rc);
		PyErr_SetString(ldaperror, ldap_err2string(rc));
		Py_DECREF(ldaperror);
		Py_DECREF(mods);
		return NULL;
	}

	/* Add new add or modify operation to the pending_ops with mod_dict. */
	sprintf(msgidstr, "%d", msgid);
	if (PyDict_SetItemString(self->conn->pending_ops, msgidstr,
			(PyObject *)mods) != 0) {
		PyErr_BadInternalCall();
		Py_DECREF(mods);
		return NULL;
	}
	Py_DECREF(mods);

	return PyLong_FromLong((long int)msgid);
}

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

/* Remove all item from LDAPEntry. */
static PyObject *
LDAPEntry_clearitems(LDAPEntry *self) {
	PyObject *keys = PyDict_Keys((PyObject *)self);
	PyObject *iter = PyObject_GetIter(keys);
	PyObject *item;

	Py_DECREF(keys);

	if (iter == NULL) return NULL;

	/* Iterate over all key in the LDAPEntry. */
	for (item = PyIter_Next(iter); item != NULL; item = PyIter_Next(iter)) {
	    /* Remove item from the LDAPEntry. */
		if (LDAPEntry_SetItem(self, item, NULL) != 0) {
			Py_DECREF(item);
			return NULL;
		}
		Py_DECREF(item);
	}
	Py_DECREF(iter);

	return Py_None;
}

/* Remove entry from the directory server,
   change all LDAPValueList status to replaced (2) */
static PyObject *
LDAPEntry_delete(LDAPEntry *self) {
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

/* Has the same functionality like dict.get(),
   but with case-insensitive keymatch. */
static PyObject *
LDAPEntry_get(LDAPEntry *self, PyObject *args) {
	PyObject *key;
	PyObject *failobj = Py_None;
	PyObject *val = NULL;

	if (!PyArg_UnpackTuple(args, "get", 1, 2, &key, &failobj))
		return NULL;
	val = LDAPEntry_GetItem(self, key);
	if (val == NULL) val = failobj;

	Py_INCREF(val);
	return val;
}

/* Sends the modifications of the entry to the directory server. */
static PyObject *
LDAPEntry_modify(LDAPEntry *self) {
	/* Connection must be set. */
	if (self->conn == NULL) {
		PyErr_SetString(PyExc_AttributeError, "LDAPConnection is not set.");
		return NULL;
	}

	/* Connection must be open. */
	if (LDAPConnection_IsClosed(self->conn) != 0) return NULL;

	return LDAPEntry_AddOrModify(self, 1);
}

/* Removes and returns with the element from the LDAPEntry,
   just like the dict.pop() function. */
static PyObject *
LDAPEntry_pop(LDAPEntry *self, PyObject *args) {
    PyObject *old_value;
    PyObject *key, *deflt = NULL;

    if(!PyArg_UnpackTuple(args, "pop", 1, 2, &key, &deflt))
        return NULL;

    old_value = LDAPEntry_GetItem(self, key);

    if (old_value == NULL) {
    	/* Key is not in the LDAPEntry. */
    	if (deflt) {
    		Py_INCREF(deflt);
    		return deflt;
    	}
		PyErr_Format(PyExc_KeyError, "Key %R is not in the LDAPEntry.", key);
		return NULL;
	}
    /* Increment the item's reference, then remove it from the LDAPEntry. */
    Py_INCREF(old_value);
    LDAPEntry_SetItem(self, key, NULL);
    return old_value;
}

/* Has the same functionality like the dict.popitem() function. */
static PyObject *
LDAPEntry_popitem(LDAPEntry *self) {
	PyObject *res, *key, *value;
	PyObject *keys = PyDict_Keys((PyObject *)self);
	PyObject *iter = PyObject_GetIter(keys);

	Py_DECREF(keys);
	if (iter == NULL) return NULL;

	key = PyIter_Next(iter);
	Py_DECREF(iter);
	if (key == NULL) {
		PyErr_SetString(PyExc_KeyError, "popitem(): LDAPEntry is empty");
		return NULL;
	}

	value = LDAPEntry_GetItem(self, key);
	if (value == NULL) {
		Py_DECREF(key);
		return NULL;
	}
	Py_INCREF(value);

    res = PyTuple_New(2);
    if (res == NULL) {
    	Py_DECREF(key);
    	return NULL;
    }

    /* Stoles the reference, whatever that means. */
    PyTuple_SET_ITEM(res, 0, key);
    PyTuple_SET_ITEM(res, 1, value);

    if (LDAPEntry_SetItem(self, key, NULL) != 0) {
    	Py_DECREF(key);
    	return NULL;
    }
    Py_DECREF(key);
    return res;
}

/*	Set distinguished name for a LDAPEntry. */
static int
LDAPEntry_setDN(LDAPEntry *self, PyObject *value, void *closure) {
	PyObject *dn = NULL;

	if (value == NULL) {
        PyErr_SetString(PyExc_TypeError, "Cannot delete the DN attribute.");
        return -1;
    }

    if (PyUnicode_Check(value)) {
    	dn = PyObject_CallFunctionObjArgs(self->dntype, value, NULL);
		/* Check for valid DN. */
		if (dn == NULL) {
			return -1;
		} else {
			Py_DECREF(self->dn);
			self->dn = dn;
		}

    } else if (PyObject_IsInstance(value, self->dntype)) {
        Py_DECREF(self->dn);
        Py_INCREF(value);
        self->dn = value;
    } else {
    	PyErr_SetString(PyExc_TypeError, "The DN attribute value must be an LDAPDN or a string.");
    	return -1;
    }

    return 0;
}

/* Returns the DN of the LDAPEntry. */
static PyObject *
LDAPEntry_getDN(LDAPEntry *self, void *closure) {
    Py_INCREF(self->dn);
    return self->dn;
}

/* Renames the entry object on the directory server, which means changing
   the DN of the entry. */
static PyObject *
LDAPEntry_rename(LDAPEntry *self, PyObject *args, PyObject *kwds) {
	int rc;
	int msgid = -1;
	char msgidstr[8];
	char *newparent_str, *newrdn_str, *olddn_str;
	PyObject *newdn, *newparent, *newrdn;
	PyObject *tmp;
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

	/* Validate and set new LDAP DN. */
	if (LDAPEntry_setDN(self, newdn, NULL) != 0) return NULL;

	/* Get rdn and parent strings. */
	newrdn = PyObject_CallMethod(self->dn, "__getitem__", "(i)", 0);
	newparent = PyObject_CallMethod(self->dn, "_LDAPDN__get_ancestors", NULL);
	if (newrdn == NULL || newparent == NULL) return NULL;

	newrdn_str = PyObject2char(newrdn);
	newparent_str = PyObject2char(newparent);
	Py_DECREF(newrdn);
	Py_DECREF(newparent);

	rc = ldap_rename(self->conn->ld, olddn_str, newrdn_str, newparent_str, 1, NULL, NULL, &msgid);
	if (rc != LDAP_SUCCESS) {
		PyObject *ldaperror = get_error_by_code(rc);
		PyErr_SetString(ldaperror, ldap_err2string(rc));
		Py_DECREF(ldaperror);
		free(olddn_str);
		free(newrdn_str);
		free(newparent_str);
		return NULL;
	}
	free(olddn_str);
	free(newrdn_str);
	free(newparent_str);

	/* Add new rename operation to the pending_ops. */
	sprintf(msgidstr, "%d", msgid);
	if (PyDict_SetItemString(self->conn->pending_ops, msgidstr,
			Py_None) != 0) {
		PyErr_BadInternalCall();
		return NULL;
	}

	return PyLong_FromLong((long int)msgid);
}

/*	Updating LDAPEntry. Pretty much same as PyDict_Update function's codebase. */
static PyObject *
LDAPEntry_Update(LDAPEntry *self, PyObject *args, PyObject *kwds) {
	int rc = 0;
	PyObject *arg = NULL;

	if (!PyArg_UnpackTuple(args, "update", 0, 1, &arg)) {
		rc = -1;
	} else if (arg != NULL) {
		if (PyObject_HasAttrString(arg, "keys") || PyDict_Check(arg)) {
			/* If argument is a dict, use own function to update. */
			rc = LDAPEntry_UpdateFromDict(self, arg);
		} else {
			/* If argument is a sequence type, use own function to update. */
			rc = LDAPEntry_UpdateFromSeq2(self, arg);
		}
	}
	if (rc == 0 && kwds != NULL) {
		if (PyArg_ValidateKeywordArguments(kwds)) {
			/* If arguments are keywords, use own function to update. */
			rc = LDAPEntry_UpdateFromDict(self, kwds);
		} else {
			rc = -1;
		}
	}
	if (rc != -1) {
		Py_INCREF(Py_None); //Why?
		return Py_None;
	}
	return NULL;
}

/*	Update LDAPEntry form dict. Based on the PyDict_Merge function. */
int
LDAPEntry_UpdateFromDict(LDAPEntry *self, PyObject *dict) {
	int rc;
	PyObject *keys = PyMapping_Keys(dict);
	PyObject *iter;
	PyObject *key, *value;
	if (keys == NULL) return -1;

	iter = PyObject_GetIter(keys);
	Py_DECREF(keys);
	if (iter == NULL) return -1;

	/*Iterate over the dict keys, and get the values. */
	for (key = PyIter_Next(iter); key != NULL; key = PyIter_Next(iter)) {
		/* Return value: New reference. */
		value = PyObject_GetItem(dict, key);
		if (value == NULL) {
			Py_DECREF(iter);
			Py_DECREF(key);
			return -1;
		}
		/* Set the new key-value. */
		rc = LDAPEntry_SetItem(self, key, value);
		Py_DECREF(key);
		Py_DECREF(value);
		if (rc < 0) {
			Py_DECREF(iter);
			return -1;
		}
	}
	Py_DECREF(iter);
	if (PyErr_Occurred()) return -1;
    return 0;
}

/*	Update LDAPEntry form sequence. Based on the PyDict_MergeFromSeq2 function. */
int
LDAPEntry_UpdateFromSeq2(LDAPEntry *self, PyObject *seq2) {
    PyObject *iter;     /* iter(seq) */
    Py_ssize_t i = 0;   /* index into seq2 of current element */
    PyObject *item;     /* seq[i] */
    PyObject *fast;     /* item as a 2-tuple or 2-list */

    iter = PyObject_GetIter(seq2);
    if (iter == NULL) return -1;

    for (item = PyIter_Next(iter); item != NULL; item = PyIter_Next(iter)) {
        PyObject *key, *value;
        Py_ssize_t n;

        fast = NULL;
        if (PyErr_Occurred()) goto Fail;

        /* Convert item to sequence, and verify length 2. */
        fast = PySequence_Fast(item, "");
        if (fast == NULL) {
            if (PyErr_ExceptionMatches(PyExc_TypeError))
                PyErr_Format(PyExc_TypeError,
                    "cannot convert LDAPEntry update "
                    "sequence element #%zd to a sequence",
                    i);
            goto Fail;
        }
        n = PySequence_Fast_GET_SIZE(fast);
        if (n != 2) {
            PyErr_Format(PyExc_ValueError,
                         "LDAPEntry update sequence element #%zd "
                         "has length %zd; 2 is required",
                         i, n);
            goto Fail;
        }

        /* Update/merge with this (key, value) pair. */
        key = PySequence_Fast_GET_ITEM(fast, 0);
        value = PySequence_Fast_GET_ITEM(fast, 1);
		int status = LDAPEntry_SetItem(self, key, value);
		if (status < 0) goto Fail;
        Py_DECREF(fast);
        Py_DECREF(item);
    }
    i = 0;
    goto Return;
Fail:
    Py_XDECREF(item);
    Py_XDECREF(fast);
    i = -1;
Return:
    Py_DECREF(iter);
    return Py_SAFE_DOWNCAST(i, Py_ssize_t, int);
}

static PyMethodDef LDAPEntry_methods[] = {
	{"delete", 	(PyCFunction)LDAPEntry_delete,	METH_NOARGS,
			"Delete LDAPEntry on LDAP server."},
	{"clear",	(PyCFunction)LDAPEntry_clearitems,	METH_NOARGS,
			"Remove all items from LDAPEntry."},
	{"get",		(PyCFunction)LDAPEntry_get,		METH_VARARGS,
			"LDAPEntry.get(k[,d]) -> LDAPEntry[k] if k in D, else d. d defaults to None."},
	{"modify", 	(PyCFunction)LDAPEntry_modify, 	METH_NOARGS,
			"Send LDAPEntry's modification to the LDAP server."},
	{"pop",		(PyCFunction)LDAPEntry_pop,		METH_VARARGS,
			"LDAPEntry.pop(k[,d]) -> v, remove specified key and return the corresponding value.\n\
			If key is not found, d is returned if given, otherwise KeyError is raised"},
	{"popitem",	(PyCFunction)LDAPEntry_popitem,	METH_NOARGS,
			"LDAPEntry.popitem() -> (k, v), remove and return some (key, value) pair as a\n\
            2-tuple; but raise KeyError if D is empty."},
	{"rename", 	(PyCFunction)LDAPEntry_rename, 	METH_VARARGS | METH_KEYWORDS,
			"Rename or remove LDAPEntry on the LDAP server."},
    {"update", 	(PyCFunction)LDAPEntry_Update, 	METH_VARARGS | METH_KEYWORDS,
    		"Updating LDAPEntry from a dictionary." },
	{"_status", 	(PyCFunction)LDAPEntry_status, 	METH_NOARGS,
				"Get LDAPEntry's modifcation status." },
    {NULL, NULL, 0, NULL}  /* Sentinel */
};

/*	Searches among lower-cased keystrings to find a match with the key.
 	if `del` set to 1, then also search among the deleted keys.
  	Sets the `found` parameter's value to 1 if key found in the list, 0 otherwise. */
PyObject *
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
		if (lowerCaseMatch(item, key) == 1) {
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
			if (lowerCaseMatch(item, key) == 1) {
				*found = 1;
				Py_DECREF(item);
				break;
			}
			Py_DECREF(item);
		}
	}
	return key;
}

/*	Returns the object (with borrowed reference) from the LDAPEntry,
    which has a case-insensitive match. */
PyObject *
LDAPEntry_GetItem(LDAPEntry *self, PyObject *key) {
	int found;
	PyObject *match = searchLowerCaseKeyMatch(self, key, 0, &found);
	return PyDict_GetItem((PyObject *)self, match);
}

/*	This is the same as LDAPEntry_GetItem(), but key is specified as a char*. */
PyObject *
LDAPEntry_GetItemString(LDAPEntry *self, const char *key) {
	PyObject *keyobj = PyUnicode_FromString(key);
	return LDAPEntry_GetItem(self, keyobj);
}

/*	Set item to LDAPEntry with a case-insensitive key. */
int
LDAPEntry_SetItem(LDAPEntry *self, PyObject *key, PyObject *value) {
	int found = 0;
	int rc = 0;
	int status = 1;
	char *newkey = lowercase(PyObject2char(key));
	LDAPValueList *list;

	/* Search for a match. */
	key = searchLowerCaseKeyMatch(self, key, 1, &found);
	if (found == 1) {
		status = 2;
	}
	if (value != NULL) {
		/* If theres an item with a `dn` key, and with a string value set to the dn attribute. */
		if (strcmp(newkey, "dn") == 0) {
			if (PyUnicode_Check(value)) {
				char *dnstr = PyObject2char(value);
				LDAPEntry_SetStringDN(self, dnstr);
				free(dnstr);
			} else {
				PyErr_SetString(PyExc_TypeError, "Distinguished name must be string type.");
				Py_DECREF(key);
				return -1;
			}
		} else {
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
		/* This means, it has to remove the item. */
		if (PyDict_DelItem((PyObject *)self, key) != 0) return -1;
		if (UniqueList_Append(self->deleted, key) != 0) return -1;
	}
	return 0;
}

/* Checks that `key` is in the LDAPEntry. */
static int
LDAPEntry_contains(PyObject *op, PyObject *key) {
    int found = -1;
    PyObject *obj = NULL;
    LDAPEntry *self = (LDAPEntry *)op;

    obj = searchLowerCaseKeyMatch(self, key, 0, &found);
    if (obj == NULL) return -1;

    return found;
}

static PySequenceMethods LDAPEntry_as_sequence = {
    0,                          /* sq_length */
    0,                          /* sq_concat */
    0,                          /* sq_repeat */
    0,                          /* sq_item */
    0,                          /* sq_slice */
    0,                          /* sq_ass_item */
    0,                          /* sq_ass_slice */
    LDAPEntry_contains,         /* sq_contains */
    0,                          /* sq_inplace_concat */
    0,                          /* sq_inplace_repeat */
};


static PyObject *
LDAPEntry_subscript(LDAPEntry *self, PyObject *key) {
	PyObject *v = LDAPEntry_GetItem(self, key);
	if (v == NULL) {
		PyErr_Format(PyExc_KeyError, "Key %R is not in the LDAPEntry.", key);
		return NULL;
	}
	Py_INCREF(v);
	return v;
}

static int
LDAPEntry_ass_sub(LDAPEntry *self, PyObject *key, PyObject *value) {
    if (key == NULL) return PyDict_DelItem((PyObject *)self, key);
    else return LDAPEntry_SetItem(self, key, value);
}

static PyMappingMethods LDAPEntry_mapping_meths = {
	0, 									/* mp_length */
	(binaryfunc)LDAPEntry_subscript,	/* mp_subscript */
	(objobjargproc)LDAPEntry_ass_sub, 	/* mp_ass_subscript */
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

/*	Setter for connection attribute. */
static int
LDAPEntry_setConnection(LDAPEntry *self, PyObject *value, void *closure) {
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

/*	Getter for connection attribute. */
static PyObject *
LDAPEntry_getConnection(LDAPEntry *self, void *closure) {
	if (self->conn == NULL) {
		PyErr_SetString(PyExc_AttributeError, "LDAPConnection is not set.");
		return NULL;
	}
    Py_INCREF(self->conn);
    return (PyObject *)self->conn;
}

int
LDAPEntry_SetStringDN(LDAPEntry *self, char *value) {
	PyObject *dn = PyUnicode_FromString(value);
	if (dn == NULL) return -1;
	return LDAPEntry_setDN(self, dn, NULL);
}

static PyGetSetDef LDAPEntry_getsetters[] = {
	{"connection", 	(getter)LDAPEntry_getConnection,
					(setter)LDAPEntry_setConnection,
					"LDAP connection.", NULL},
	{"dn", 			(getter)LDAPEntry_getDN,
					(setter)LDAPEntry_setDN,
					"Distinguished name", NULL},
    {NULL}  /* Sentinel */
};

PyTypeObject LDAPEntryType = {
    PyObject_HEAD_INIT(NULL)
    "pyldap._LDAPEntry",      /* tp_name */
    sizeof(LDAPEntry),       /* tp_basicsize */
    0,                       /* tp_itemsize */
    (destructor)LDAPEntry_dealloc,       /* tp_dealloc */
    0,                       /* tp_print */
    0,                       /* tp_getattr */
    0,                       /* tp_setattr */
    0,                       /* tp_reserved */
    0,                       /* tp_repr */
    0,                       /* tp_as_number */
    &LDAPEntry_as_sequence,  /* tp_as_sequence */
    &LDAPEntry_mapping_meths,/* tp_as_mapping */
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
    (traverseproc)LDAPEntry_traverse,/* tp_traverse */
    (inquiry)LDAPEntry_clear, /* tp_clear */
    0,                       /* tp_richcompare */
    0,                       /* tp_weaklistoffset */
    0,                       /* tp_iter */
    0,                       /* tp_iternext */
    LDAPEntry_methods,       /* tp_methods */
    0,       				 /* tp_members */
    LDAPEntry_getsetters,    /* tp_getset */
    0,            			 /* tp_base */
    0,                       /* tp_dict */
    0,                       /* tp_descr_get */
    0,                       /* tp_descr_set */
    0,                       /* tp_dictoffset */
    (initproc)LDAPEntry_init,/* tp_init */
    0,                       /* tp_alloc */
    LDAPEntry_new,           /* tp_new */
};
