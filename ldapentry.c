#include "errors.h"
#include "utils.h"
#include "uniquelist.h"

#include "ldapentry.h"

static int
LDAPEntry_clear(LDAPEntry *self) {
    PyObject *tmp;

    tmp = (PyObject *)self->attributes;
    self->attributes = NULL;
    Py_XDECREF(tmp);

    tmp = (PyObject *)self->client;
    self->client = NULL;
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

/*	Deallocate the LDAPEntry. */
static void
LDAPEntry_dealloc(LDAPEntry* self) {;
    LDAPEntry_clear(self);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static int
LDAPEntry_traverse(LDAPEntry *self, visitproc visit, void *arg) {
	Py_VISIT(self->dn);
    Py_VISIT(self->deleted);
	Py_VISIT(self->attributes);
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
        /* Set an empty list for attributes. */
        self->attributes = UniqueList_New();
        if (self->attributes == NULL) {
			Py_DECREF(self);
			return NULL;
		}
        /* Set an empty list for deleted attributes. */
        self->deleted = UniqueList_New();
        if (self->deleted == NULL) {
			Py_DECREF(self);
			return NULL;
		}
        self->client = NULL;
	}
    return (PyObject *)self;
}

/*	Initializing LDAPEntry. */
static int
LDAPEntry_init(LDAPEntry *self, PyObject *args, PyObject *kwds) {
	PyObject *client = NULL;
	PyObject *dn = NULL, *tmp;
	LDAPDN dnstruct;
	static char *kwlist[] = {"dn", "client", NULL};
	char *dnstr;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|O", kwlist, &dn, &client)) {
		return -1;
	}

	/* Check for valid DN. */
	if (dn != NULL) {
		dnstr = PyObject2char(dn);
		if (ldap_str2dn(dnstr, &dnstruct, 0) != LDAP_SUCCESS) {
			PyErr_SetString(PyExc_AttributeError, "Invalid distinguished name.");
			return -1;
		}
	}

	if (client != NULL && PyObject_IsInstance(client, (PyObject *)&LDAPClientType) != 1) {
		PyErr_SetString(PyExc_TypeError, "Client must be an LDAPClient type.");
		return -1;
	}

	/* Just like in the Python doc example. */
	if (dn) {
		tmp = self->dn;
		Py_INCREF(dn);
		self->dn = dn;
		Py_XDECREF(tmp);
	}

	if (client) {
		tmp = (PyObject *)self->client;
		Py_INCREF(client);
		self->client = (LDAPClient *)client;
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
LDAPMod **
LDAPEntry_CreateLDAPMods(LDAPEntry *self) {
	int i = 0;
	Py_ssize_t j;
	LDAPMod *mod;
	LDAPMod **mods;
	PyObject *keys = PyMapping_Keys((PyObject *)self);
	PyObject *iter, *key;
	LDAPValueList *value;

	mods = (LDAPMod **)malloc(sizeof(LDAPMod *) * (Py_SIZE(self)*2 + 1));
	if (mods == NULL) return NULL;

	if (keys == NULL) return NULL;

	iter = PyObject_GetIter(keys);
	Py_DECREF(keys);
	if (iter == NULL) return NULL;

	for (key = PyIter_Next(iter); key != NULL; key = PyIter_Next(iter)) {
		/* Return value: New reference. */
		value = (LDAPValueList *)LDAPEntry_GetItem(self, key);
		if (value == NULL) {
			Py_DECREF(iter);
			Py_DECREF(key);
			return NULL;
		}
		if (value->status == 1) {
			/* LDAPMod for newly added attributes and values. */
			if (Py_SIZE((PyObject *)value->added) > 0) {
				mod = createLDAPModFromItem(LDAP_MOD_ADD | LDAP_MOD_BVALUES, key, (PyObject *)value->added);
				if (mod == NULL) return NULL;
				mods[i++] = mod;
			}
			/* LDAPMod for deleted values. */
			if (Py_SIZE((PyObject *)value->deleted) > 0) {
				mod = createLDAPModFromItem(LDAP_MOD_DELETE | LDAP_MOD_BVALUES, key, (PyObject *)value->deleted);
				if (mod == NULL) return NULL;
				mods[i++] = mod;
			}
		} else if (value->status == 2) {
			/* LDAPMod for replaced attributes. */
			mod = createLDAPModFromItem(LDAP_MOD_REPLACE | LDAP_MOD_BVALUES, key, (PyObject *)value);
			if (mod == NULL) return NULL;
			mods[i++] = mod;
		}
		Py_DECREF(key);
		Py_DECREF(value);
	}
	Py_DECREF(iter);
	/* LDAPMod for deleted attributes. */
	for (j = 0; j < Py_SIZE((PyObject *)self->deleted); j++) {
		mod = createLDAPModFromItem(LDAP_MOD_DELETE | LDAP_MOD_BVALUES, self->deleted->list.ob_item[j], NULL);
		Py_DECREF(self->deleted->list.ob_item[j]);
		if (mod == NULL) return NULL;
		mods[i++] = mod;
	}
	Py_DECREF(self->deleted);
	self->deleted = UniqueList_New();
	mods[i] = NULL;
	return mods;
}

/* Frees null-delimitered LDAPMod list. */
void
LDAPEntry_DismissLDAPMods(LDAPEntry *self, LDAPMod **mods) {
	int i, j;
	struct berval **bvals;
	LDAPValueList *val;

	for (i = 0; mods[i] != NULL; i++) {
		bvals = mods[i]->mod_vals.modv_bvals;
		if (bvals != NULL) {
			for (j = 0; bvals[j] != NULL; j++) {
				free(bvals[j]->bv_val);
				free(bvals[j]);
			}
		}
		/* Change attributes' status to "not changed" (-1). */
		val = (LDAPValueList *)LDAPEntry_GetItemString(self, mods[i]->mod_type);
		if (val != NULL) val->status = -1;
		free(mods[i]->mod_type);
		free(mods[i]);
	}
}

/*	Create a LDAPEntry from a LDAPMessage. */
LDAPEntry *
LDAPEntry_FromLDAPMessage(LDAPMessage *entrymsg, LDAPClient *client) {
	int i;
	char *dn;
	char *attr;
	struct berval **values;
	BerElement *ber;
	PyObject *val, *attrobj;
	LDAPValueList *lvl = NULL;
	LDAPEntry *self;

	/* Create a new LDAPEntry, raise PyErr_NoMemory if it's failed. */
	self = LDAPEntry_New();
	if (self == NULL) {
		return (LDAPEntry *)PyErr_NoMemory();
	}
	LDAPEntry_SetClient(self, client);
	/* Set the DN for LDAPEntry. */
	dn = ldap_get_dn(client->ld, entrymsg);
	if (dn != NULL) {
		LDAPEntry_SetStringDN(self, dn);
		ldap_memfree(dn);
	}

	/* Iterate over the LDAP attributes. */
	for (attr = ldap_first_attribute(client->ld, entrymsg, &ber);
		attr != NULL; attr = ldap_next_attribute(client->ld, entrymsg, ber)) {
		/* Create a string of attribute's name and add to the attributes list. */
		attrobj = PyUnicode_FromString(attr);
		if (attrobj == NULL || UniqueList_Append(self->attributes, attrobj) !=  0) {
			Py_DECREF(self);
			Py_XDECREF(attrobj);
			ldap_memfree(attr);
			if (ber != NULL) {
				ber_free(ber, 0);
			}
			return (LDAPEntry *)PyErr_NoMemory();
		}
		values = ldap_get_values_len(client->ld, entrymsg, attr);
		if (values != NULL) {
			lvl = LDAPValueList_New();
			if (lvl == NULL){
				Py_DECREF(self);
				Py_DECREF(attrobj);
				ldap_memfree(attr);
				if (ber != NULL) {
					ber_free(ber, 0);
				}
				return (LDAPEntry *)PyErr_NoMemory();
			}

			for (i = 0; values[i] != NULL; i++) {
				/* Convert berval to PyObject*, if it's failed skip it. */
				val = berval2PyObject(values[i]);
				if (val == NULL) continue;
				/* If the attribute has more value, then append to the list. */
				if (PyList_Append((PyObject *)lvl, val) != 0) {
					Py_DECREF(lvl);
					Py_DECREF(self);
					Py_DECREF(attrobj);
					ldap_memfree(attr);
					if (ber != NULL) {
						ber_free(ber, 0);
					}
					return (LDAPEntry *)PyErr_NoMemory();
				}
			}
			PyDict_SetItem((PyObject *)self, attrobj, (PyObject *)lvl);
		}
		ldap_value_free_len(values);
	}
	/* Cleaning the mess. */
	ldap_memfree(attr);
	if (ber != NULL) {
		ber_free(ber, 0);
	}
	return self;
}

/* Preform a LDAP add or modify operation depend on the `mod` parameter. */
PyObject *
add_or_modify(LDAPEntry *self, int mod) {
	int rc;
	char *dnstr = NULL;
	LDAPMod **mods = NULL;

	/* Get DN string. */
	dnstr = PyObject2char(self->dn);
	if (dnstr == NULL || strlen(dnstr) == 0) {
		PyErr_SetString(PyExc_AttributeError, "Missing distinguished name.");
		return NULL;
	}
	mods = LDAPEntry_CreateLDAPMods(self);
	if (mods == NULL) {
		PyErr_SetString(PyExc_MemoryError, "Create LDAPMods is failed.");
		return NULL;
	}

	if (mod == 0) {
		rc = ldap_add_ext_s(self->client->ld, dnstr, mods, NULL, NULL);
	} else {
		rc = ldap_modify_ext_s(self->client->ld, dnstr, mods, NULL, NULL);
	}
	if (rc != LDAP_SUCCESS) {
		//TODO Proper errors
		PyErr_SetString(LDAPError, ldap_err2string(rc));
		free(dnstr);
		return NULL;
	}
	free(dnstr);
	LDAPEntry_DismissLDAPMods(self, mods);
	return Py_None;
}

static PyObject *
LDAPEntry_add(LDAPEntry *self, PyObject *args, PyObject* kwds) {
	/* Client must be set. */
	if (self->client == NULL) {
		PyErr_SetString(PyExc_AttributeError, "LDAPClient is not set.");
		return NULL;
	}
	/* Client must be connected. */
	if (!self->client->connected) {
		PyErr_SetString(LDAPExc_NotConnected, "Client has to connect to the server first.");
		return NULL;
	}
	return add_or_modify(self, 0);
}

static PyObject *
LDAPEntry_delete(LDAPEntry *self, PyObject *args, PyObject *kwds) {
	char *dnstr;
	PyObject *keys = PyMapping_Keys((PyObject *)self);
	PyObject *iter, *key;
	LDAPValueList *value;

	/* Client must be set. */
	if (self->client == NULL) {
		PyErr_SetString(PyExc_AttributeError, "LDAPClient is not set.");
		return NULL;
	}

	dnstr = PyObject2char(self->dn);
	if (LDAPClient_DelEntryStringDN(self->client, dnstr) != 0) return NULL;

	if (keys == NULL) return NULL;

	iter = PyObject_GetIter(keys);
	Py_DECREF(keys);
	if (iter == NULL) return NULL;

	for (key = PyIter_Next(iter); key != NULL; key = PyIter_Next(iter)) {
		/* Return value: New reference. */
		value = (LDAPValueList *)LDAPEntry_GetItem(self, key);
		if (value == NULL) {
			Py_DECREF(iter);
			Py_DECREF(key);
			return NULL;
		}
		value->status = 2;
	}
	return Py_None;
}

static PyObject *
LDAPEntry_modify(LDAPEntry *self, PyObject *args, PyObject* kwds) {
	/* Client must be set. */
	if (self->client == NULL) {
		PyErr_SetString(PyExc_AttributeError, "LDAPClient is not set.");
		return NULL;
	}
	/* Client must be connected. */
	if (!self->client->connected) {
		PyErr_SetString(LDAPExc_NotConnected, "Client has to connect to the server first.");
		return NULL;
	}
	return add_or_modify(self, 1);
}

static PyObject *
LDAPEntry_rename(LDAPEntry *self, PyObject *args, PyObject *kwds) {
	int rc, i, j = 0;
	char *newdn, *newparent = NULL, *newrdn;
	char *tmp;
	char *kwlist[] = {"newdn", NULL};
	LDAPDN dn;

	/* Client must be set. */
	if (self->client == NULL) {
		PyErr_SetString(PyExc_AttributeError, "LDAPClient is not set.");
		return NULL;
	}
	/* Client must be connected. */
	if (!self->client->connected) {
		PyErr_SetString(LDAPExc_NotConnected, "Client has to connect to the server first.");
		return NULL;
	}

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "s", kwlist, &newdn)) {
		PyErr_SetString(PyExc_AttributeError, "Wrong parameter.");
		return NULL;
	}

	rc = ldap_str2dn(newdn, &dn, 0);
	if (rc != LDAP_SUCCESS) {
		PyErr_SetString(PyExc_AttributeError, "Invalid distinguished name.");
		return NULL;
	}

	newrdn = strdup(newdn);

	strtok(newrdn, ",");
	tmp = strchr(newdn, ',');

	if (tmp != NULL) {
		newparent = malloc(sizeof(char) * strlen(tmp));
		for (i = 1; tmp[i] != '\0'; i++) {
			newparent[j++] = tmp[i];
		}
		newparent[j] = '\0';
	}

	ldap_rename_s(self->client->ld, PyObject2char(self->dn), newrdn, newparent, 1, NULL, NULL);
	if (rc != LDAP_SUCCESS) {
		//TODO Proper errors
		PyErr_SetString(LDAPError, ldap_err2string(rc));
		free(newrdn);
		free(newparent);
		return NULL;
	}
	free(newrdn);
	free(newparent);
	return Py_None;
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
	{"add", 	(PyCFunction)LDAPEntry_add,		METH_NOARGS,	"Add new LDAPEntry to LDAP server."},
	{"delete", 	(PyCFunction)LDAPEntry_delete,	METH_NOARGS,	"Delete LDAPEntry on LDAP server."},
	{"modify", 	(PyCFunction)LDAPEntry_modify, 	METH_NOARGS,	"Send LDAPEntry's modification to the LDAP server."},
	{"rename", 	(PyCFunction)LDAPEntry_rename, 	METH_VARARGS | METH_KEYWORDS,	"Rename or remove LDAPEntry on the LDAP server."},
    {"update", 	(PyCFunction)LDAPEntry_Update, 	METH_VARARGS | METH_KEYWORDS,
    											"Updating LDAPEntry from a dictionary." },
    {NULL, NULL, 0, NULL}  /* Sentinel */
};

/*	Searches amongs lower-cased keystrings to find a match with the key.
  	Sets the `found` parameter's value to 1 if key found in the list, 0 otherwise. */
PyObject *
searchLowerCaseKeyMatch(LDAPEntry *self, PyObject *key, int* found) {
	PyObject *keys = PyDict_Keys((PyObject *)self);
	PyObject *iter = PyObject_GetIter(keys);
	PyObject *item;

	if (iter == NULL) return NULL;
	/* Searching for same lowercase key amongs the other keys. */
	for (item = PyIter_Next(iter); item != NULL; item = PyIter_Next(iter)) {
		if (lowerCaseMatch(item, key) == 1) {
			key = item;
			*found = 1;
			break;
		}
		*found = 0;
		Py_DECREF(item);
	}
	Py_DECREF(iter);
	return key;
}

/*	Return the object from the LDAPEntry, which has a case-insensitive match. */
PyObject *
LDAPEntry_GetItem(LDAPEntry *self, PyObject *key) {
	int found;
	PyObject *match = searchLowerCaseKeyMatch(self, key, &found);
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
	key = searchLowerCaseKeyMatch(self, key, &found);
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
			/* New key should be added to the attribute list. */
			if (found == 0) {
				if (UniqueList_Append(self->attributes, key) != 0) {
					Py_DECREF(key);
					return -1;
				}
			}
		}
	} else {
		/* This means, it has to remove the item. */
		if (PyDict_DelItem((PyObject *)self, key) != 0) return -1;
		if (UniqueList_Append(self->deleted, key) != 0) return -1;
		/* Remove from the attributes list. */
		if (PySequence_DelItem((PyObject *)self->attributes, PySequence_Index((PyObject *)self->attributes, key)) != 0) {
			Py_DECREF(key);
			return -1;
		}
	}
	Py_DECREF(key);
	return 0;
}

static PyObject *
LDAPEntry_subscript(LDAPEntry *self, PyObject *key) {
	PyObject *v = LDAPEntry_GetItem(self, key);
	if (v == NULL) {
		PyErr_Format(PyExc_KeyError, "Key '%R' is not in the LDAPEntry.", key);
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

/* Set LDAPClient for a LDAPEntry. */
int
LDAPEntry_SetClient(LDAPEntry *self, LDAPClient *client) {
	PyObject *tmp;

	if (client) {
		tmp = (PyObject *)self->client;
		Py_INCREF(client);
		self->client = client;
		Py_XDECREF(tmp);
	} else {
		return -1;
	}
	return 0;
}

/*	Setter for client attribute. */
static int
LDAPEntry_setClient(LDAPEntry *self, PyObject *value, void *closure) {
    if (value == NULL) {
        PyErr_SetString(PyExc_TypeError, "Cannot delete the client attribute.");
        return -1;
    }

    if (!PyObject_IsInstance(value, (PyObject *)&LDAPClientType)) {
        PyErr_SetString(PyExc_TypeError, "The client attribute value must be a LDAPClient.");
        return -1;
    }

    if (LDAPEntry_SetClient(self, (LDAPClient *)value) != 0) return -1;

    return 0;
}

/*	Getter for client attribute. */
static PyObject *
LDAPEntry_getClient(LDAPEntry *self, void *closure) {
	if (self->client == NULL) {
		return Py_None;
	}
    Py_INCREF(self->client);
    return (PyObject *)self->client;
}

/*	Set distinguished name for a LDAPEntry. */
static int
LDAPEntry_setDN(LDAPEntry *self, PyObject *value, void *closure) {
    if (value == NULL) {
        PyErr_SetString(PyExc_TypeError, "Cannot delete the DN attribute.");
        return -1;
    }

    if (!PyUnicode_Check(value)) {
        PyErr_SetString(PyExc_TypeError, "The DN attribute value must be a string.");
        return -1;
    }

    Py_DECREF(self->dn);
    Py_INCREF(value);
    self->dn = value;

    return 0;
}

static PyObject *
LDAPEntry_getDN(LDAPEntry *self, void *closure) {
    Py_INCREF(self->dn);
    return self->dn;
}

int
LDAPEntry_SetStringDN(LDAPEntry *self, char *value) {
	PyObject *dn = PyUnicode_FromString(value);
	if (dn == NULL) return -1;
	return LDAPEntry_setDN(self, dn, NULL);
}

static PyObject *
LDAPEntry_getAttributes(LDAPEntry *self, void *closure) {
    Py_INCREF(self->attributes);
    return (PyObject *)self->attributes;
}

static int
LDAPEntry_setAttributes(LDAPEntry *self, PyObject *value, void *closure) {
	if (value == NULL) {
		PyErr_SetString(PyExc_TypeError, "Cannot delete this attribute.");
		return -1;
	} else {
		PyErr_SetString(PyExc_TypeError, "Cannot change this attribute.");
		return -1;
	}
}

static PyGetSetDef LDAPEntry_getsetters[] = {
    {"attributes",	(getter)LDAPEntry_getAttributes,
    				(setter)LDAPEntry_setAttributes,
    				"Tuple of attributes", NULL},
	{"client", 		(getter)LDAPEntry_getClient,
					(setter)LDAPEntry_setClient,
					"LDAP client.", NULL},
	{"dn", 			(getter)LDAPEntry_getDN,
					(setter)LDAPEntry_setDN,
					"Distinguished name", NULL},
    {NULL}  /* Sentinel */
};

PyTypeObject LDAPEntryType = {
    PyObject_HEAD_INIT(NULL)
    "pyLDAP.LDAPEntry",      /* tp_name */
    sizeof(LDAPEntry),       /* tp_basicsize */
    0,                       /* tp_itemsize */
    (destructor)LDAPEntry_dealloc,       /* tp_dealloc */
    0,                       /* tp_print */
    0,                       /* tp_getattr */
    0,                       /* tp_setattr */
    0,                       /* tp_reserved */
    0,                       /* tp_repr */
    0,                       /* tp_as_number */
    0,                       /* tp_as_sequence */
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
    &PyDict_Type,            /* tp_base */
    0,                       /* tp_dict */
    0,                       /* tp_descr_get */
    0,                       /* tp_descr_set */
    0,                       /* tp_dictoffset */
    (initproc)LDAPEntry_init,/* tp_init */
    0,                       /* tp_alloc */
    LDAPEntry_new,           /* tp_new */
};
