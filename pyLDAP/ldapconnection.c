#include "ldapconnection.h"
#include "ldapentry.h"
#include "utils.h"

/*	Dealloc the LDAPConnection object. */
static void
LDAPConnection_dealloc(LDAPConnection* self) {
    Py_XDECREF(self->client);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

/*	Create a new LDAPConnection object. */
static PyObject *
LDAPConnection_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
    LDAPConnection *self;

	self = (LDAPConnection *)type->tp_alloc(type, 0);
	if (self != NULL) {
        self->client = NULL;
	}
    return (PyObject *)self;
}

/*	Opens a connection to the LDAP server. Initializes LDAP structure.
	If TLS is true, starts TLS session.
*/
static int
connect(LDAPConnection *self) {
	int rc = -1;
	char *binddn = NULL;
	char *pswstr = NULL;
	char *mech = NULL;
	char *authzid = "";
	char *realm = NULL;
	char *authcid = NULL;
	PyObject *url = NULL;
	PyObject *tls = NULL;
	PyObject *tmp = NULL;
	PyObject *auth_dict = NULL;

	url = PyObject_GetAttrString(self->client, "_LDAPClient__url");
	if (url == NULL) return -1;

	rc = _LDAP_initialization(&(self->ld), url);
	Py_DECREF(url);

	if (rc != LDAP_SUCCESS) {
		PyObject *ldaperror = get_error_by_code(rc);
		PyErr_SetString(ldaperror, ldap_err2string(rc));
		Py_DECREF(ldaperror);
		return -1;
	}

	tls = PyObject_GetAttrString(self->client, "_LDAPClient__tls");
	if (tls == NULL) return -1;

	/* Start TLS, if it necessary. */
	if (PyObject_IsTrue(tls)) {
		rc = ldap_start_tls_s(self->ld, NULL, NULL);
		if (rc != LDAP_SUCCESS) {
			//TODO Proper errors
			PyObject *ldaperror = get_error("LDAPError");
			PyErr_SetString(ldaperror, ldap_err2string(rc));
			Py_DECREF(ldaperror);
			Py_DECREF(tls);
			return -1;
		}
	}
	Py_DECREF(tls);

	auth_dict = PyObject_GetAttrString(self->client, "_LDAPClient__auth_dict");
	if (auth_dict == NULL) return -1;


	tmp = PyObject_GetAttrString(self->client, "_LDAPClient__mechanism");
	if (tmp == NULL) return -1;
	mech = PyObject2char(tmp);
	Py_XDECREF(tmp);

	tmp = PyDict_GetItemString(auth_dict, "binddn");
	binddn = PyObject2char(tmp);

	tmp = PyDict_GetItemString(auth_dict, "password");
	pswstr = PyObject2char(tmp);

	tmp = PyDict_GetItemString(auth_dict, "authzid");
	authzid = PyObject2char(tmp);
	if (authzid == NULL) authzid = "";

	tmp = PyDict_GetItemString(auth_dict, "realm");
	realm = PyObject2char(tmp);

	tmp = PyDict_GetItemString(auth_dict, "authcid");
	authcid = PyObject2char(tmp);

	rc = _LDAP_bind_s(self->ld, mech, binddn, pswstr, authcid, realm, authzid);

	free(mech);
	free(binddn);
	free(pswstr);
	free(authcid);
	free(realm);
	if (strcmp(authzid, "") != 0) free(authzid);

	if (rc != LDAP_SUCCESS) {
		PyObject *ldaperror = get_error_by_code(rc);
		PyErr_SetString(ldaperror, ldap_err2string(rc));
		Py_DECREF(ldaperror);
		Py_DECREF(auth_dict);
		return -1;
	}

	Py_DECREF(auth_dict);
	return 0;
}

/*	Initialize the LDAPObject. */
static int
LDAPConnection_init(LDAPConnection *self, PyObject *args, PyObject *kwds) {
	PyObject *async_obj = NULL;
	PyObject *client = NULL;
	PyObject *ldapclient_type = NULL;
	PyObject *tmp = NULL;
    static char *kwlist[] = {"client", "async", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|OO!", kwlist, &client,
    		&PyBool_Type, &async_obj)) {
    	return -1;
    }

    ldapclient_type = load_python_object("pyLDAP.ldapclient", "LDAPClient");
    if (ldapclient_type == NULL ||
    		!PyObject_IsInstance(client, ldapclient_type)) {
    	return -1;
    }
	Py_DECREF(ldapclient_type);

    if (client) {
    	tmp = self->client;
    	Py_INCREF(client);
    	self->client = client;
    	Py_XDECREF(tmp);
    }

    return connect(self);
}

/*	Close connection. */
static PyObject *
LDAPConnection_Close(LDAPConnection *self, PyObject *args, PyObject *kwds) {
	int rc;

	rc = _LDAP_unbind(self->ld);
	if (rc != LDAP_SUCCESS) {
		PyObject *ldaperror = get_error("LDAPError");
		PyErr_SetString(ldaperror, ldap_err2string(rc));
		Py_DECREF(ldaperror);
		return NULL;
	}
	return Py_None;
}

/*	Delete an entry with the `dnstr` distinguished name on the server. */
int
LDAPConnection_DelEntryStringDN(LDAPConnection *self, char *dnstr) {
	int rc = LDAP_SUCCESS;

	if (dnstr != NULL) {
		rc = ldap_delete_ext_s(self->ld, dnstr, NULL, NULL);
		if (rc != LDAP_SUCCESS) {
			//TODO proper errors
			PyObject *ldaperror = get_error("LDAPError");
			PyErr_SetString(ldaperror, ldap_err2string(rc));
			Py_DECREF(ldaperror);
			return -1;
		}
	}
	return 0;
}
static PyObject *
LDAPConnection_DelEntry(LDAPConnection *self, PyObject *args, PyObject *kwds) {
	char *dnstr = NULL;
	static char *kwlist[] = {"dn", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "s", kwlist, &dnstr)) {
		PyErr_SetString(PyExc_AttributeError, "Wrong parameter.");
		return NULL;
	}

	if (LDAPConnection_DelEntryStringDN(self, dnstr) != 0) return NULL;
	return Py_None;
}

/*	LDAP search function for internal use. Returns a Python list of LDAPEntries.
	The `basestr` is the base DN of the searching, `scope` is the search scope (BASE|ONELEVEL|SUB),
	`filterstr` is the LDAP search filter string, `attrs` is a null-terminated string list of attributes'
	names to get only the selected attributes. If `attrsonly` is 1 get only attributes' name without values.
	If `firstonly` is 1, get only the first LDAP entry of the messages. The `timeout` is an integer of
	seconds for timelimit, `sizelimit` is a limit for size.
*/
PyObject *
searching(LDAPConnection *self, char *basestr, int scope, char *filterstr,
		char **attrs, int attrsonly, int timeout, int sizelimit) {
	int rc;
	struct timeval *timelimit;
	LDAPMessage *res, *entry;
	PyObject *entrylist;
	LDAPEntry *entryobj;

	entrylist = PyList_New(0);
	if (entrylist == NULL) {
		return PyErr_NoMemory();
	}

	/* Create a timeval, and set tv_sec to timeout, if timeout greater than 0. */
	if (timeout > 0) {
		timelimit = malloc(sizeof(struct timeval));
		if (timelimit != NULL) {
			timelimit->tv_sec = timeout;
			timelimit->tv_usec = 0;
		}
	} else {
		timelimit = NULL;
	}

	/* If empty filter string is given, set to NULL. */
	if (filterstr == NULL || strlen(filterstr) == 0) filterstr = NULL;
	rc = ldap_search_ext_s(self->ld, basestr, scope, filterstr, attrs, attrsonly, NULL,
						NULL, timelimit, sizelimit, &res);

	if (rc == LDAP_NO_SUCH_OBJECT) {
		free(timelimit);
		return entrylist;
	}
	if (rc != LDAP_SUCCESS) {
		Py_DECREF(entrylist);
		free(timelimit);
		//TODO proper errors
		PyObject *ldaperror = get_error("LDAPError");
		PyErr_SetString(ldaperror, ldap_err2string(rc));
		Py_DECREF(ldaperror);
        return NULL;
	}
	/* Iterate over the response LDAP messages. */
	for (entry = ldap_first_entry(self->ld, res);
		entry != NULL;
		entry = ldap_next_entry(self->ld, entry)) {
		entryobj = LDAPEntry_FromLDAPMessage(entry, self);
		if (entryobj == NULL) {
			Py_DECREF(entrylist);
			free(timelimit);
			return NULL;
		}
		/* Remove useless LDAPEntry. */
		if (PyList_Size((PyObject *)entryobj->attributes) == 0) {
			Py_DECREF(entryobj);
			continue;
		}
		if ((entryobj == NULL) ||
				(PyList_Append(entrylist, (PyObject *)entryobj)) != 0) {
			Py_XDECREF(entryobj);
			Py_XDECREF(entrylist);
			free(timelimit);
			return PyErr_NoMemory();
		}
		Py_DECREF(entryobj);
	}
	free(timelimit);
	return entrylist;
}

/* Searches for LDAP entries. */
static PyObject *
LDAPConnection_Search(LDAPConnection *self, PyObject *args, PyObject *kwds) {
	int scope = -1;
	int timeout, sizelimit, attrsonly = 0;
	char *basestr = NULL;
	char *filterstr = NULL;
	PyObject *entrylist;
	PyObject *attrlist  = NULL;
	PyObject *attrsonlyo = NULL;
	PyObject *url = NULL;
	static char *kwlist[] = {"base", "scope", "filter", "attrlist", "timeout", "sizelimit", "attrsonly", NULL};


    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|sizOiiO!", kwlist, &basestr, &scope, &filterstr,
    		&attrlist, &timeout, &sizelimit, &PyBool_Type, &attrsonlyo)) {
		PyErr_SetString(PyExc_AttributeError,
				"Wrong parameters (base<str>, scope<int>, filter<str>, attrlist<List>, timeout<int>, attrsonly<bool>).");
        return NULL;
	}

    url = PyObject_GetAttrString(self->client, "_LDAPClient__url");
    if (url == NULL) return NULL;

    if (basestr == NULL) {
    	PyObject *basedn = PyObject_GetAttrString(url, "basedn");
    	if (basedn == NULL) {
    	  	Py_DECREF(url);
    		return NULL;
    	}

    	if (basedn == Py_None) {
    		Py_DECREF(basedn);
    		PyErr_SetString(PyExc_AttributeError, "Search base DN cannot be None.");
    	  	Py_DECREF(url);
    		return NULL;
    	} else {
    		basestr = PyObject2char(basedn);
    		Py_DECREF(basedn);
    		if (basestr == NULL) {
    		  	Py_DECREF(url);
    			return NULL;
    		}
    	}
    }

    if (scope == -1) {
    	PyObject *scopeobj = PyObject_GetAttrString(url, "scope_num");
    	if (scopeobj == NULL) {
    	  	Py_DECREF(url);
    	  	free(basestr);
    		return NULL;
    	}

    	if (scopeobj == Py_None) {
    		Py_DECREF(scopeobj);
    	  	Py_DECREF(url);
    	  	free(basestr);
			PyErr_SetString(PyExc_AttributeError, "Search scope cannot be None.");
			return NULL;
    	} else {
    		scope = PyLong_AsLong(scopeobj);
			Py_DECREF(scopeobj);
			if (scope == -1) {
			  	Py_DECREF(url);
			  	free(basestr);
				return NULL;
			}
    	}
    }

    if (filterstr == NULL) {
    	PyObject *filter = PyObject_GetAttrString(url, "filter");
    	if (filter == NULL) {
    	  	Py_DECREF(url);
    	  	free(basestr);
    		return NULL;
    	}
    	if (filter == Py_None) {
    		Py_DECREF(filter);
    	} else {
    		filterstr = PyObject2char(filter);
    		Py_DECREF(filter);
    		if (filterstr == NULL) {
    		  	Py_DECREF(url);
    		  	free(basestr);
    			return NULL;
    		}
    	}
    }

    if (attrsonlyo != NULL) {
    	attrsonly = PyObject_IsTrue(attrsonlyo);
	}

    if (attrlist == NULL) {
    	attrlist = PyObject_GetAttrString(url, "attributes");
    }

	entrylist = searching(self, basestr, scope, filterstr, PyList2StringList(attrlist), attrsonly, timeout, sizelimit);
	Py_XDECREF(attrlist);
	return entrylist;
}

static PyObject *
LDAPConnection_Whoami(LDAPConnection *self) {
	int rc = -1;
	struct berval *authzid = NULL;

	rc = ldap_whoami_s(self->ld, &authzid, NULL, NULL);
	if (rc != LDAP_SUCCESS) {
		//TODO proper errors
		PyObject *ldaperror = get_error("LDAPError");
		PyErr_SetString(ldaperror, ldap_err2string(rc));
		Py_DECREF(ldaperror);
		return NULL;
	}

	if (authzid == NULL) return PyUnicode_FromString("anonym");

	if(authzid->bv_len == 0) {
		authzid->bv_val = "anonym";
		authzid->bv_len = 6;
	}
	return PyUnicode_FromString(authzid->bv_val);
}


static PyMethodDef LDAPConnection_methods[] = {
	{"close", (PyCFunction)LDAPConnection_Close, METH_NOARGS,
	 "Close connection with the LDAP Server."
	},
	{"del_entry", (PyCFunction)LDAPConnection_DelEntry, METH_VARARGS,
	"Delete an LDAPEntry with the given distinguished name."
	},
	{"search", (PyCFunction)LDAPConnection_Search, METH_VARARGS | METH_KEYWORDS,
	 "Searches for LDAP entries."
	},
	{"whoami", (PyCFunction)LDAPConnection_Whoami, METH_NOARGS,
	 "LDAPv3 Who Am I operation."
	},
    {NULL, NULL, 0, NULL}  /* Sentinel */
};

PyTypeObject LDAPConnectionType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pyLDAP.LDAPConnection",       /* tp_name */
    sizeof(LDAPConnection),        /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)LDAPConnection_dealloc, /* tp_dealloc */
    0,                         /* tp_print */
    0,                         /* tp_getattr */
    0,                         /* tp_setattr */
    0,                         /* tp_reserved */
    0,                         /* tp_repr */
    0,                         /* tp_as_number */
    0,                         /* tp_as_sequence */
    0,                         /* tp_as_mapping */
    0,                         /* tp_hash  */
    0,                         /* tp_call */
    0,                         /* tp_str */
    0,                         /* tp_getattro */
    0,                         /* tp_setattro */
    0,                         /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT |
        Py_TPFLAGS_BASETYPE,   /* tp_flags */
    "LDAPConnection object",   	   /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    LDAPConnection_methods,        /* tp_methods */
    0,        				   /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)LDAPConnection_init, /* tp_init */
    0,                         /* tp_alloc */
    LDAPConnection_new,            /* tp_new */
};
