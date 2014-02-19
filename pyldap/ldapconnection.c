#include "ldapconnection.h"
#include "ldapentry.h"
#include "utils.h"

/*	Dealloc the LDAPConnection object. */
static void
LDAPConnection_dealloc(LDAPConnection* self) {
    int i;

	Py_XDECREF(self->client);
    Py_XDECREF(self->buffer);
    if (self->search_params != NULL) {
		free(self->search_params->base);
		free(self->search_params->filter);
		free(self->search_params->timeout);
		if (self->search_params != NULL && self->search_params->attrs != NULL) {
			for (i = 0; self->search_params->attrs[i] != NULL; i++) {
				free(self->search_params->attrs[i]);
			}
			free(self->search_params->attrs);
		}
	}
    if (self->cookie != NULL) free(self->cookie);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

/*	Create a new LDAPConnection object. */
static PyObject *
LDAPConnection_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
    LDAPConnection *self = NULL;

	self = (LDAPConnection *)type->tp_alloc(type, 0);
	if (self != NULL) {
        self->client = NULL;
	}
	self->buffer = NULL;
	self->search_params = NULL;
	self->async = 0;
	self->page_size = 0;

    return (PyObject *)self;
}

/*	Opens a connection to the LDAP server. Initializes LDAP structure.
	If TLS is true, starts TLS session.
*/
static int
connecting(LDAPConnection *self) {
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

    if (async_obj != NULL) self->async = PyObject_IsTrue(async_obj);

    ldapclient_type = load_python_object("pyldap.ldapclient", "LDAPClient");
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

    return connecting(self);
}

/*	Close connection. */
static PyObject *
LDAPConnection_Close(LDAPConnection *self) {
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

/* Add new LDAPEntry to ther server. */
static PyObject *
LDAPConnection_Add(LDAPConnection *self, PyObject *args) {
	PyObject *param = NULL;

	if (!PyArg_ParseTuple(args, "O", &param)) {
		PyErr_SetString(PyExc_AttributeError, "Wrong parameter.");
		return NULL;
	}

	if (LDAPEntry_Check(param) != 1) {
		PyErr_SetString(PyExc_AttributeError, "Parameter must be an LDAPEntry");
		return NULL;
	}
	/* Set this connection to the LDAPEntry, before add to the server. */
	if (LDAPEntry_SetConnection((LDAPEntry *)param, self) == 0) {
		if (LDAPEntry_AddOrModify((LDAPEntry *)param, 0) != NULL) {
			return Py_None;
		}
	}

	return NULL;
}

/*	Delete an entry with the `dnstr` distinguished name on the server. */
int
LDAPConnection_DelEntryStringDN(LDAPConnection *self, char *dnstr) {
	int rc = LDAP_SUCCESS;

	if (dnstr != NULL) {
		rc = ldap_delete_ext_s(self->ld, dnstr, NULL, NULL);
		if (rc != LDAP_SUCCESS) {
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
searching(LDAPConnection *self) {
	int rc;
	LDAPMessage *res, *entry;
	PyObject *entrylist;
	LDAPEntry *entryobj;
	LDAPControl *page_ctrl = NULL;
	LDAPControl **server_ctrls = NULL;
	LDAPControl **returned_ctrls;

	entrylist = PyList_New(0);
	if (entrylist == NULL) {
		return PyErr_NoMemory();
	}

	if (self->page_size > 1) {
		/* Create page control and add to the server controls. */
		server_ctrls = (LDAPControl **)malloc(sizeof(LDAPControl *)*2);
		if (server_ctrls == NULL) return PyErr_NoMemory();
		rc = ldap_create_page_control(self->ld, (ber_int_t)(self->page_size),
						self->cookie, 0, &page_ctrl);
		server_ctrls[0] = page_ctrl;
		server_ctrls[1] = NULL;
	}

	rc = ldap_search_ext_s(self->ld, self->search_params->base,
									self->search_params->scope,
									self->search_params->filter,
									self->search_params->attrs,
									self->search_params->attrsonly,
									server_ctrls, NULL,
									self->search_params->timeout,
									self->search_params->sizelimit, &res);

	if (rc == LDAP_NO_SUCH_OBJECT) {
		return entrylist;
	}
	if (rc != LDAP_SUCCESS  && rc != LDAP_PARTIAL_RESULTS) {
		Py_DECREF(entrylist);
		PyObject *ldaperror = get_error("LDAPError");
		PyErr_SetString(ldaperror, ldap_err2string(rc));
		Py_DECREF(ldaperror);
        return NULL;
	}

	rc = ldap_parse_result(self->ld, res, NULL, NULL, NULL, NULL, &returned_ctrls, 0);
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__)

	if (self->cookie != NULL && self->cookie->bv_val != NULL) {
    	ber_bvfree(self->cookie);
    	self->cookie = NULL;
    }
    rc = ldap_parse_page_control(self->ld, returned_ctrls, NULL, &(self->cookie));
#else
	rc = ldap_parse_pageresponse_control(self->ld,
			ldap_control_find(LDAP_CONTROL_PAGEDRESULTS, returned_ctrls, NULL),
			NULL, self->cookie);
#endif
	/* Iterate over the response LDAP messages. */
	for (entry = ldap_first_entry(self->ld, res);
		entry != NULL;
		entry = ldap_next_entry(self->ld, entry)) {
		entryobj = LDAPEntry_FromLDAPMessage(entry, self);
		if (entryobj == NULL) {
			Py_DECREF(entrylist);
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
			return PyErr_NoMemory();
		}
		Py_DECREF(entryobj);
	}
	/* Cleanup. */
	if (returned_ctrls != NULL) ldap_controls_free(returned_ctrls);
	if (page_ctrl != NULL) ldap_control_free(page_ctrl);
	ldap_msgfree(res);
	return entrylist;
}

/* Searches for LDAP entries. */
static PyObject *
LDAPConnection_Search(LDAPConnection *self, PyObject *args, PyObject *kwds) {
	int i;
	int scope = -1;
	int timeout, sizelimit, attrsonly = 0;
	char *basestr = NULL;
	char *filterstr = NULL;
	PyObject *attrlist  = NULL;
	PyObject *attrsonlyo = NULL;
	PyObject *url = NULL;
	PyObject *sizeo = NULL;
	static char *kwlist[] = {"base", "scope", "filter", "attrlist", "timeout", "sizelimit", "attrsonly", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|sizOiiO!", kwlist, &basestr, &scope, &filterstr,
    		&attrlist, &timeout, &sizelimit, &PyBool_Type, &attrsonlyo)) {
		PyErr_SetString(PyExc_AttributeError,
				"Wrong parameters (base<str>, scope<int>, filter<str>, attrlist<List>, timeout<int>, attrsonly<bool>).");
        return NULL;
	}

    /* If search_param is already set, clear it, and set the new ones. */
    if (self->search_params != NULL) {
    	free(self->search_params->base);
    	free(self->search_params->filter);
    	free(self->search_params->timeout);
    	if (self->search_params->attrs != NULL) {
    		for (i = 0; self->search_params->attrs[i] != NULL; i++) {
    			free(self->search_params->attrs[i]);
    		}
    	}
    	free(self->search_params->attrs);
    }
    self->search_params = (SearchParams *)malloc(sizeof(SearchParams));
    if (self->search_params == NULL) return PyErr_NoMemory();

    /* Create a timeval, and set tv_sec to timeout, if timeout greater than 0. */
    if (timeout > 0) {
    	self->search_params->timeout = malloc(sizeof(struct timeval));
		if (self->search_params->timeout != NULL) {
			self->search_params->timeout->tv_sec = timeout;
			self->search_params->timeout->tv_usec = 0;
		}
	} else {
		self->search_params->timeout = NULL;
	}

    self->search_params->sizelimit = sizelimit;

    /* Get additional informations from the LDAP URL. */
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
    self->search_params->base = (char *)malloc(sizeof(char) * (strlen(basestr)+1));
    strcpy(self->search_params->base, basestr);

    if (scope == -1) {
    	PyObject *scopeobj = PyObject_GetAttrString(url, "scope_num");
    	if (scopeobj == NULL) {
    	  	Py_DECREF(url);
    		return NULL;
    	}

    	if (scopeobj == Py_None) {
    		Py_DECREF(scopeobj);
    	  	Py_DECREF(url);
			PyErr_SetString(PyExc_AttributeError, "Search scope cannot be None.");
			return NULL;
    	} else {
    		scope = PyLong_AsLong(scopeobj);
			Py_DECREF(scopeobj);
			if (scope == -1) {
			  	Py_DECREF(url);
				return NULL;
			}
    	}
    }
    self->search_params->scope = scope;

    if (filterstr == NULL) {
    	PyObject *filter = PyObject_GetAttrString(url, "filter");
    	if (filter == NULL) {
    	  	Py_DECREF(url);
    		return NULL;
    	}
    	if (filter == Py_None) {
    		Py_DECREF(filter);
    	} else {
    		filterstr = PyObject2char(filter);
    		Py_DECREF(filter);
    		if (filterstr == NULL) {
    		  	Py_DECREF(url);
    			return NULL;
    		}
    	}
    }

    /* If empty filter string is given, set to NULL. */
	if (filterstr == NULL || strlen(filterstr) == 0) {
		self->search_params->filter = NULL;
	} else {
	    self->search_params->filter = (char *)malloc(sizeof(char) * (strlen(filterstr)+1));
	    strcpy(self->search_params->filter, filterstr);
	}

    if (attrsonlyo != NULL) {
    	attrsonly = PyObject_IsTrue(attrsonlyo);
	}
    self->search_params->attrsonly = attrsonly;

    if (attrlist == NULL) {
    	PyObject *attr_list = PyObject_GetAttrString(url, "attributes");
    	if (attr_list == NULL) {
    		Py_DECREF(url);
    		return NULL;
    	}
    	self->search_params->attrs = PyList2StringList(attr_list);
    	Py_DECREF(attr_list);
    } else {
    	self->search_params->attrs = PyList2StringList(attrlist);
    }
	Py_DECREF(url);

	/* Get page size, and if it's set create cookie for page result control */
	sizeo = PyObject_GetAttrString(self->client, "_LDAPClient__page_size");
	if (sizeo == NULL) return NULL;
	self->page_size = (int)PyLong_AsLong(sizeo);
	Py_DECREF(sizeo);
	if (PyErr_Occurred()) return NULL;

	if (self->page_size > 0) {
		/* Create cookie for the page result. */
		self->cookie = (struct berval *)malloc(sizeof(struct berval));
		if (self->cookie == NULL) return PyErr_NoMemory();
		self->cookie->bv_len = 0;
		self->cookie->bv_val = NULL;
		/* Get the first page, and create an iterator for the next. */
		self->buffer = searching(self);
		if (self->buffer == NULL) return NULL;
		return (PyObject *)self;
	}

	return searching(self);
}

static PyObject *
LDAPConnection_Whoami(LDAPConnection *self) {
	int rc = -1;
	struct berval *authzid = NULL;

	rc = ldap_whoami_s(self->ld, &authzid, NULL, NULL);
	if (rc != LDAP_SUCCESS) {
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

PyObject*
LDAPConnection_getiter(LDAPConnection *self) {
    Py_INCREF(self);
	return (PyObject*)self;
}

PyObject*
LDAPConnection_iternext(LDAPConnection *self) {
	PyObject *item = NULL;

	if (Py_SIZE(self->buffer) != 0) {
		/* Get first element from the buffer list. */
		item = PyObject_CallMethod(self->buffer, "pop", "(i)", 0);
		if (item != NULL) return item;
	} else {
		Py_DECREF(self->buffer);
		if ((self->cookie->bv_val != NULL) &&
				(strlen(self->cookie->bv_val) > 0)) {
			/* Get the next page of the search. */
			self->buffer = searching(self);
			if (self->buffer == NULL) return NULL;
			item = PyObject_CallMethod(self->buffer, "pop", "(i)", 0);
			if (item != NULL) {
				return item;
			} else return NULL;
		} else {
			ber_bvfree(self->cookie);
			self->cookie = NULL;
			return NULL;
		}
	}
	return NULL;
}

static PyMethodDef LDAPConnection_methods[] = {
	{"add",	(PyCFunction)LDAPConnection_Add, METH_VARARGS,
			"Add new LDAPEntry to the LDAP server."},
	{"close", (PyCFunction)LDAPConnection_Close, METH_NOARGS,
			"Close connection with the LDAP Server."},
	{"del_entry", (PyCFunction)LDAPConnection_DelEntry, METH_VARARGS,
			"Delete an LDAPEntry with the given distinguished name."},
	{"search", (PyCFunction)LDAPConnection_Search, 	METH_VARARGS | METH_KEYWORDS,
			"Searches for LDAP entries."},
	{"whoami", (PyCFunction)LDAPConnection_Whoami, METH_NOARGS,
			"LDAPv3 Who Am I operation."},
    {NULL, NULL, 0, NULL}  /* Sentinel */
};

PyTypeObject LDAPConnectionType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pyldap.LDAPConnection",       /* tp_name */
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
    (getiterfunc)LDAPConnection_getiter,  /* tp_iter */
    (iternextfunc)LDAPConnection_iternext,/* tp_iternext */
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
