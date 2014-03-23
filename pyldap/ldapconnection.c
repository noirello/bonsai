#include "ldapconnection.h"
#include "ldapentry.h"
#include "ldapsearchiter.h"
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
    LDAPConnection *self = NULL;

	self = (LDAPConnection *)type->tp_alloc(type, 0);
	if (self != NULL) {
        self->client = NULL;
    	self->async = 0;
    	self->page_size = 0;
	}

    return (PyObject *)self;
}

/*	Opens a connection to the LDAP server. Initializes LDAP structure.
	If TLS is true, starts TLS session.
*/
static int
connecting(LDAPConnection *self) {
	int rc = -1;
	int tls_option = -1;
	char *binddn = NULL;
	char *pswstr = NULL;
	char *mech = NULL;
	char *authzid = "";
	char *realm = NULL;
	char *authcid = NULL;
	PyObject *url = NULL;
	PyObject *tls = NULL;
	PyObject *tmp = NULL;
	PyObject *creds = NULL;

	url = PyObject_GetAttrString(self->client, "_LDAPClient__url");
	if (url == NULL) return -1;

	tmp = PyObject_GetAttrString(self->client, "_LDAPClient__cert_policy");
	tls_option = (int)PyLong_AsLong(tmp);
	Py_DECREF(tmp);

	rc = _LDAP_initialization(&(self->ld), url, tls_option);
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
			PyObject *ldaperror = get_error_by_code(rc);
			PyErr_SetString(ldaperror, ldap_err2string(rc));
			Py_DECREF(ldaperror);
			Py_DECREF(tls);
			return -1;
		}
	}
	Py_DECREF(tls);

	creds = PyObject_GetAttrString(self->client, "_LDAPClient__credentials");
	if (creds == NULL) return -1;

	tmp = PyObject_GetAttrString(self->client, "_LDAPClient__mechanism");
	if (tmp == NULL) return -1;
	mech = PyObject2char(tmp);
	Py_XDECREF(tmp);

	/* Get credential information, if it's given. */
	if (PyTuple_Check(creds) && PyTuple_Size(creds) > 1) {
		if (strcmp(mech, "SIMPLE") == 0) {
			tmp = PyTuple_GetItem(creds, 0);
			binddn = PyObject2char(tmp);
		} else {
			tmp = PyTuple_GetItem(creds, 0);
			authcid = PyObject2char(tmp);
			tmp = PyDict_GetItemString(creds, "realm");
			realm = PyObject2char(tmp);
		}
		tmp = PyTuple_GetItem(creds, 1);
		pswstr = PyObject2char(tmp);
	}

	if (authzid == NULL) authzid = "";

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
		Py_DECREF(creds);
		return -1;
	}
	Py_DECREF(creds);

	return 0;
}

/*	Initialize the LDAPConnection. */
static int
LDAPConnection_init(LDAPConnection *self, PyObject *args, PyObject *kwds) {
	PyObject *async_obj = NULL;
	PyObject *client = NULL;
	PyObject *ldapclient_type = NULL;
	PyObject *tmp = NULL;
	PyObject *page_size = NULL;
    static char *kwlist[] = {"client", "async", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|O!", kwlist, &client,
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
    	/* Get page size from the client. */
    	page_size = PyObject_GetAttrString(self->client, "_LDAPClient__page_size");
    	if (page_size == NULL) return -1;
    	self->page_size = (int)PyLong_AsLong(page_size);
    	Py_DECREF(page_size);
    	if (PyErr_Occurred()) return -1;
        return connecting(self);
    }
    return -1;
}

/*	Close connection. */
static PyObject *
LDAPConnection_Close(LDAPConnection *self) {
	int rc;

	rc = _LDAP_unbind(self->ld);
	if (rc != LDAP_SUCCESS) {
		PyObject *ldaperror = get_error_by_code(rc);
		PyErr_SetString(ldaperror, ldap_err2string(rc));
		Py_DECREF(ldaperror);
		return NULL;
	}
	return Py_None;
}

/* Add new LDAPEntry to the server. */
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
			PyObject *ldaperror = get_error_by_code(rc);
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
LDAPConnection_Searching(LDAPConnection *self, PyObject *iterator) {
	int rc;
	LDAPMessage *res, *entry;
	PyObject *entrylist;
	LDAPEntry *entryobj;
	LDAPControl *page_ctrl = NULL;
	LDAPControl **server_ctrls = NULL;
	LDAPControl **returned_ctrls;
	LDAPSearchIter *search_iter = (LDAPSearchIter *)iterator;

	entrylist = PyList_New(0);
	if (entrylist == NULL) {
		return PyErr_NoMemory();
	}

	if (self->page_size > 1) {
		/* Create page control and add to the server controls. */
		server_ctrls = (LDAPControl **)malloc(sizeof(LDAPControl *)*2);
		if (server_ctrls == NULL) return PyErr_NoMemory();
		rc = ldap_create_page_control(self->ld, (ber_int_t)(self->page_size),
				search_iter->cookie, 0, &page_ctrl);
		server_ctrls[0] = page_ctrl;
		server_ctrls[1] = NULL;
	}

	rc = ldap_search_ext_s(self->ld, search_iter->base,
				search_iter->scope,
				search_iter->filter,
				search_iter->attrs,
				search_iter->attrsonly,
				server_ctrls, NULL,
				search_iter->timeout,
				search_iter->sizelimit, &res);

	if (rc == LDAP_NO_SUCH_OBJECT) {
		return entrylist;
	}
	if (rc != LDAP_SUCCESS  && rc != LDAP_PARTIAL_RESULTS) {
		Py_DECREF(entrylist);
		PyObject *ldaperror = get_error_by_code(rc);
		PyErr_SetString(ldaperror, ldap_err2string(rc));
		Py_DECREF(ldaperror);
        return NULL;
	}

	rc = ldap_parse_result(self->ld, res, NULL, NULL, NULL, NULL, &returned_ctrls, 0);
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__)

	if (search_iter->cookie != NULL && search_iter->cookie->bv_val != NULL) {
    	ber_bvfree(search_iter->cookie);
    	search_iter->cookie = NULL;
    }
    rc = ldap_parse_page_control(self->ld, returned_ctrls, NULL, &(search_iter->cookie));
#else
	rc = ldap_parse_pageresponse_control(self->ld,
			ldap_control_find(LDAP_CONTROL_PAGEDRESULTS, returned_ctrls, NULL),
			NULL, search_iter->cookie);
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
		if ((entryobj == NULL) ||
				(PyList_Append(entrylist, (PyObject *)entryobj)) != 0) {
			Py_XDECREF(entryobj);
			Py_DECREF(entrylist);
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
	int scope = -1;
	int timeout, sizelimit, attrsonly = 0;
	char *basestr = NULL;
	char *filterstr = NULL;
	char **attrs = NULL;
	PyObject *attrlist  = NULL;
	PyObject *attrsonlyo = NULL;
	PyObject *url = NULL;
	LDAPSearchIter *search_iter = NULL;
	static char *kwlist[] = {"base", "scope", "filter", "attrlist", "timeout", "sizelimit", "attrsonly", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|sizOiiO!", kwlist, &basestr, &scope, &filterstr,
    		&attrlist, &timeout, &sizelimit, &PyBool_Type, &attrsonlyo)) {
		PyErr_SetString(PyExc_AttributeError,
				"Wrong parameters (base<str>, scope<int>, filter<str>, attrlist<List>, timeout<int>, attrsonly<bool>).");
        return NULL;
	}

    /* Get additional informations from the LDAP URL. */
    url = PyObject_GetAttrString(self->client, "_LDAPClient__url");
    if (url == NULL) return NULL;

    search_iter = LDAPSearchIter_New(self);
    if (search_iter == NULL) {
    	return PyErr_NoMemory();
    }

    if (basestr == NULL) {
    	PyObject *basedn = PyObject_GetAttrString(url, "basedn");
    	if (basedn == NULL) {
    		Py_DECREF(search_iter);
    	  	Py_DECREF(url);
    		return NULL;
    	}

    	if (basedn == Py_None) {
    		Py_DECREF(basedn);
    		PyErr_SetString(PyExc_AttributeError, "Search base DN cannot be None.");
    		Py_DECREF(search_iter);
    	  	Py_DECREF(url);
    		return NULL;
    	} else {
    		basestr = PyObject2char(basedn);
    		Py_DECREF(basedn);
    		if (basestr == NULL) {
    		  	Py_DECREF(url);
    		  	Py_DECREF(search_iter);
    			return NULL;
    		}
    	}
    }

    if (scope == -1) {
    	PyObject *scopeobj = PyObject_GetAttrString(url, "scope_num");
    	if (scopeobj == NULL) {
    	  	Py_DECREF(url);
    	  	Py_DECREF(search_iter);
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
			  	Py_DECREF(search_iter);
				return NULL;
			}
    	}
    }

    if (filterstr == NULL) {
    	PyObject *filter = PyObject_GetAttrString(url, "filter");
    	if (filter == NULL) {
    	  	Py_DECREF(url);
    	  	Py_DECREF(search_iter);
    		return NULL;
    	}
    	if (filter == Py_None) {
    		Py_DECREF(filter);
    	} else {
    		filterstr = PyObject2char(filter);
    		Py_DECREF(filter);
    		if (filterstr == NULL) {
    		  	Py_DECREF(url);
    		  	Py_DECREF(search_iter);
    			return NULL;
    		}
    	}
    }

    if (attrsonlyo != NULL) {
    	attrsonly = PyObject_IsTrue(attrsonlyo);
	}

    if (attrlist == NULL) {
    	PyObject *attr_list = PyObject_GetAttrString(url, "attributes");
    	if (attr_list == NULL) {
    		Py_DECREF(url);
    		Py_DECREF(search_iter);
    		return NULL;
    	}
    	attrs = PyList2StringList(attr_list);
    	Py_DECREF(attr_list);
    } else {
    	attrs = PyList2StringList(attrlist);
    }
	Py_DECREF(url);

	if (LDAPSearchIter_SetParams(search_iter, attrs, attrsonly, basestr,
			filterstr, scope, sizelimit, timeout) != 0) {
		Py_DECREF(url);
		Py_DECREF(search_iter);
		return NULL;
	}

	if (self->page_size > 0) {
		/* Create cookie for the page result. */
		search_iter->cookie = (struct berval *)malloc(sizeof(struct berval));
		if (search_iter->cookie == NULL) return PyErr_NoMemory();

		search_iter->cookie->bv_len = 0;
		search_iter->cookie->bv_val = NULL;
		/* Get the first page, and create an iterator for the next. */
		search_iter->buffer = LDAPConnection_Searching(self,
				(PyObject *)search_iter);

		if (search_iter->buffer == NULL) return NULL;
		return (PyObject *)search_iter;
	}

	return LDAPConnection_Searching(self, (PyObject *)search_iter);
}

static PyObject *
LDAPConnection_Whoami(LDAPConnection *self) {
	int rc = -1;
	struct berval *authzid = NULL;

	rc = ldap_whoami_s(self->ld, &authzid, NULL, NULL);
	if (rc != LDAP_SUCCESS) {
		PyObject *ldaperror = get_error_by_code(rc);
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
	{"add",	(PyCFunction)LDAPConnection_Add, METH_VARARGS,
			"Add new LDAPEntry to the LDAP server."},
	{"close", (PyCFunction)LDAPConnection_Close, METH_NOARGS,
			"Close connection with the LDAP Server."},
	{"delete", (PyCFunction)LDAPConnection_DelEntry, METH_VARARGS,
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
    "LDAPConnection object",   /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,  					   /* tp_iter */
    0,						   /* tp_iternext */
    LDAPConnection_methods,    /* tp_methods */
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
