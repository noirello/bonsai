#include "ldapclient.h"
#include "ldapentry.h"
#include "utils.h"

/*	Dealloc the LDAPClient object. */
static void
LDAPClient_dealloc(LDAPClient* self) {
    Py_XDECREF(self->url);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

/*	Create a new LDAPClient object. */
static PyObject *
LDAPClient_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
    LDAPClient *self;

	self = (LDAPClient *)type->tp_alloc(type, 0);
	if (self != NULL) {
		/* Create az empty python string for url. */
        self->url = PyUnicode_FromString("");
        if (self->url == NULL) {
            Py_DECREF(self);
            return NULL;
        }
	}
	self->connected = 0;
	self->tls = 0;
    return (PyObject *)self;
}

/*	Initialize the LDAPObject. */
static int
LDAPClient_init(LDAPClient *self, PyObject *args, PyObject *kwds) {
	int tls = 0;
	char *urlstr = NULL;
	PyObject *tlso = NULL;
	PyObject *ldapurl = NULL;
	PyObject *ldapurl_type = NULL;
	PyObject *scheme = NULL;
    static char *kwlist[] = {"url", "tls", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|sO!", kwlist, &urlstr, &PyBool_Type, &tlso)) {
    	return -1;
    }

    ldapurl_type = load_python_object("pyLDAP.ldapurl", "LDAPURL");
    if (ldapurl_type == NULL) return -1;

    ldapurl = PyObject_CallFunction(ldapurl_type, "s", urlstr);
    if (ldapurl == NULL) {
    	return -1;
    }
    self->url = ldapurl;

	if (tlso != NULL) {
		tls = PyObject_IsTrue(tlso);
	}

	self->connected = 0;
	self->tls = tls;
	scheme = PyObject_GetAttrString(ldapurl, "scheme");
	/* If connection uses SSL set TLS to 0, to avoid duplicated TLS session. */
	if (PyUnicode_CompareWithASCIIString(scheme, "ldaps") == 0) {
		self->tls = 0;
	}
	Py_DECREF(ldapurl_type);
	Py_DECREF(scheme);
    return 0;
}

/*	Opens a connection to the LDAP server. Initializes LDAP structure.
	If TLS is true, starts TLS session.
*/
static PyObject *
LDAPClient_Connect(LDAPClient *self, PyObject *args, PyObject *kwds) {
	int rc = -1;
	char *binddn = NULL;
	char *pswstr = NULL;
	char *mech = NULL;
	char *authzid = "";
	char *realm = NULL;
	char *authcid = NULL;
	static char *kwlist[] = {"binddn", "password", "mechanism", "username", "realm", "authname", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|ssssss", kwlist, &binddn, &pswstr, &mech, &authcid, &realm, &authzid)) {
		PyErr_SetString(PyExc_AttributeError, "Wrong parameters (binddn<str>, password<str>)");
		return NULL;
	}

	rc = _LDAP_initialization(&(self->ld), self->url);

	if (rc != LDAP_SUCCESS) {
		PyObject *ldaperror = get_error_by_code(rc);
		PyErr_SetString(ldaperror, ldap_err2string(rc));
		Py_DECREF(ldaperror);
		return NULL;
	}

	/* Start TLS, if it necessary. */
	if (self->tls == 1) {
		rc = ldap_start_tls_s(self->ld, NULL, NULL);
		if (rc != LDAP_SUCCESS) {
			//TODO Proper errors
			PyObject *ldaperror = get_error("LDAPError");
			PyErr_SetString(ldaperror, ldap_err2string(rc));
			Py_DECREF(ldaperror);
			return NULL;
		}
	}

	rc = _LDAP_bind_s(self->ld, mech, binddn, pswstr, authcid, realm, authzid);

	if (rc != LDAP_SUCCESS) {
		PyObject *ldaperror = get_error_by_code(rc);
		PyErr_SetString(ldaperror, ldap_err2string(rc));
		Py_DECREF(ldaperror);
		return NULL;
	}

	self->connected = 1;
	return Py_None;
}

/*	Close connection. */
static PyObject *
LDAPClient_Close(LDAPClient *self, PyObject *args, PyObject *kwds) {
	int rc;
	if (self->connected) {
		rc = _LDAP_unbind(self->ld);
		if (rc != LDAP_SUCCESS) {
			PyObject *ldaperror = get_error("LDAPError");
			PyErr_SetString(ldaperror, ldap_err2string(rc));
			Py_DECREF(ldaperror);
			return NULL;
		}
		self->connected = 0;
	}
	return Py_None;
}

/*	Delete an entry with the `dnstr` distinguished name on the server. */
int
LDAPClient_DelEntryStringDN(LDAPClient *self, char *dnstr) {
	int rc = LDAP_SUCCESS;

	if (!self->connected) {
		PyObject *ldaperror = get_error("NotConnected");
		PyErr_SetString(ldaperror, "Client has to connect to the server first.");
		Py_DECREF(ldaperror);
		return -1;
	}

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
LDAPClient_DelEntry(LDAPClient *self, PyObject *args, PyObject *kwds) {
	char *dnstr = NULL;
	static char *kwlist[] = {"dn", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "s", kwlist, &dnstr)) {
		PyErr_SetString(PyExc_AttributeError, "Wrong parameter.");
		return NULL;
	}

	if (LDAPClient_DelEntryStringDN(self, dnstr) != 0) return NULL;
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
searching(LDAPClient *self, char *basestr, int scope, char *filterstr, char **attrs,
		int attrsonly, int firstonly, int timeout, int sizelimit) {
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
		if (firstonly) {
			Py_DECREF(entrylist);
			return NULL;
		} else {
			return entrylist;
		}
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
		/* Return with the first entry. */
		if (firstonly == 1) {
			free(timelimit);
			return (PyObject *)entryobj;
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

/*	Return an LDAPEntry of the given distinguished name. */
static PyObject *
LDAPClient_GetEntry(LDAPClient *self, PyObject *args, PyObject *kwds) {
  	char *dnstr;
	PyObject *entry;
	static char *kwlist[] = {"dn", NULL};

	if (!self->connected) {
		PyObject *ldaperror = get_error("NotConnected");
		PyErr_SetString(ldaperror, "Client has to connect to the server first.");
		Py_DECREF(ldaperror);
		return NULL;
	}

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "s", kwlist, &dnstr)) {
		PyErr_SetString(PyExc_AttributeError, "Wrong parameter.");
		return NULL;
	}

	entry = searching(self, dnstr, LDAP_SCOPE_BASE, NULL, NULL, 0, 1, 0, 0);
	if (entry == NULL) {
		Py_INCREF(Py_None);
		return Py_None;
	}
	return entry;
}

/* Returns an LDAPEntry of the RootDSE. */
static PyObject *
LDAPClient_GetRootDSE(LDAPClient *self) {
	PyObject *rootdse;
	char *attrs[7];

	if (!self->connected) {
		PyObject *ldaperror = get_error("NotConnected");
		PyErr_SetString(ldaperror, "Client has to connect to the server first.");
		Py_DECREF(ldaperror);
		return NULL;
	}

	attrs[0] = "namingContexts";
  	attrs[1] = "altServer";
	attrs[2] = "supportedExtension";
  	attrs[3] = "supportedControl";
	attrs[4] = "supportedSASLMechanisms";
  	attrs[5] = "supportedLDAPVersion";
  	attrs[6] = NULL;
  	rootdse = searching(self, "", LDAP_SCOPE_BASE, "(objectclass=*)", attrs, 0, 1, 0, 0);
	return rootdse;
}

/* Searches for LDAP entries. */
static PyObject *
LDAPClient_Search(LDAPClient *self, PyObject *args, PyObject *kwds) {
	int scope;
	int timeout, sizelimit, attrsonly = 0;
	char *basestr, *filterstr = NULL;
	PyObject *entrylist;
	PyObject *attrlist  = NULL;
	PyObject *attrsonlyo = NULL;
	static char *kwlist[] = {"base", "scope", "filter", "attrlist", "timeout", "sizelimit", "attrsonly", NULL};

	if (!self->connected) {
		PyObject *ldaperror = get_error("NotConnected");
		PyErr_SetString(ldaperror, "Client has to connect to the server first.");
		Py_DECREF(ldaperror);
		return NULL;
	}

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "si|zOiiO!", kwlist, &basestr, &scope, &filterstr,
    		&attrlist, &timeout, &sizelimit, &PyBool_Type, &attrsonly)) {
		PyErr_SetString(PyExc_AttributeError,
				"Wrong parameters (base<str>, scope<str> [, filter<str>, attrlist<List>, timeout<int>, attrsonly<bool>]).");
        return NULL;
	}

    if (attrsonlyo != NULL) {
    	attrsonly = PyObject_IsTrue(attrsonlyo);
	}

	entrylist = searching(self, basestr, scope, filterstr, PyList2StringList(attrlist), attrsonly, 0, timeout, sizelimit);
	return entrylist;
}

#if !defined(WIN32) || !defined(_WIN32) || !defined(__WIN32__)
static PyObject *
LDAPClient_Whoami(LDAPClient *self) {
	int rc = -1;
	struct berval *authzid = NULL;

	if (!self->connected) {
		PyObject *ldaperror = get_error("NotConnected");
		PyErr_SetString(ldaperror, "Client has to connect to the server first.");
		Py_DECREF(ldaperror);
		return NULL;
	}
	rc = ldap_whoami_s(self->ld, &authzid, NULL, NULL);
	if (rc != LDAP_SUCCESS) {
		//TODO proper errors
		PyObject *ldaperror = get_error("LDAPError");
		PyErr_SetString(ldaperror, ldap_err2string(rc));
		Py_DECREF(ldaperror);
		return NULL;
	}
	if(authzid->bv_len == 0) {
		authzid->bv_val = "anonym";
		authzid->bv_len = 6;
	}
	return PyUnicode_FromString(authzid->bv_val);
}
#endif

static PyMemberDef LDAPClient_members[] = {
    {"url", T_OBJECT_EX, offsetof(LDAPClient, url), 0,
     "LDAP url"},
    {NULL}  /* Sentinel */
};

static PyMethodDef LDAPClient_methods[] = {
	{"close", (PyCFunction)LDAPClient_Close, METH_NOARGS,
	 "Close connection with the LDAP Server."
	},
	{"connect", (PyCFunction)LDAPClient_Connect,  METH_VARARGS | METH_KEYWORDS,
	 "Open a connection to the LDAP Server."
	},
	{"del_entry", (PyCFunction)LDAPClient_DelEntry, METH_VARARGS,
	"Delete an LDAPEntry with the given distinguished name."
	},
	{"get_entry", (PyCFunction)LDAPClient_GetEntry, METH_VARARGS | METH_KEYWORDS,
	"Return an LDAPEntry with the given distinguished name, or return None if the entry doesn't exist."
	},
	{"get_rootDSE", (PyCFunction)LDAPClient_GetRootDSE, METH_NOARGS,
	"Return an LDAPEntry of the RootDSE."
	},
	{"search", (PyCFunction)LDAPClient_Search, METH_VARARGS | METH_KEYWORDS,
	 "Searches for LDAP entries."
	},
#if !defined(WIN32) || !defined(_WIN32) || !defined(__WIN32__)
	{"whoami", (PyCFunction)LDAPClient_Whoami, METH_NOARGS,
	 "LDAPv3 Who Am I operation."
	},
#endif
    {NULL, NULL, 0, NULL}  /* Sentinel */
};

PyTypeObject LDAPClientType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pyLDAP.LDAPClient",       /* tp_name */
    sizeof(LDAPClient),        /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)LDAPClient_dealloc, /* tp_dealloc */
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
    "LDAPClient object",   	   /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    LDAPClient_methods,        /* tp_methods */
    LDAPClient_members,        /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)LDAPClient_init, /* tp_init */
    0,                         /* tp_alloc */
    LDAPClient_new,            /* tp_new */
};
