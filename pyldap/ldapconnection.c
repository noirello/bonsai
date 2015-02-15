#include "ldapconnection.h"
#include "ldapentry.h"
#include "ldapsearchiter.h"
#include "utils.h"

/*	Dealloc the LDAPConnection object. */
static void
LDAPConnection_dealloc(LDAPConnection* self) {
	int i = 0;
	Py_XDECREF(self->client);
	Py_XDECREF(self->pending_ops);

	/* Free LDAPSortKey list. */
	if (self->sort_list !=  NULL) {
		for (i = 0; self->sort_list[i] != NULL; i++) {
			free(self->sort_list[i]->attributeType);
			free(self->sort_list[i]);
		}
		free(self->sort_list);
	}

	Py_TYPE(self)->tp_free((PyObject*)self);
}

/*	Create a new LDAPConnection object. */
static PyObject *
LDAPConnection_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
	LDAPConnection *self = NULL;

	self = (LDAPConnection *)type->tp_alloc(type, 0);
	if (self != NULL) {
		self->client = NULL;
		self->pending_ops = NULL;
		self->page_size = 0;
		self->closed = -1;
		self->sort_list = NULL;
	}

	return (PyObject *)self;
}

/* Check, that the connection is not closed.
   Set Python exception if it is.
*/
int
LDAPConnection_IsClosed(LDAPConnection *self) {
	if (self->closed) {
		/* The connection is closed. */
		PyObject *ldaperror = get_error_by_code(-11);
		PyErr_SetString(ldaperror, "The connection is already closed.");
		Py_DECREF(ldaperror);
		return 1;
	}
	return 0;
}

/*	Open a connection to the LDAP server. Initializes LDAP structure.
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

	/* Get URL policy from LDAPClient. */
	url = PyObject_GetAttrString(self->client, "_LDAPClient__url");
	if (url == NULL) return -1;

	/* Get cert policy from LDAPClient. */
	tmp = PyObject_GetAttrString(self->client, "_LDAPClient__cert_policy");
	tls_option = (int)PyLong_AsLong(tmp);
	Py_DECREF(tmp);

	rc = LDAP_initialization(&(self->ld), url, tls_option);
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
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__)
		rc = ldap_start_tls_sA(self->ld, NULL, NULL, NULL, NULL);
#else
		rc = ldap_start_tls_s(self->ld, NULL, NULL);
#endif
		if (rc != LDAP_SUCCESS) {
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

	rc = LDAP_bind(self->ld, mech, binddn, pswstr, authcid, realm, authzid);

	/* Clean up. */
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
	self->closed = 0;
	return 0;
}

/*	Initialize the LDAPConnection. */
static int
LDAPConnection_init(LDAPConnection *self, PyObject *args, PyObject *kwds) {
	PyObject *client = NULL;
	PyObject *ldapclient_type = NULL;
	PyObject *tmp = NULL;
	static char *kwlist[] = {"client", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &client)) {
		return -1;
	}

	/* Validate that the Python object parameter is type of an LDAPClient. */
	ldapclient_type = load_python_object("pyldap.ldapclient", "LDAPClient");
	if (ldapclient_type == NULL ||
		!PyObject_IsInstance(client, ldapclient_type)) {
		return -1;
	}
	Py_DECREF(ldapclient_type);

	/* Create a dict for pending LDAP operations. */
	self->pending_ops = PyDict_New();
	if (self->pending_ops == NULL) return -1;

	if (client) {
		tmp = self->client;
		Py_INCREF(client);
		self->client = client;
		Py_XDECREF(tmp);

		return connecting(self);
	}
	return -1;
}

/*	Close connection. */
static PyObject *
LDAPConnection_Close(LDAPConnection *self) {
	int rc;
	int msgid;
	PyObject *keys = PyDict_Keys(self->pending_ops);
	PyObject *iter, *key;
	PyObject *ldaperror = NULL;

	if (keys == NULL) return NULL;

	if (self->closed == 1) {
		/* Connection is already close, nothing to do. */
		Py_DECREF(keys);
		return Py_None;
	}

	iter = PyObject_GetIter(keys);
	Py_DECREF(keys);
	if (iter == NULL) return NULL;

	for (key = PyIter_Next(iter); key != NULL; key = PyIter_Next(iter)) {
		/* Key should be an integer by design, if it is not rather not process. */
		if (!PyLong_Check(key)) continue;
		msgid = (int)PyLong_AsLong(key);
		/* Remove item from the dict. */
		if (PyDict_DelItem(self->pending_ops, key) != 0) {
			Py_DECREF(iter);
			Py_DECREF(key);
			PyErr_BadInternalCall();
			return NULL;
		}
		Py_DECREF(key);

		/* Skip negatives, cause assertion error. */
		if (msgid <= 0) continue;
		/* Abandon the pending operations from the server. */
		rc = LDAP_abandon(self->ld, msgid);
		if (rc != LDAP_SUCCESS) {
			Py_DECREF(iter);
			ldaperror = get_error_by_code(rc);
			PyErr_SetString(ldaperror, ldap_err2string(rc));
			Py_DECREF(ldaperror);
			return NULL;
		}
	}
	Py_DECREF(iter);

	rc = LDAP_unbind(self->ld);
	if (rc != LDAP_SUCCESS) {
		ldaperror = get_error_by_code(rc);
		PyErr_SetString(ldaperror, ldap_err2string(rc));
		Py_DECREF(ldaperror);
		return NULL;
	}
	self->closed = 1;
	return Py_None;
}

/* Add new LDAPEntry to the server. */
static PyObject *
LDAPConnection_Add(LDAPConnection *self, PyObject *args) {
	PyObject *param = NULL;
	PyObject *msgid = NULL;

	if (LDAPConnection_IsClosed(self) != 0) return NULL;

	if (!PyArg_ParseTuple(args, "O", &param)) {
		PyErr_SetString(PyExc_AttributeError, "Wrong parameter.");
		return NULL;
	}

	/* Validate parameter. */
	if (LDAPEntry_Check(param) != 1) {
		PyErr_SetString(PyExc_AttributeError, "Parameter must be an LDAPEntry");
		return NULL;
	}
	/* Set this connection to the LDAPEntry, before add to the server. */
	if (LDAPEntry_SetConnection((LDAPEntry *)param, self) == 0) {
		msgid = LDAPEntry_AddOrModify((LDAPEntry *)param, 0);
		if (msgid != NULL) {
			return msgid;
		}
	}

	return NULL;
}

/*	Delete an entry with the `dnstr` distinguished name on the server. */
int
LDAPConnection_DelEntryStringDN(LDAPConnection *self, char *dnstr) {
	int msgid = -1;
	int rc = LDAP_SUCCESS;

	if (dnstr != NULL) {
		rc = ldap_delete_ext(self->ld, dnstr, NULL, NULL, &msgid);
		if (rc != LDAP_SUCCESS) {
			PyObject *ldaperror = get_error_by_code(rc);
			PyErr_SetString(ldaperror, ldap_err2string(rc));
			Py_DECREF(ldaperror);
			return -1;
		}
		/* Add new delete operation to the pending_ops. */
		if (addToPendingOps(self->pending_ops, msgid,  Py_None) != 0) {
			return -1;
		}
		return msgid;
	}
	return -1;
}

static PyObject *
LDAPConnection_DelEntry(LDAPConnection *self, PyObject *args, PyObject *kwds) {
	char *dnstr = NULL;
	int msgid = -1;
	static char *kwlist[] = {"dn", NULL};

	if (LDAPConnection_IsClosed(self) != 0) return NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "s", kwlist, &dnstr)) {
		PyErr_SetString(PyExc_AttributeError, "Wrong parameter.");
		return NULL;
	}

	msgid = LDAPConnection_DelEntryStringDN(self, dnstr);
	if (msgid < 0) return NULL;

	return PyLong_FromLong((long int)msgid);
}

int
LDAPConnection_Searching(LDAPConnection *self, PyObject *iterator) {
	int rc;
	int msgid = -1;
	int num_of_ctrls = 0;
	LDAPControl *page_ctrl = NULL;
	LDAPControl *sort_ctrl = NULL;
	LDAPControl **server_ctrls = NULL;
	LDAPSearchIter *search_iter = (LDAPSearchIter *)iterator;

	/* Check the number of server controls and allocate it. */
	if (self->page_size > 1) num_of_ctrls++;
	if (self->sort_list != NULL) num_of_ctrls++;
	if (num_of_ctrls > 0) {
		server_ctrls = (LDAPControl **)malloc(sizeof(LDAPControl *)
				* (num_of_ctrls + 1));
		if (server_ctrls == NULL) {
			PyErr_NoMemory();
			return -1;
		}
		num_of_ctrls = 0;
	}

	if (self->page_size > 1) {
		/* Create page control and add to the server controls. */
		rc = ldap_create_page_control(self->ld, self->page_size,
				search_iter->cookie, 0, &page_ctrl);
		if (rc != LDAP_SUCCESS) {
			PyErr_BadInternalCall();
			return -1;
		}
		server_ctrls[num_of_ctrls++] = page_ctrl;
		server_ctrls[num_of_ctrls] = NULL;
	}

	if (self->sort_list != NULL) {
		rc = ldap_create_sort_control(self->ld, self->sort_list, 0, &sort_ctrl);
		if (rc != LDAP_SUCCESS) {
			PyErr_BadInternalCall();
			return -1;
		}
		server_ctrls[num_of_ctrls++] = sort_ctrl;
		server_ctrls[num_of_ctrls] = NULL;
	}

	rc = ldap_search_ext(self->ld, search_iter->base,
				search_iter->scope,
				search_iter->filter,
				search_iter->attrs,
				search_iter->attrsonly,
				server_ctrls, NULL,
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__)
				search_iter->timeout->tv_sec,
#else
				search_iter->timeout,
#endif
				search_iter->sizelimit, &msgid);

	if (rc != LDAP_SUCCESS) {
			PyObject *ldaperror = get_error_by_code(rc);
			PyErr_SetString(ldaperror, ldap_err2string(rc));
			Py_DECREF(ldaperror);
			return -1;
	}

	if (addToPendingOps(self->pending_ops, msgid,  Py_None) != 0) {
		return -1;
	}

	/* Cleanup. */
	if (page_ctrl != NULL) ldap_control_free(page_ctrl);
	if (sort_ctrl != NULL) ldap_control_free(sort_ctrl);
	if (server_ctrls != NULL) free(server_ctrls);

	return msgid;
}

/* Search for LDAP entries. */
static PyObject *
LDAPConnection_Search(LDAPConnection *self, PyObject *args, PyObject *kwds) {
	int scope = -1;
	int msgid = -1;
	int timeout = 0, sizelimit = 0, attrsonly = 0;
	char *basestr = NULL;
	char *filterstr = NULL;
	char **attrs = NULL;
	PyObject *attrlist  = NULL;
	PyObject *attrsonlyo = NULL;
	LDAPSearchIter *search_iter = NULL;
	PyObject *page_size = NULL, *sort_list = NULL;
	static char *kwlist[] = {"base", "scope", "filter", "attrlist", "timeout", "sizelimit", "attrsonly", NULL};

	if (LDAPConnection_IsClosed(self) != 0) return NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|zizO!iiO!", kwlist, &basestr, &scope, &filterstr,
			&PyList_Type, &attrlist, &timeout, &sizelimit, &PyBool_Type, &attrsonlyo)) {
		PyErr_SetString(PyExc_AttributeError,
				"Wrong parameters (base<str|LDAPDN>, scope<int>, filter<str>, attrlist<List>, timeout<int>, attrsonly<bool>).");
		return NULL;
	}

	/* Check that scope's value is not remained the default. */
	if (scope == -1) {
		PyErr_SetString(PyExc_AttributeError, "Search scope must be set.");
		return NULL;
	}

	search_iter = LDAPSearchIter_New(self);
	if (search_iter == NULL) return PyErr_NoMemory();

	/* Get page size from the connection object. */
	page_size = PyObject_GetAttrString((PyObject *)self, "_LDAPConnection__page_size");
	if (page_size == NULL) return NULL;
	self->page_size = (int)PyLong_AsLong(page_size);
	Py_DECREF(page_size);
	if (PyErr_Occurred()) return NULL;

	/* Get sort list from the client. */
	sort_list = PyObject_GetAttrString((PyObject *)self, "_LDAPConnection__sort_attrs");
	if (PyList_Size(sort_list) > 0) {
		self->sort_list = PyList2LDAPSortKeyList(sort_list);
		if (self->sort_list == NULL) {
			PyErr_BadInternalCall();
			return NULL;
		}
	}

	/* Convert Python objects to C types. */
	if (attrsonlyo != NULL) attrsonly = PyObject_IsTrue(attrsonlyo);
	if (attrlist != NULL) attrs = PyList2StringList(attrlist);

	if (LDAPSearchIter_SetParams(search_iter, attrs, attrsonly, basestr,
			filterstr, scope, sizelimit, timeout) != 0) {
		Py_DECREF(search_iter);
		return NULL;
	}

	if (self->page_size > 0) {
		/* Create cookie for the page result. */
		search_iter->cookie = (struct berval *)malloc(sizeof(struct berval));
		if (search_iter->cookie == NULL) return PyErr_NoMemory();

		search_iter->cookie->bv_len = 0;
		search_iter->cookie->bv_val = NULL;
	}

	msgid = LDAPConnection_Searching(self, (PyObject *)search_iter);
	if (msgid < 0) return NULL;

	return PyLong_FromLong((long int)msgid);
}

static PyObject *
LDAPConnection_Whoami(LDAPConnection *self) {
	int rc = -1;
	int msgid = -1;

	if (LDAPConnection_IsClosed(self) != 0) return NULL;
	/* Start an LDAP Who Am I operation. */
	rc = ldap_extended_operation(self->ld, "1.3.6.1.4.1.4203.1.11.3", NULL, NULL, NULL, &msgid);

	if (rc != LDAP_SUCCESS) {
		PyObject *ldaperror = get_error_by_code(rc);
		PyErr_SetString(ldaperror, ldap_err2string(rc));
		Py_DECREF(ldaperror);
		return NULL;
	}

	if (addToPendingOps(self->pending_ops, msgid,  Py_None) != 0) {
		return NULL;
	}
	return PyLong_FromLong((long int)msgid);
}

PyObject *
LDAPConnection_Result(LDAPConnection *self, int msgid, int block) {
	int rc = -1;
	char msgidstr[8];
	int err = 0;
	LDAPMessage *res, *entry;
	LDAPControl **returned_ctrls = NULL;
	LDAPEntry *entryobj = NULL;
	LDAPSearchIter *search_iter = NULL;
	LDAPModList *mods = NULL;
	struct timeval zerotime;
	struct berval *authzid = NULL;
	char *retoid = NULL;
	char *errorstr = NULL;
	PyObject *ldaperror = NULL;

	sprintf(msgidstr, "%d", msgid);

	if (block == 1) {
		/* The ldap_result will block, and wait for server response. */
		Py_BEGIN_ALLOW_THREADS
		rc = ldap_result(self->ld, msgid, LDAP_MSG_ALL, NULL, &res);
		Py_END_ALLOW_THREADS
	} else {
		zerotime.tv_sec = 0L;
		zerotime.tv_usec = 0L;
		rc = ldap_result(self->ld, msgid, LDAP_MSG_ALL, &zerotime, &res);
	}

	switch (rc) {
	case -1:
		/* Error occurred during the operation. */
		/* Getting the error code from the session. */
		/* 0x31: LDAP_OPT_RESULT_CODE or LDAP_OPT_ERROR_NUMBER */
		ldap_get_option(self->ld, 0x0031,  &err);
		ldaperror = get_error_by_code(err);
		PyErr_SetString(ldaperror, ldap_err2string(err));
		Py_DECREF(ldaperror);
		return NULL;
	case 0:
		/* Timeout exceeded.*/
		break;
	case LDAP_RES_SEARCH_ENTRY:
		/* Received one of the entries from the server. */
		/* Only matters when ldap_result is set with LDAP_MSG_ONE. */
		break;
	case LDAP_RES_SEARCH_RESULT:
		/* Get SearchIter from pending operations. */
		search_iter = (LDAPSearchIter *)PyDict_GetItemString(self->pending_ops,
				msgidstr);
		Py_XINCREF(search_iter);
		if (search_iter == NULL ||
				PyDict_DelItemString(self->pending_ops, msgidstr) != 0) {
			PyErr_BadInternalCall();
			return NULL;
		}

		/* Set a new empty list for buffer. */
		if (search_iter->buffer == NULL) {
			search_iter->buffer = PyList_New(0);
			if (search_iter->buffer == NULL) return PyErr_NoMemory();
		} else {
			Py_DECREF(search_iter->buffer);
			search_iter->buffer = PyList_New(0);
		}

		/* Iterate over the received LDAP messages. */
		for (entry = ldap_first_entry(self->ld, res);
			entry != NULL;
			entry = ldap_next_entry(self->ld, entry)) {
			entryobj = LDAPEntry_FromLDAPMessage(entry, self);
			if (entryobj == NULL) {
				Py_DECREF(search_iter->buffer);
				return NULL;
			}
			if ((entryobj == NULL) ||
					(PyList_Append(search_iter->buffer,
							(PyObject *)entryobj)) != 0) {
				Py_XDECREF(entryobj);
				Py_DECREF(search_iter->buffer);
				return PyErr_NoMemory();
			}
			Py_DECREF(entryobj);
		}
		/* Check for any error during the searching. */
		rc = ldap_parse_result(self->ld, res, &err, NULL, NULL, NULL,
				&returned_ctrls, 1);

		if (err == LDAP_NO_SUCH_OBJECT) {
			return search_iter->buffer;
		}

		if (err != LDAP_SUCCESS && err != LDAP_PARTIAL_RESULTS) {
			ldaperror = get_error_by_code(err);
			PyErr_SetString(ldaperror, ldap_err2string(err));
			Py_DECREF(ldaperror);
			Py_DECREF(search_iter->buffer);
			return NULL;
		}
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
		/* Cleanup. */
		if (returned_ctrls != NULL) ldap_controls_free(returned_ctrls);

		return (PyObject *)search_iter;
	case LDAP_RES_EXTENDED:
		rc = ldap_parse_extended_result(self->ld, res, &retoid, &authzid, 1);

		/* Remove operations from pending_ops. */
		if (PyDict_DelItemString(self->pending_ops, msgidstr) != 0) {
			PyErr_BadInternalCall();
			return NULL;
		}

		if( rc != LDAP_SUCCESS ) {
			ldaperror = get_error_by_code(err);
			PyErr_SetString(ldaperror, ldap_err2string(err));
			Py_DECREF(ldaperror);
			return NULL;
		}
		/* LDAP Who Am I operation. */
		/* WARNING: OpenLDAP does not send back oid for whoami operations.
		  	It's gonna be really messy, if it does for any type of extended op. */
		if (retoid == NULL || strcmp(retoid, "1.3.6.1.4.1.4203.1.11.3") == 0) {
			if (authzid == NULL) return PyUnicode_FromString("anonym");

			if(authzid->bv_len == 0) {
				authzid->bv_val = "anonym";
				authzid->bv_len = 6;
			}
			free(retoid);
			return PyUnicode_FromString(authzid->bv_val);
		}
		break;
	default:
		rc = ldap_parse_result(self->ld, res, &err, NULL, NULL, NULL,
				&returned_ctrls, 1);

		/* Get the modification list from the pending_ops. */
		mods = (LDAPModList *)PyDict_GetItemString(self->pending_ops, msgidstr);
		if (mods == NULL) return NULL;
		Py_INCREF(mods);
		/* Remove operations from pending_ops. */
		if (PyDict_DelItemString(self->pending_ops, msgidstr) != 0) {
			PyErr_BadInternalCall();
			return NULL;
		}

		if (rc != LDAP_SUCCESS || err != LDAP_SUCCESS) {
			/* LDAP add or modify operation is failed,
			   then rollback the changes. */
			if (LDAPEntry_Rollback((LDAPEntry *)mods->entry, mods) != 0)
				return NULL;

			ldaperror = get_error_by_code(err);
			ldap_get_option(self->ld, LDAP_OPT_ERROR_STRING, &errorstr);
			if (errorstr != NULL) {
				PyErr_SetString(ldaperror, errorstr);
				//TODO free(errorstr) causes segfault on Windows, as does ldap_memfree;
			} else {
				PyErr_SetString(ldaperror, ldap_err2string(err));
			}
			Py_DECREF(ldaperror);
			return NULL;
		}
		Py_RETURN_TRUE;
	}
	Py_RETURN_NONE;
}

static PyObject *
LDAPConnection_result(LDAPConnection *self, PyObject *args, PyObject *kwds) {
	int msgid = 0;
	int block = 0;
	char msgidstr[8];
	PyObject *msgid_obj = NULL;
	PyObject *res = NULL;
	PyObject *block_obj = NULL;
	PyObject *keys = PyDict_Keys(self->pending_ops);

	static char *kwlist[] = {"msgid", "block", NULL};

	if (LDAPConnection_IsClosed(self) != 0) return NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "i|O!", kwlist, &msgid,
			&PyBool_Type, &block_obj)) {
		PyErr_SetString(PyExc_AttributeError, "Wrong parameter.");
		return NULL;
	}

	/* Convert Python bool object to int. */
	if (block_obj != NULL) block = PyObject_IsTrue(block_obj);

	sprintf(msgidstr, "%d", msgid);
	msgid_obj = PyUnicode_FromString(msgidstr);
	if (keys == NULL || msgid_obj == NULL) return NULL;

	if (PySequence_Contains(keys, msgid_obj) < 1)  {
		PyObject *ldaperror = get_error_by_code(-10);
		PyErr_SetString(ldaperror, "Given message ID is invalid or the"
				" associated operation is already finished.");
		Py_DECREF(ldaperror);
		res = NULL;
	} else {
		res = LDAPConnection_Result(self, msgid, block);
	}

	Py_DECREF(keys);
	Py_DECREF(msgid_obj);
	return res;
}

static PyObject *
LDAPConnection_cancel(LDAPConnection *self, PyObject *args, PyObject *kwds) {
	int msgid = -1;
	char msgidstr[8];
	int rc = 0;
	static char *kwlist[] = {"msgid", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "i", kwlist, &msgid)) {
		PyErr_SetString(PyExc_AttributeError, "Wrong parameters");
		return NULL;
	}

	rc = LDAP_abandon(self->ld, msgid);
	if (rc != LDAP_SUCCESS) {
		PyObject *ldaperror = get_error_by_code(rc);
		PyErr_SetString(ldaperror, ldap_err2string(rc));
		Py_DECREF(ldaperror);
		return NULL;
	}

	/* Remove message id from the pending_ops. */
	sprintf(msgidstr, "%d", msgid);
	if (PyDict_DelItemString(self->pending_ops, msgidstr) != 0) {
		PyErr_BadInternalCall();
		return NULL;
	}

	return Py_None;
}

static PyMethodDef LDAPConnection_methods[] = {
	{"add", (PyCFunction)LDAPConnection_Add, METH_VARARGS,
			"Add new LDAPEntry to the LDAP server."},
	{"cancel", (PyCFunction)LDAPConnection_cancel, METH_VARARGS,
			"Cancel ongoing operations associated with the given message id."},
	{"close", (PyCFunction)LDAPConnection_Close, METH_NOARGS,
			"Close connection with the LDAP Server."},
	{"delete", (PyCFunction)LDAPConnection_DelEntry, METH_VARARGS,
			"Delete an LDAPEntry with the given distinguished name."},
	{"get_result", (PyCFunction)LDAPConnection_result, METH_VARARGS | METH_KEYWORDS,
			"Poll the status of the operation associated with the given message id from LDAP server."},
	{"search", (PyCFunction)LDAPConnection_Search, 	METH_VARARGS | METH_KEYWORDS,
			"Search for LDAP entries."},
	{"whoami", (PyCFunction)LDAPConnection_Whoami, METH_NOARGS,
			"LDAPv3 Who Am I operation."},
    {NULL, NULL, 0, NULL}  /* Sentinel */
};

PyTypeObject LDAPConnectionType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pyldap._LDAPConnection",       /* tp_name */
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
