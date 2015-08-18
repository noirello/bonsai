#include "ldapconnection.h"
#include "ldapentry.h"
#include "ldapsearchiter.h"
#include "ldapconnectiter.h"
#include "utils.h"

/*	Dealloc the LDAPConnection object. */
static void
LDAPConnection_dealloc(LDAPConnection* self) {
	int i = 0;
	Py_XDECREF(self->client);
	Py_XDECREF(self->pending_ops);
	Py_XDECREF(self->socketpair);

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
		/* The connection should be closed. */
		self->closed = 1;
		self->async = 0;
		self->sort_list = NULL;
		self->csock = -1;
		self->socketpair = NULL;
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
		PyObject *ldaperror = get_error_by_code(-101);
		PyErr_SetString(ldaperror, "The connection is closed.");
		Py_DECREF(ldaperror);
		return -1;
	}
	return 0;
}

static int
get_socketpair(PyObject *client, PyObject **tup, SOCKET *csock, SOCKET *ssock) {
	int rc = 0;
	PyObject *tmp = NULL;

	*tup = PyObject_CallMethod(client, "_create_socketpair", NULL);
	if (*tup == NULL) return -1;

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

/*	Open a connection to the LDAP server. Initialises LDAP structure.
	If TLS is true, starts TLS session.
*/
static int
connecting(LDAPConnection *self, LDAPConnectIter **conniter) {
	int rc = -1;
	int tls_option = -1;
	char *mech = NULL;
	SOCKET ssock;
	PyObject *url = NULL;
	PyObject *tls = NULL;
	PyObject *tmp = NULL;
	PyObject *creds = NULL;
	ldap_conndata_t *info = NULL;

	/* Get URL policy from LDAPClient. */
	url = PyObject_GetAttrString(self->client, "url");
	if (url == NULL) return -1;

	/* Get cert policy from LDAPClient. */
	tmp = PyObject_GetAttrString(self->client, "cert_policy");
	if (tmp == NULL) goto error;
	tls_option = (int)PyLong_AsLong(tmp);
	Py_DECREF(tmp);

	/* Get mechanism and credentials. */
	creds = PyObject_GetAttrString(self->client, "credentials");
	if (creds == NULL) goto error;

	tmp = PyObject_GetAttrString(self->client, "mechanism");
	if (tmp == NULL) {
		Py_DECREF(creds);
		goto error;
	}
	mech = PyObject2char(tmp);
	Py_DECREF(tmp);

	/* Init the socketpair. */
	rc = get_socketpair(self->client, &(self->socketpair), &(self->csock), &ssock);
	if (rc != 0) goto error;

	info = create_conn_info(mech, ssock, creds);
	Py_DECREF(creds);
	if (info == NULL) goto error;

	tls = PyObject_GetAttrString(self->client, "tls");
	if (tls == NULL) goto error;

	*conniter = LDAPConnectIter_New(self, info);
	if (*conniter == NULL) goto error;

	rc = LDAP_start_init(url, PyObject_IsTrue(tls), tls_option, ssock, &((*conniter)->thread), &((*conniter)->data));
	Py_DECREF(url);
	Py_DECREF(tls);

	if (rc != 0) {
		set_exception(self->ld, rc);
		return -1;
	}
	return 0;

error:
	Py_DECREF(url);
	return -1;
}

/*	Initialise the LDAPConnection. */
static int
LDAPConnection_init(LDAPConnection *self, PyObject *args, PyObject *kwds) {
	PyObject *client = NULL;
	PyObject *async = NULL;
	PyObject *ldapclient_type = NULL;
	PyObject *tmp = NULL;
	static char *kwlist[] = {"client", "async", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "OO!", kwlist, &client,
			&PyBool_Type, &async)) {
		return -1;
	}

	if (client == NULL || async == NULL) return -1;

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

	/* Convert PyBool to char and set to async. */
	self->async = (char)PyObject_IsTrue(async);

	/* Set client object to LDAPConnection. */
	tmp = self->client;
	Py_INCREF(client);
	self->client = client;
	Py_XDECREF(tmp);

	return 0;
}

/* Open connection. */
static PyObject *
LDAPConnection_Open(LDAPConnection *self) {
	int rc = 0;
	LDAPConnectIter *iter = NULL;

	rc = connecting(self, &iter);
	if (rc != 0) return NULL;

	/* Add binding operation to the pending_ops. */
	if (add_to_pending_ops(self->pending_ops, (int)(self->csock),
		(PyObject *)iter) != 0) {
		return NULL;
	}

	return PyLong_FromLong((long int)(self->csock));
}

/*	Close connection. */
static PyObject *
LDAPConnection_Close(LDAPConnection *self) {
	int rc;
	int msgid;
	PyObject *keys = PyDict_Keys(self->pending_ops);
	PyObject *iter, *key;

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
		rc = ldap_abandon_ext(self->ld, msgid, NULL, NULL);
		if (rc != LDAP_SUCCESS) {
			Py_DECREF(iter);
			set_exception(self->ld, rc);
			return NULL;
		}
	}
	Py_DECREF(iter);

	rc = ldap_unbind_ext(self->ld, NULL, NULL);
	if (rc != LDAP_SUCCESS) {
		set_exception(self->ld, rc);
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
			set_exception(self->ld, rc);
			return -1;
		}
		/* Add new delete operation to the pending_ops. */
		if (add_to_pending_ops(self->pending_ops, msgid,  Py_None) != 0) {
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
				search_iter->timeout,
				search_iter->sizelimit, &msgid);

	if (rc != LDAP_SUCCESS) {
		set_exception(self->ld, rc);
		return -1;
	}

	if (add_to_pending_ops(self->pending_ops, msgid,
			(PyObject *)search_iter) != 0) {
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

	/* Create a SearchIter for storing the search params and result. */
	search_iter = LDAPSearchIter_New(self);
	if (search_iter == NULL) return PyErr_NoMemory();

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
		set_exception(self->ld, rc);
		return NULL;
	}

	if (add_to_pending_ops(self->pending_ops, msgid,  Py_None) != 0) {
		return NULL;
	}

	return PyLong_FromLong((long int)msgid);
}

PyObject *
parse_search_result(LDAPConnection *self, LDAPMessage *res, char *msgidstr){
	int rc = -1;
	int err = 0;
	LDAPMessage *entry;
	LDAPControl **returned_ctrls = NULL;
	LDAPEntry *entryobj = NULL;
	LDAPSearchIter *search_iter = NULL;

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
	for (entry = ldap_first_entry(self->ld, res); entry != NULL;
		entry = ldap_next_entry(self->ld, entry)) {
		entryobj = LDAPEntry_FromLDAPMessage(entry, self);
		if (entryobj == NULL) {
			Py_DECREF(search_iter->buffer);
			return NULL;
		}
		if ((entryobj == NULL) || (PyList_Append(search_iter->buffer,
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

	if (rc != LDAP_SUCCESS ) {
		set_exception(self->ld, rc);
		return NULL;
	}

	if (err == LDAP_NO_SUCH_OBJECT) {
		return search_iter->buffer;
	}

	if (err != LDAP_SUCCESS && err != LDAP_PARTIAL_RESULTS) {
		set_exception(self->ld, err);
		Py_DECREF(search_iter->buffer);
		return NULL;
	}
	rc = ldap_parse_pageresponse_control(self->ld,
			ldap_control_find(LDAP_CONTROL_PAGEDRESULTS, returned_ctrls, NULL),
			NULL, search_iter->cookie);
	/* Cleanup. */
	if (returned_ctrls != NULL) ldap_controls_free(returned_ctrls);

	return (PyObject *)search_iter;
}

PyObject *
parse_extended_result(LDAPConnection *self, LDAPMessage *res, char *msgidstr) {
	int rc = -1;
	struct berval *authzid = NULL;
	char *retoid = NULL;
	PyObject *retval = NULL;

	rc = ldap_parse_extended_result(self->ld, res, &retoid, &authzid, 1);

	/* Remove operations from pending_ops. */
	if (PyDict_DelItemString(self->pending_ops, msgidstr) != 0) {
		PyErr_BadInternalCall();
		return NULL;
	}

	if (rc != LDAP_SUCCESS ) {
		set_exception(self->ld, rc);
		return NULL;
	}
	/* LDAP Who Am I operation. */
	/* WARNING: OpenLDAP does not send back oid for whoami operations.
		It's gonna be really messy, if it does for any type of extended op. */
	if (retoid == NULL || strcmp(retoid, "1.3.6.1.4.1.4203.1.11.3") == 0) {
		if (authzid == NULL) return PyUnicode_FromString("anonymous");

		if(authzid->bv_len == 0) {
			authzid->bv_val = "anonymous";
			authzid->bv_len = 9;
		}
		ldap_memfree(retoid);
		retval = PyUnicode_FromString(authzid->bv_val);
		ber_bvfree(authzid);
	}
	return retval;
}

PyObject *
LDAPConnection_Result(LDAPConnection *self, int msgid, int block) {
	int rc = -1;
	int err = 0;
	char msgidstr[8];
	LDAPMessage *res;
	LDAPControl **returned_ctrls = NULL;
	LDAPModList *mods = NULL;
	struct timeval zerotime;
	PyObject *ext_obj = NULL;
	PyObject *conniter = NULL;
	PyObject *ret = NULL;

	/*- Create a char* from int message id. */
	sprintf(msgidstr, "%d", msgid);

	if (self->closed && self->csock == msgid) {
		/* The function is called on a initialising and binding procedure. */
		conniter = PyDict_GetItemString(self->pending_ops, msgidstr);
		if (conniter == NULL) return NULL;
		/* Check, that we get the right object. */
		if (!PyObject_IsInstance(conniter, (PyObject *)&LDAPConnectIterType)) {
			PyErr_BadInternalCall();
			return NULL;
		}
		ret = LDAPConnectIter_Next(conniter, block);
		if (ret == NULL) return NULL;
		if (ret == Py_None) return ret;
		else {
			/* The init and bind are finished. */
			/* Remove operations from pending_ops. */
			if (PyDict_DelItemString(self->pending_ops, msgidstr) != 0) {
				PyErr_BadInternalCall();
				return NULL;
			}
			Py_DECREF(conniter);
			return (PyObject *)self;
		}
	}

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
		/* Call set_exception with 0 param to get error code from session. */
		set_exception(self->ld, 0);
		return NULL;
	case 0:
		/* Timeout exceeded.*/
		break;
	case LDAP_RES_SEARCH_ENTRY:
		/* Received one of the entries from the server. */
		/* Only matters when ldap_result is set with LDAP_MSG_ONE. */
		break;
	case LDAP_RES_SEARCH_RESULT:
		return parse_search_result(self, res, msgidstr);
	case LDAP_RES_EXTENDED:
		ext_obj = parse_extended_result(self, res, msgidstr);
		if (ext_obj == NULL && PyErr_Occurred()) return NULL;
		if (ext_obj != NULL) return ext_obj;
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
			/* Set Python error. */
			set_exception(self->ld, err);
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
		PyObject *ldaperror = get_error_by_code(-100);
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

	rc = ldap_abandon_ext(self->ld, msgid, NULL, NULL);
	if (rc != LDAP_SUCCESS) {
		set_exception(self->ld, rc);
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

static PyObject *
LDAPConnection_fileno(LDAPConnection *self) {
	int rc = 0;
	int desc = 0;

	/* For ongoing initialisation return the dummy socket descriptor,
	that will be pinged when the init thread is finished. */
	if (self->closed && self->csock != -1) {
		return PyLong_FromLong((long int)self->csock);
	}

	rc = ldap_get_option(self->ld, LDAP_OPT_DESC, &desc);
	if (rc != LDAP_SUCCESS) {
		set_exception(self->ld, rc);
		return NULL;
	}
	return PyLong_FromLong((long int)desc);
}

static PyObject *
LDAPConnection_setPageSize(LDAPConnection *self, PyObject *args, PyObject *kwds) {
	int page_size = -1;
	static char *kwlist[] = {"page_size", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "i", kwlist, &page_size)) {
		PyErr_SetString(PyExc_ValueError,
				"The page_size parameter must be an integer.");
		return NULL;
	}

	if (page_size > 2) {
		self->page_size = page_size;
	} else {
		PyErr_SetString(PyExc_ValueError,
				"The page_size parameter must be greater, than 1.");
	}

	return Py_None;
}

static PyObject *
LDAPConnection_setSortOrder(LDAPConnection *self, PyObject *args, PyObject *kwds) {
	PyObject *sort_list = NULL;
	static char *kwlist[] = {"sort_list", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!", kwlist, &PyList_Type, &sort_list)) {
		PyErr_SetString(PyExc_ValueError,
				"The sort_list parameter must be a list.");
		return NULL;
	}

	if (PyList_Size(sort_list) > 0) {
		/* Convert the attribute, reverse order pairs to LDAPSortKey struct. */
		self->sort_list = PyList2LDAPSortKeyList(sort_list);
		if (self->sort_list == NULL) {
			PyErr_BadInternalCall();
			return NULL;
		}
	}

	return Py_None;
}

static PyMemberDef LDAPConnection_members[] = {
    {"async", T_BOOL, offsetof(LDAPConnection, async), READONLY,
     "Asynchronous connection"},
	{"closed", T_BOOL, offsetof(LDAPConnection, closed), READONLY,
	 "Connection is closed"},
	{"page_size", T_INT, offsetof(LDAPConnection, page_size), READONLY,
	 "The number of entries on a page"},
    {NULL}  /* Sentinel */
};

static PyMethodDef LDAPConnection_methods[] = {
	{"add", (PyCFunction)LDAPConnection_Add, METH_VARARGS,
			"Add new LDAPEntry to the LDAP server."},
	{"cancel", (PyCFunction)LDAPConnection_cancel, METH_VARARGS,
			"Cancel ongoing operations associated with the given message id."},
	{"close", (PyCFunction)LDAPConnection_Close, METH_NOARGS,
			"Close connection with the LDAP Server."},
	{"delete", (PyCFunction)LDAPConnection_DelEntry, METH_VARARGS,
			"Delete an LDAPEntry with the given distinguished name."},
	{"fileno", (PyCFunction)LDAPConnection_fileno, METH_NOARGS,
			"Get the socket descriptor that belongs to the connection."},
	{"get_result", (PyCFunction)LDAPConnection_result, METH_VARARGS | METH_KEYWORDS,
			"Poll the status of the operation associated with the given message id from LDAP server."},
	{"open", (PyCFunction)LDAPConnection_Open, METH_NOARGS,
			"Open connection with the LDAP Server."},
	{"search", (PyCFunction)LDAPConnection_Search, 	METH_VARARGS | METH_KEYWORDS,
			"Search for LDAP entries."},
	{"set_page_size", (PyCFunction)LDAPConnection_setPageSize, METH_VARARGS,
			"Set how many entry will be on a page of a search result."},
	{"set_sort_order", (PyCFunction)LDAPConnection_setSortOrder, METH_VARARGS,
			"Set a list of attribute names to sort entries in a search result."},
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
	LDAPConnection_members,	   /* tp_members */
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
