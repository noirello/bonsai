/*
 * ldapconnectiter.c
 *
 *  Created on: 22 Jun 2015
 *      Author: noirello
 */
#include "ldapconnectiter.h"

#include "utils.h"

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__)
//MS Windows

/* Poll the answer of the separate thread that runs the binding process.
Returns NULL in case of error, Py_None for timeout, and the LDAPConnection
object if successfully finished the binding. */
static PyObject *
binding(LDAPConnectIter *self) {
	int rc;
	char buff[1];

	if (self->bind_inprogress == 0) {
		/* First call of bind. */
		rc = _ldap_bind(self->conn->ld, self->info, NULL, &(self->message_id));
		if (rc != LDAP_SUCCESS) {
			set_exception(self->conn->ld, rc);
			return NULL;
		}
		self->bind_inprogress = 1;
		Py_RETURN_NONE;
	} else {
		if (self->conn->async == 0) {
			rc = WaitForSingleObject(self->info->thread, self->timeout);
		} else {
			rc = WaitForSingleObject(self->info->thread, 10);
		}
		switch (rc) {
		case WAIT_TIMEOUT:
			if (self->conn->async == 0) {
				TerminateThread(self->info->thread, -1);
				CloseHandle(self->info->thread);
				ldap_unbind_ext(self->conn->ld, NULL, NULL);
				set_exception(NULL, LDAP_TIMEOUT);
				return NULL;
			}
			Py_RETURN_NONE;
		case WAIT_OBJECT_0:
			GetExitCodeThread(self->info->thread, &rc);
			CloseHandle(self->info->thread);
			if (rc != LDAP_SUCCESS) {
				/* The ldap_connect is failed. Set a Python error. */
				set_exception(self->conn->ld, rc);
				return NULL;
			}
			if (self->conn->csock != -1) {
				/* Read and drop the data from the dummy socket. */
				if (recv(self->conn->csock, buff, 1, 0) == -1) return NULL;
				/* Dummy sockets are no longer needed. */
				self->conn->csock = -1;
				close_socketpair(self->conn->socketpair);
			}
			/* The binding is successfully finished. */
			self->bind_inprogress = 0;
			self->conn->closed = 0;
			Py_INCREF((PyObject *)self->conn);
			return (PyObject *)self->conn;
		default:
			/* The thread is failed. */
			PyErr_BadInternalCall();
			return NULL;
		}
	}
}

#else

 /* Poll the answer of the async function calls of the binding process.
 Returns NULL in case of error, Py_None for timeout, and the LDAPConnection
 object if successfully finished the binding. */
static PyObject *
binding(LDAPConnectIter *self) {
	int rc = -1;
	int err = 0;
	struct timeval polltime;
	LDAPControl **returned_ctrls = NULL;
	LDAPMessage *res;

	polltime.tv_sec = 0L;
	polltime.tv_usec = 10L;

	if (self->bind_inprogress == 0) {
		/* First call of bind. */
		rc = _ldap_bind(self->conn->ld, self->info, NULL, &(self->message_id));
		if (rc != LDAP_SUCCESS && rc != LDAP_SASL_BIND_IN_PROGRESS) {
			close_socketpair(self->conn->socketpair);
			set_exception(self->conn->ld, rc);
			return NULL;
		}
		if (self->conn->csock != -1) {
			/* Dummy sockets are no longer needed. Dispose. */
			self->conn->csock = -1;
			close_socketpair(self->conn->socketpair);
		}
		self->bind_inprogress = 1;
		Py_RETURN_NONE;
	} else {
		if (self->conn->async == 0) {
			/* Block until the server response. */
			if (self->timeout == -1) {
				rc = ldap_result(self->conn->ld, self->message_id, LDAP_MSG_ALL, NULL, &res);
			} else {
				polltime.tv_sec = self->timeout / 1000;
				polltime.tv_usec = (self->timeout % 1000) * 1000;
				rc = ldap_result(self->conn->ld, self->message_id, LDAP_MSG_ALL, &polltime, &res);
			}
		} else {
			/* Binding is already in progress, poll result from the server. */
			rc = ldap_result(self->conn->ld, self->message_id, LDAP_MSG_ALL, &polltime, &res);
		}
		switch (rc) {
		case -1:
			/* Error occurred during the operation. */
			set_exception(self->conn->ld, 0);
			return NULL;
		case 0:
			/* Timeout exceeded.*/
			if (self->conn->async == 0) {
				set_exception(self->conn->ld, -5);
				return NULL;
			}
			Py_RETURN_NONE;
		case LDAP_RES_BIND:
			/* Response is arrived from the server. */
			rc = ldap_parse_result(self->conn->ld, res, &err, NULL, NULL, NULL, &returned_ctrls, 0);

			if ((rc != LDAP_SUCCESS) ||
				(err != LDAP_SASL_BIND_IN_PROGRESS && err != LDAP_SUCCESS)) {
				/* Connection is failed. */
				set_exception(self->conn->ld, err);
				return NULL;
			}

			if (strcmp(self->info->mech, "SIMPLE") != 0) {
				/* Continue SASL binding procedure. */
				rc = _ldap_bind(self->conn->ld, self->info, res, &(self->message_id));

				if (rc != LDAP_SUCCESS && rc != LDAP_SASL_BIND_IN_PROGRESS) {
					set_exception(self->conn->ld, rc);
					return NULL;
				}

				if (rc == LDAP_SASL_BIND_IN_PROGRESS) {
					Py_RETURN_NONE;
				}
			}

			if (rc == LDAP_SUCCESS) {
				/* The binding is successfully finished. */
				self->bind_inprogress = 0;
				self->conn->closed = 0;
				Py_INCREF((PyObject *)self->conn);
				return (PyObject *)self->conn;
			}
			Py_RETURN_NONE;
		default:
			/* Invalid return value, it never should happen. */
			PyErr_BadInternalCall();
			return NULL;
		}
	}
}

#endif

/*	Dealloc the LDAPConnectIter object. */
static void
ldapconnectiter_dealloc(LDAPConnectIter* self) {
	Py_XDECREF(self->conn);
	if (self->info != NULL) dealloc_conn_info(self->info);
	Py_TYPE(self)->tp_free((PyObject*)self);
}

/*	Create a new LDAPConnectIter object. */
static PyObject *
ldapconnectiter_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
	LDAPConnectIter *self = NULL;

	self = (LDAPConnectIter *)type->tp_alloc(type, 0);

	if (self != NULL) {
		self->conn = NULL;
		self->init_finished = 0;
		self->message_id = 0;
		self->init_thread_data = NULL;
		self->init_thread = 0;
		self->timeout = -1;
	}

	return (PyObject *)self;
}


/* Return a char* attribute from the LDAPClient object. */
static int
get_tls_attribute(PyObject *client, const char *name, char **value) {
	PyObject *tmp = NULL;

	tmp = PyObject_GetAttrString(client, name);
	if (tmp == NULL) return -1;

	if (tmp == Py_None) *value = NULL;
	else *value= PyObject2char(tmp);
	Py_DECREF(tmp);

	return 0;
}

/* Create and return a ldapInitThreadData struct for the initialisation thread. */
static ldapInitThreadData *
create_init_thread_data(PyObject *client, SOCKET sock) {
	int rc = 0;
	ldapInitThreadData *data = NULL;
	PyObject *url = NULL;
	PyObject *tmp = NULL;
	PyObject *tls = NULL;

	data = (ldapInitThreadData *)malloc(sizeof(ldapInitThreadData));
	if (data == NULL) {
		PyErr_NoMemory();
		return NULL;
	}
	data->ca_cert = NULL;
	data->ca_cert_dir = NULL;
	data->client_cert = NULL;
	data->client_key = NULL;
	data->url = NULL;

	/* Get URL policy from LDAPClient. */
	url = PyObject_GetAttrString(client, "url");
	if (url == NULL) goto error;

	/* Get URL address information from the LDAPClient's LDAPURL object. */
	tmp = PyObject_CallMethod(url, "get_address", NULL);
	Py_DECREF(url);
	if (tmp == NULL) goto error;
	data->url = PyObject2char(tmp);
	Py_DECREF(tmp);
	if (data->url == NULL) goto error;

	/* Check the TLS state. */
	tls = PyObject_GetAttrString(client, "tls");
	if (tls == NULL) goto error;
	data->tls = PyObject_IsTrue(tls);
	Py_DECREF(tls);

	/* Set cert policy from LDAPClient. */
	tmp = PyObject_GetAttrString(client, "cert_policy");
	if (tmp == NULL) goto error;
	data->cert_policy = (int)PyLong_AsLong(tmp);
	Py_DECREF(tmp);

	/* Set CA cert directory from LDAPClient. */
	rc = get_tls_attribute(client, "ca_cert_dir", &(data->ca_cert_dir));
	if (rc != 0) goto error;
	/* Set CA cert from LDAPClient. */
	rc = get_tls_attribute(client, "ca_cert", &(data->ca_cert));
	if (rc != 0) goto error;
	/* Set client cert from LDAPClient. */
	rc = get_tls_attribute(client, "client_cert", &(data->client_cert));
	if (rc != 0) goto error;
	/* Set client key from LDAPClient. */
	rc = get_tls_attribute(client, "client_key", &(data->client_key));
	if (rc != 0) goto error;

	data->ld = NULL;
	data->sock = sock;
	return data;
error:
	if (data->ca_cert != NULL) free(data->ca_cert);
	if (data->ca_cert_dir != NULL) free(data->ca_cert_dir);
	if (data->client_cert != NULL) free(data->client_cert);
	if (data->client_key != NULL) free(data->client_key);
	if (data->url != NULL) free(data->url);
	free(data);
	PyErr_BadInternalCall();
	return NULL;
}

/* Create a new LDAPConnectIter object for internal use. */
LDAPConnectIter *
LDAPConnectIter_New(LDAPConnection *conn, ldap_conndata_t *info, SOCKET sock) {
	int err = 0;
	LDAPConnectIter *self =
			(LDAPConnectIter *)LDAPConnectIterType.tp_new(&LDAPConnectIterType,
					NULL, NULL);

	if (conn != NULL && self != NULL) {
		Py_INCREF(conn);
		self->conn = conn;
		self->info = info;

		self->init_thread_data = create_init_thread_data(self->conn->client, sock);
		if (self->init_thread_data == NULL) return NULL;

		self->init_thread = create_init_thread(self->init_thread_data, &err);
		if (err != 0) return NULL;

		self->timeout = -1;
	}

	return self;
}

/* Step the connection process into the next stage. */
PyObject *
LDAPConnectIter_Next(LDAPConnectIter *self, int timeout) {
	int rc = -1;
	PyObject *val = NULL;
	char buff[1];

	/* The connection is already binded. */
	if (self->conn->closed == 0) {
		return PyErr_Format(PyExc_StopIteration, "Connection is already open.");
	}

	if (self->timeout == -1 && timeout >= 0) {
		self->timeout = timeout;
	}

	if (self->init_finished == 0) {
		rc = _ldap_finish_init_thread(self->conn->async, self->init_thread, &(self->timeout),
				self->init_thread_data, &(self->conn->ld));
		if (rc == -1) return NULL; /* Error is happened. */
		if (rc == 1) {
			/* Initialisation is finished. */
			self->init_finished = 1;
			if (self->conn->csock != -1) {
				/* Read and drop the data from the dummy socket. */
				if (recv(self->conn->csock, buff, 1, 0) == -1) return NULL;
			}
		}
	}

	if (self->init_finished == 1) {
		/* Init for the LDAP structure is finished, TLS (if it is needed) already set, start binding. */
		val = binding(self);
		if (val == NULL) return NULL; /* It is an error. */
		if (val != Py_None) return val;
	}

	if (self->conn->async == 0) {
		/* If the function is blocking, then call next() */
		/* automatically, until an error or the LDAPConnection occurs.  */
		return LDAPConnectIter_Next(self, self->timeout);
	} else {
		Py_RETURN_NONE;
	}
}

PyTypeObject LDAPConnectIterType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "_bonsai.ldapconnectiter",       /* tp_name */
    sizeof(LDAPConnectIter),        /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)ldapconnectiter_dealloc, /* tp_dealloc */
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
    "ldapconnectiter object, implemented in C.",   	   /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,						   /* tp_iter */
    0,							/* tp_iternext */
    0,   					/* tp_methods */
    0,        				   /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    0,							/* tp_init */
    0,                         /* tp_alloc */
    ldapconnectiter_new,			/* tp_new */
};
