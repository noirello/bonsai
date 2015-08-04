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

	if (self->bind_inprogress == 0) {
		/* First call of bind. */
		rc = LDAP_bind(self->conn->ld, self->info, NULL, &(self->message_id));
		if (rc != LDAP_SUCCESS) {
			set_exception(self->conn->ld, rc);
			return NULL;
		}
		self->bind_inprogress = 1;
		Py_RETURN_NONE;
	} else {
		if (self->async) {
			rc = WaitForSingleObject(self->info->thread, 10);
		} else {
			rc = WaitForSingleObject(self->info->thread, INFINITE);
		}
		switch (rc) {
		case WAIT_TIMEOUT:
			Py_RETURN_NONE;
		case WAIT_OBJECT_0:
			GetExitCodeThread(self->info->thread, &rc);
			CloseHandle(self->info->thread);
			if (rc != LDAP_SUCCESS) {
				/* The ldap_connect is failed. Set a Python error. */
				set_exception(self->conn->ld, rc);
				return NULL;
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
		rc = LDAP_bind(self->conn->ld, self->info, NULL, &(self->message_id));
		if (rc != LDAP_SUCCESS && rc != LDAP_SASL_BIND_IN_PROGRESS) {
			set_exception(self->conn->ld, rc);
			return NULL;
		}
		self->bind_inprogress = 1;
		Py_RETURN_NONE;
	} else {
		if (self->async) {
			/* Binding is already in progress, poll result from the server. */
			rc = ldap_result(self->conn->ld, self->message_id, LDAP_MSG_ALL, &polltime, &res);
		} else {
			/* Block until the server response. */
			rc = ldap_result(self->conn->ld, self->message_id, LDAP_MSG_ALL, NULL, &res);
		}
		switch (rc) {
		case -1:
			/* Error occurred during the operation. */
			set_exception(self->conn->ld, 0);
			return NULL;
		case 0:
			/* Timeout exceeded.*/
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
				rc = LDAP_bind(self->conn->ld, self->info, res, &(self->message_id));

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
LDAPConnectIter_dealloc(LDAPConnectIter* self) {
	Py_XDECREF(self->conn);
	if (self->info != NULL) dealloc_conn_info(self->info);
	Py_TYPE(self)->tp_free((PyObject*)self);
}

/*	Create a new LDAPConnectIter object. */
static PyObject *
LDAPConnectIter_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
	LDAPConnectIter *self = NULL;

	self = (LDAPConnectIter *)type->tp_alloc(type, 0);

	if (self != NULL) {
		self->conn = NULL;
		self->init_finished = 0;
		self->message_id = 0;
		self->thread = NULL;
		self->data = NULL;
		self->async = 0;
	}

	return (PyObject *)self;
}

/*	Creates a new LDAPConnectIter object for internal use. */
LDAPConnectIter *
LDAPConnectIter_New(LDAPConnection *conn, ldap_conndata_t *info, int async) {
	LDAPConnectIter *self =
			(LDAPConnectIter *)LDAPConnectIterType.tp_new(&LDAPConnectIterType,
					NULL, NULL);

	if (conn != NULL && self != NULL) {
		Py_INCREF(conn);
		self->conn = conn;
		self->info = info;
		self->async = async;
	}

	return self;
}

PyObject *
LDAPConnectIter_getiter(LDAPConnectIter *self) {
	Py_INCREF(self);
	return (PyObject*)self;
}

PyObject *
LDAPConnectIter_iternext(LDAPConnectIter *self) {
	int rc = -1;
	PyObject *val = NULL;
	PyObject *wrapper = NULL;

	/* The connection is already binded. */
	if (self->conn->closed == 0) {
		return PyErr_Format(PyExc_StopIteration, "Connection is already open.");
	}

	if (self->init_finished == 0) {
		rc = LDAP_finish_init(self->async, (void *)self->thread, (void *)self->data, &(self->conn->ld));
		if (rc == -1) return NULL; /* Error is happened. */
		if (rc == 1) {
			/* Initialisation is finished. */
			self->init_finished = 1;
			if (update_conn_info(self->conn->ld, self->info) != 0) return NULL;
		}
	} else {
		/* Init for the LDAP structure is finished, TLS (if it is needed) already set, start binding. */
		val = binding(self);
		if (val == NULL) return NULL;
		if (val != Py_None) {
			if (self->async) {
				/* Raise a StopIteration error to imitate a generator func. */
				/* Need some workaround (Python Issue #23996). */
				PyObject *args = Py_BuildValue("(O)", val);
				wrapper = PyObject_CallObject(PyExc_StopIteration, args);
				Py_DECREF(args);
				if (wrapper == NULL) {
					Py_DECREF(val);
					PyErr_BadInternalCall();
					return NULL;
				}
				/* Embedding StopIterator into StopIterator to
				   avoid *_PyGen_FetchStopIterationValue() crashes */
				((PyStopIterationObject *)wrapper)->value = val;
				PyErr_SetObject(PyExc_StopIteration, wrapper);
				return NULL;
			} else {
				/* Simple return the LDAPConnection object. */
				return val;
			}
		}
	}
	if (self->async) {
		Py_RETURN_NONE;
	} else {
		/* If the connection is not asynchronous, then call next() */
		/* automatically, until an error or the LDAPConnection occurs.  */
		return LDAPConnectIter_iternext(self);
	}
}

PyTypeObject LDAPConnectIterType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pyldap.LDAPConnectIter",       /* tp_name */
    sizeof(LDAPConnectIter),        /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)LDAPConnectIter_dealloc, /* tp_dealloc */
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
    "LDAPConnectIter object",   	   /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    (getiterfunc)LDAPConnectIter_getiter,  /* tp_iter */
    (iternextfunc)LDAPConnectIter_iternext,/* tp_iternext */
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
    LDAPConnectIter_new,			/* tp_new */
};
