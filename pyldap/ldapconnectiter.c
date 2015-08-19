/*
 * ldapconnectiter.c
 *
 *  Created on: 22 Jun 2015
 *      Author: noirello
 */
#include "ldapconnectiter.h"

#include "utils.h"

/* Close and dispose the dummy sockets. */
static void
close_socketpair(PyObject *tup) {
	PyObject *tmp = NULL;
	PyObject *ret = NULL;

	/* Sanity check. */
	if (tup != NULL && PyTuple_Check(tup) && PyTuple_Size(tup) == 2) {
		tmp = PyTuple_GetItem(tup, 0);
		if (tmp) {
			ret = PyObject_CallMethod(tmp, "close", NULL);
			if (ret) Py_DECREF(ret);
		}

		tmp = PyTuple_GetItem(tup, 1);
		if (tmp) {
			ret = PyObject_CallMethod(tmp, "close", NULL);
			if (ret) Py_DECREF(ret);
		}
		Py_DECREF(tup);
	}
}

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__)
//MS Windows

/* Poll the answer of the separate thread that runs the binding process.
Returns NULL in case of error, Py_None for timeout, and the LDAPConnection
object if successfully finished the binding. */
static PyObject *
binding(LDAPConnectIter *self, int block) {
	int rc;
	char buff[1];

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
		if (block) {
			rc = WaitForSingleObject(self->info->thread, INFINITE);
		} else {
			rc = WaitForSingleObject(self->info->thread, 10);
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
			/* Read and drop the data from the dummy socket. */
			if (recv(self->conn->csock, buff, 1, 0) == -1) return NULL;
			/* Dummy sockets are no longer needed. */
			self->conn->csock = -1;
			close_socketpair(self->conn->socketpair);
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
binding(LDAPConnectIter *self, int block) {
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
		/* Dummy sockets are no longer needed. Dispose. */
		self->conn->csock = -1;
		close_socketpair(self->conn->socketpair);
		self->bind_inprogress = 1;
		Py_RETURN_NONE;
	} else {
		if (block) {
			/* Block until the server response. */
			rc = ldap_result(self->conn->ld, self->message_id, LDAP_MSG_ALL, NULL, &res);
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
	}

	return (PyObject *)self;
}

/*	Creates a new LDAPConnectIter object for internal use. */
LDAPConnectIter *
LDAPConnectIter_New(LDAPConnection *conn, ldap_conndata_t *info) {
	LDAPConnectIter *self =
			(LDAPConnectIter *)LDAPConnectIterType.tp_new(&LDAPConnectIterType,
					NULL, NULL);

	if (conn != NULL && self != NULL) {
		Py_INCREF(conn);
		self->conn = conn;
		self->info = info;
	}

	return self;
}

PyObject *
LDAPConnectIter_Next(LDAPConnectIter *self, int block) {
	int rc = -1;
	PyObject *val = NULL;
	char buff[1];

	/* The connection is already binded. */
	if (self->conn->closed == 0) {
		return PyErr_Format(PyExc_StopIteration, "Connection is already open.");
	}

	if (self->init_finished == 0) {
		rc = LDAP_finish_init(!block, (void *)self->thread, (void *)self->data, &(self->conn->ld));
		if (rc == -1) return NULL; /* Error is happened. */
		if (rc == 1) {
			/* Initialisation is finished. */
			self->init_finished = 1;
			/* Read and drop the data from the dummy socket. */
			if (recv(self->conn->csock, buff, 1, 0) == -1) return NULL;
			if (update_conn_info(self->conn->ld, self->info) != 0) return NULL;
		}
	}

	if (self->init_finished == 1) {
		/* Init for the LDAP structure is finished, TLS (if it is needed) already set, start binding. */
		val = binding(self, block);
		if (val == NULL) return NULL; /* It is an error. */
		if (val != Py_None) return val;
	}

	if (block) {
		/* If the functiion is blocking, then call next() */
		/* automatically, until an error or the LDAPConnection occurs.  */
		return LDAPConnectIter_Next(self, block);
	} else {
		Py_RETURN_NONE;
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
    LDAPConnectIter_new,			/* tp_new */
};
