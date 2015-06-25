/*
 * ldapconnectiter.c
 *
 *  Created on: 22 Jun 2015
 *      Author: noirello
 */
#include "ldapconnectiter.h"

#include "utils.h"

/*	Dealloc the LDAPConnectIter object. */
static void
LDAPConnectIter_dealloc(LDAPConnectIter* self) {
	Py_XDECREF(self->conn);
	if (self->conn != NULL) dealloc_conn_info(self->info);
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
		self->tls = 0;
		self->tls_step = 0;
		self->message_id = 0;
		self->thread = NULL;
		self->cert_policy = -1;
		self->async = 0;
	}

	return (PyObject *)self;
}

/*	Creates a new LDAPConnectIter object for internal use. */
LDAPConnectIter *
LDAPConnectIter_New(LDAPConnection *conn, ldapConnectionInfo *info, int async, int has_tls, int cert_policy) {
	LDAPConnectIter *self =
			(LDAPConnectIter *)LDAPConnectIterType.tp_new(&LDAPConnectIterType,
					NULL, NULL);

	if (conn != NULL && self != NULL) {
		Py_INCREF(conn);
		self->conn = conn;
		self->info = info;
		self->tls = has_tls;
		self->cert_policy = cert_policy;
		self->async = async;
		self->thread = (pthread_t *)malloc(sizeof(pthread_t));
		if (self->thread == NULL) {
			PyErr_NoMemory();
			return NULL;
		}
	}

	return self;
}

PyObject*
LDAPConnectIter_getiter(LDAPConnectIter *self) {
	Py_INCREF(self);
	return (PyObject*)self;
}

PyObject *
LDAPConnectIter_iternext(LDAPConnectIter *self) {
	int rc = -1;
	int err = 0;
	ldapThreadData *val = NULL;
	struct timespec ts;
	struct timeval polltime;
	const int version = LDAP_VERSION3;
	LDAPControl **returned_ctrls = NULL;
	LDAPMessage *res;

	ts.tv_nsec = 100;
	ts.tv_sec = 0;

	polltime.tv_sec = 0L;
	polltime.tv_usec = 10L;

	if (self->init_finished == 0) {
		if (self->async) {
			/* Polling thread state. Warning: this function is not portable (_np). */
			rc = pthread_timedjoin_np(*(self->thread), (void **)&val, &ts);
		} else {
			/* Block until thread is finished. */
			rc = pthread_join(*(self->thread), (void **)&val);
		}
		switch (rc) {
		case ETIMEDOUT:
			break;
		case 0:
			/* Thread is finished. */
			if (val->retval != LDAP_SUCCESS) {
				PyObject *ldaperror = get_error_by_code(val->retval );
				PyErr_SetString(ldaperror, ldap_err2string(val->retval ));
				Py_DECREF(ldaperror);
				return NULL;
			}
			/* Set initialised LDAP struct pointer. */
			self->conn->ld = val->ld;
			ldap_set_option(self->conn->ld, LDAP_OPT_PROTOCOL_VERSION, &version);
			if (self->cert_policy != -1) {
				/* Set cert policy. */
				ldap_set_option(self->conn->ld, LDAP_OPT_X_TLS_REQUIRE_CERT, &(self->cert_policy));
				/* Set TLS option globally. */
				ldap_set_option(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT, &(self->cert_policy));
			}
			self->init_finished = 1;
			break;
		default:
			/* The thread is failed. */
			PyErr_BadInternalCall();
			return NULL;
		}
	} else if (self->tls == 1 && self->tls_step != 2) {
		switch(self->tls_step) {
		case 0:
			/* Send START_TLS to the server. */
			rc = ldap_start_tls(self->conn->ld, NULL, NULL, &(self->message_id));
			if (rc != LDAP_SUCCESS) {
				PyObject *ldaperror = get_error_by_code(rc);
				PyErr_SetString(ldaperror, ldap_err2string(rc));
				Py_DECREF(ldaperror);
				return NULL;
			}
			self->tls_step++;
			break;
		case 1:
			if (self->async) {
				/* Poll result from the server. */
				rc = ldap_result(self->conn->ld, self->message_id, LDAP_MSG_ALL, &polltime, &res);
			} else {
				/* Block until the server response. */
				rc = ldap_result(self->conn->ld, self->message_id, LDAP_MSG_ALL, NULL, &res);
			}
			switch (rc) {
			case -1:
				/* Error occurred during the operation. */
				/* Getting the error code from the session. */
				/* 0x31: LDAP_OPT_RESULT_CODE or LDAP_OPT_ERROR_NUMBER */
				ldap_get_option(self->conn->ld, 0x0031,  &err);
				PyObject *ldaperror = get_error_by_code(err);
				PyErr_SetString(ldaperror, ldap_err2string(err));
				Py_DECREF(ldaperror);
				return NULL;
			case 0:
				/* Timeout exceeded.*/
				break;
			case LDAP_RES_EXTENDED:
				/* Response is arrived about the START_TLS. */
				rc = ldap_parse_extended_result(self->conn->ld, res, NULL, NULL, 1);
				if (rc != LDAP_SUCCESS) {
					PyObject *ldaperror = get_error_by_code(rc);
					PyErr_SetString(ldaperror, ldap_err2string(rc));
					Py_DECREF(ldaperror);
					return NULL;
				}
				rc = ldap_install_tls(self->conn->ld);
				if (rc != LDAP_SUCCESS) {
					PyObject *ldaperror = get_error_by_code(rc);
					PyErr_SetString(ldaperror, ldap_err2string(rc));
					Py_DECREF(ldaperror);
					return NULL;
				}
				self->tls_step++;
				break;
			default:
				/* Invalid return value, it never should happen. */
				//TODO: Error handling.
				break;
			break;
			}
		}
	} else {
		/* Init for the LDAP structure is finished, TLS (if it as needed) already set, start binding. */
		if (self->bind_inprogress == 0) {
			/* First call of bind. */
			rc = LDAP_bind(self->conn->ld, self->info, NULL, &(self->message_id));
			if (rc != LDAP_SUCCESS && rc != LDAP_SASL_BIND_IN_PROGRESS) {
				PyObject *ldaperror = get_error_by_code(rc);
				PyErr_SetString(ldaperror, ldap_err2string(rc));
				Py_DECREF(ldaperror);
				return NULL;
			}
			self->bind_inprogress = 1;
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
				/* Getting the error code from the session. */
				/* 0x31: LDAP_OPT_RESULT_CODE or LDAP_OPT_ERROR_NUMBER */
				ldap_get_option(self->conn->ld, 0x0031,  &err);
				PyObject *ldaperror = get_error_by_code(err);
				PyErr_SetString(ldaperror, ldap_err2string(err));
				Py_DECREF(ldaperror);
				return NULL;
			case 0:
				/* Timeout exceeded.*/
				break;
			case LDAP_RES_BIND:
				/* Response is arrived from the server. */
				rc = ldap_parse_result(self->conn->ld, res, &err, NULL, NULL, NULL, &returned_ctrls, 0);

				if ((rc != LDAP_SUCCESS) ||
						(err != LDAP_SASL_BIND_IN_PROGRESS && err != LDAP_SUCCESS)) {
					/* Connection is failed. */
					ldaperror = get_error_by_code(err);
					PyErr_SetString(ldaperror, ldap_err2string(err));
					Py_DECREF(ldaperror);
					return NULL;
				}

				if (strcmp(self->info->mech, "SIMPLE") != 0) {
					/* Continue SASL binding procedure. */
					rc = LDAP_bind(self->conn->ld, self->info, res, &(self->message_id));

					if (rc != LDAP_SUCCESS && rc != LDAP_SASL_BIND_IN_PROGRESS) {
						ldaperror = get_error_by_code(err);
						PyErr_SetString(ldaperror, ldap_err2string(err));
						Py_DECREF(ldaperror);
						return NULL;
					}

					if (rc == LDAP_SASL_BIND_IN_PROGRESS) break;
				}

				if (rc == LDAP_SUCCESS ) {
					self->bind_inprogress = 0;
					Py_INCREF((PyObject *)self->conn);
					self->conn->closed = 0;
					return (PyObject *)self->conn;
				}
				break;
			default:
				/* Invalid return value, it never should happen. */
				//TODO: Error handling.
				break;
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
