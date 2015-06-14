/*
 * ldapoperation.c
 *
 *  Created on: 13 Jun 2015
 *      Author: noirello
 */

#include "ldapoperation.h"

#include "utils.h"

/*	Dealloc the LDAPOperation object. Depending on the operation's type
 	different deallocation is used. */
static void
LDAPOperation_dealloc(LDAPOperation* self) {
	PyObject *tmp;
	ldapConnectionInfo *info;

	Py_XDECREF(self->conn);
	Py_XDECREF(self->message_ids);

	if (self->data != NULL) {
		switch (self->type) {
		case 0:
			/* Data: Py_None. */
			break;
		case 1:
			/* Data: ldapConnectionInfo. */
			info = (ldapConnectionInfo *)self->data;
			dealloc_conn_info(info);
			break;
		case 2:
		case 3:
			/* Data: LDAPSearchIter or LDAPModList. */
			tmp = (PyObject *)self->data;
			Py_DECREF(tmp);
			break;
		}
	}

	Py_TYPE(self)->tp_free((PyObject*)self);
}

/*	Create a new LDAPOperation object. */
static PyObject *
LDAPOperation_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
	LDAPOperation *self = NULL;

	self = (LDAPOperation *)type->tp_alloc(type, 0);

	if (self != NULL) {
		self->conn = NULL;
		self->message_ids = PyList_New(0);
		if (self->message_ids == NULL) return NULL;
		self->data = NULL;
		self->type = 0;
	}

	return (PyObject *)self;
}

/*	Create a new LDAPSearchIter object for internal use. */
LDAPOperation *
LDAPOperation_New(LDAPConnection *conn, unsigned short type, void *data) {
	LDAPOperation *self = (LDAPOperation *)LDAPOperationType
			.tp_new(&LDAPOperationType, NULL, NULL);

	if (conn != NULL && self != NULL) {
		Py_INCREF(conn);
		self->conn = conn;
		self->type = type;
		self->data = data;
	}
	return self;
}

/* Add a new LDAPOperation object to the LDAPConnection pending_op dict,
   :param int msgid: the id of an asynchronous LDAP operation.
   :param LDAPConnection* conn: an LDAPConnection object.
   :param unsigned short type: the type of the LDAPOperation object.
   :param void* data: the data that belongs to the LDAPOperation.
*/
int
LDAPOperation_Proceed(LDAPConnection *conn, int msgid, unsigned short type, void *data) {
	char msgidstr[8];
	LDAPOperation *self = NULL;
	PyObject *msgid_obj = NULL;

	self = LDAPOperation_New(conn, type, data);
	if (self == NULL) return -1;

	sprintf(msgidstr, "%d", msgid);
	msgid_obj = PyUnicode_FromString(msgidstr);

	if (msgid_obj == NULL) {
		PyErr_BadInternalCall();
		Py_DECREF(self);
		return -1;
	}

	if (PyDict_SetItem(self->conn->pending_ops, msgid_obj, (PyObject *)self) != 0) {
		PyErr_BadInternalCall();
		Py_DECREF(msgid_obj);
		Py_DECREF(self);
		return -1;
	}
	Py_DECREF(self);


	if (PyList_Append(self->message_ids, msgid_obj) != 0) {
		PyErr_BadInternalCall();
		Py_DECREF(msgid_obj);
		Py_DECREF(self);
		return -1;
	}
	Py_DECREF(msgid_obj);

	return 0;
}

/* Return the borrowed reference of the LDAPOperation that
   belongs to the given id. */
LDAPOperation *
get_ldap_operation(LDAPConnection *conn, int id) {
	char idstr[8];
	LDAPOperation *self = NULL;

	sprintf(idstr, "%d", id);
	/* Return value: Borrowed reference. */
	self =  (LDAPOperation *)PyDict_GetItemString(conn->pending_ops, idstr);

	return self;
}

/* Append a new asynchronous LDAP message id to the message list. */
int
LDAPOperation_AppendMsgId(LDAPConnection *conn, int id, int new_msgid) {
	char msgidstr[8];
	PyObject *msgid_obj = NULL;
	LDAPOperation *self = NULL;

	self =  get_ldap_operation(conn, id);
	if (self == NULL) return -1;

	/* Create PyUnicode object from new_msgid. */
	sprintf(msgidstr, "%d", new_msgid);
	msgid_obj = PyUnicode_FromString(msgidstr);
	if (msgid_obj == NULL) {
		PyErr_BadInternalCall();
		return -1;
	}

	if (PyList_Append(self->message_ids, msgid_obj) != 0) {
		PyErr_BadInternalCall();
		Py_DECREF(msgid_obj);
		return -1;
	}
	Py_DECREF(msgid_obj);

	return 0;
}

/* Return the first message id of an asynchronous LDAP operation
   from the list. */
int
LDAPOperation_GetFirstMsgId(LDAPConnection *conn, int id) {
	char *msgidstr = NULL;
	LDAPOperation *self = NULL;
	PyObject *msgid_obj = NULL;

	self =  get_ldap_operation(conn, id);
	if (self == NULL) return -1;

	/* Get first element from the list. */
	msgid_obj = PyList_GetItem(self->message_ids, 0);
	if (msgid_obj == NULL) return -1;

	/* Convert PyUnicode object o char *. */
	msgidstr = PyObject2char(msgid_obj);
	if (msgidstr == NULL) return -1;

	/* Convert char * to int and return it. */
	return atoi(msgidstr);
}

/* Return the data that belongs to the LDAPOperation object. */
void *
LDAPOperation_GetData(LDAPConnection *conn, int id) {
	LDAPOperation *self = NULL;

	self =  get_ldap_operation(conn, id);
	if (self == NULL) return NULL;

	return self->data;
}

/* Remove the first message id from the list.
   If only one message id is on the list, remove the entire LDAPOperation
   object from the LDAPConnection's pennding_ops dict. */
int
LDAPOperation_Remove(LDAPConnection *conn, int id) {
	char idstr[8];
	LDAPOperation *self = NULL;

	sprintf(idstr, "%d", id);
	/* Return value: Borrowed reference. */
	self =  (LDAPOperation *)PyDict_GetItemString(conn->pending_ops, idstr);
	if (self == NULL) return -1;

	if (Py_SIZE(self->message_ids) > 1) {
		/* Remove only the first item. */
		if (PyList_SetSlice(self->message_ids, 0, 1, NULL) != 0) {
			return -1;
		}
	} else {
		/* All LDAP operation is finished, remove the object from pending_ops. */
		if (PyDict_DelItemString(conn->pending_ops, idstr) != 0) {
			PyErr_BadInternalCall();
			return -1;
		}
	}
	return 0;
}

PyTypeObject LDAPOperationType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pyldap.LDAPOperation",       /* tp_name */
    sizeof(LDAPOperation),        /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)LDAPOperation_dealloc, /* tp_dealloc */
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
    "LDAPOperation object",   	   /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,  					   /* tp_iter */
    0,						   /* tp_iternext */
    0,   					  /* tp_methods */
    0,        				   /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    0,							/* tp_init */
    0,                         /* tp_alloc */
    LDAPOperation_new,			/* tp_new */
};
