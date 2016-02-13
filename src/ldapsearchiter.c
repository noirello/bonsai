/*
 * ldapsearchiter.c
 *
 *  Created on: Mar 3, 2014
 *      Author: noirello
 */
#include "ldapsearchiter.h"
#include "ldapconnection.h"

/*	Dealloc the LDAPSearchIter object. */
static void
ldapsearchiter_dealloc(LDAPSearchIter* self) {
	int i;

	Py_XDECREF(self->buffer);
	Py_XDECREF(self->conn);

	free(self->base);
	free(self->filter);
	if (self->attrs != NULL) {
		for (i = 0; self->attrs[i] != NULL; i++) {
			free(self->attrs[i]);
		}
		free(self->attrs);
	}

	free(self->cookie);
	Py_TYPE(self)->tp_free((PyObject*)self);
}

/*	Create a new LDAPSearchIter object. */
static PyObject *
ldapsearchiter_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
	LDAPSearchIter *self = NULL;

	//self = (LDAPSearchIter *)PyType_GenericAlloc(type, 0);
	self = (LDAPSearchIter *)type->tp_alloc(type, 0);

	if (self != NULL) {
		self->buffer = NULL;
		self->attrs = NULL;
		self->base = NULL;
		self->cookie = NULL;
		self->filter = NULL;
		self->timeout = 0;
		self->attrsonly = 0;
		self->scope = 0;
		self->sizelimit = 0;
	}

	return (PyObject *)self;
}

/*	Creates a new LDAPSearchIter object for internal use. */
LDAPSearchIter *
LDAPSearchIter_New(LDAPConnection *conn) {
	LDAPSearchIter *self =
			(LDAPSearchIter *)LDAPSearchIterType.tp_new(&LDAPSearchIterType,
					NULL, NULL);
	if (conn != NULL && self != NULL) {
		Py_INCREF(conn);
		self->conn = conn;
	}
	return self;
}

/* Set the parameters of an LDAPSEarchIter object. */
int
LDAPSearchIter_SetParams(LDAPSearchIter *self, char **attrs, int attrsonly,
		char *base, char *filter, int scope, int sizelimit, double timeout) {

	self->attrs = attrs;
	self->attrsonly = attrsonly;

	/* Copying base string and filter string, because there is no
	 guarantee that someone will not free them prematurely. */
	self->base = (char *)malloc(sizeof(char) * (strlen(base)+1));
	strcpy(self->base, base);

	/* If empty filter string is given, set to NULL. */
	if (filter == NULL || strlen(filter) == 0) {
		self->filter = NULL;
	} else {
		self->filter = (char *)malloc(sizeof(char) * (strlen(filter)+1));
		strcpy(self->filter, filter);
	}
	self->scope = scope;
	self->sizelimit = sizelimit;
	self->timeout = timeout;

	return 0;
}

/* Get the next page of a paged LDAP search. */
static PyObject *
ldapsearchiter_acquirenextpage(LDAPSearchIter *self) {
	int msgid = -1;

	/* If paged LDAP search is in progress. */
	if ((self->cookie != NULL) && (self->cookie->bv_val != NULL) &&
			(strlen(self->cookie->bv_val) > 0)) {
		msgid = LDAPConnection_Searching(self->conn, (PyObject *)self);
		if (msgid < 0) return NULL;

		return PyLong_FromLong((long int)msgid);
	} else {
		ber_bvfree(self->cookie);
		self->cookie = NULL;

		Py_RETURN_NONE;
	}
}

/* Return with the LDAPSerachIter object. */
static PyObject*
ldapsearchiter_getiter(LDAPSearchIter *self) {
	Py_INCREF(self);
	return (PyObject*)self;
}

/* Step the LDAPSearchIter iterator. */
static PyObject *
ldapsearchiter_iternext(LDAPSearchIter *self) {
	PyObject *item = NULL;

	if (self->buffer == NULL) return NULL;

	if (Py_SIZE(self->buffer) != 0) {
		/* Get first element from the buffer list. (Borrowed ref.)*/
		item = PyList_GetItem(self->buffer, 0);
		if (item == NULL) {
			PyErr_BadInternalCall();
			return NULL;
		}
		Py_INCREF(item);
		/* Remove the first element from the buffer list. */
		if (PyList_SetSlice(self->buffer, 0, 1, NULL) != 0) {
			PyErr_BadInternalCall();
			return NULL;
		}
		return item;
	} else {
		Py_DECREF(self->buffer);
		self->buffer = NULL;
	}
	return NULL;
}

static PyMethodDef ldapsearchiter_methods[] = {
	{"acquire_next_page", (PyCFunction)ldapsearchiter_acquirenextpage,
			METH_NOARGS, "Get next page of paged LDAP search."},
    {NULL, NULL, 0, NULL}  /* Sentinel */
};

PyTypeObject LDAPSearchIterType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "_bonsai.ldapsearchiter",       /* tp_name */
    sizeof(LDAPSearchIter),        /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)ldapsearchiter_dealloc, /* tp_dealloc */
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
    "ldapsearchiter object",   	   /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    (getiterfunc)ldapsearchiter_getiter,  /* tp_iter */
    (iternextfunc)ldapsearchiter_iternext,/* tp_iternext */
    ldapsearchiter_methods,   	/* tp_methods */
    0,        				   /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    0,							/* tp_init */
    0,                         /* tp_alloc */
    ldapsearchiter_new,			/* tp_new */
};
