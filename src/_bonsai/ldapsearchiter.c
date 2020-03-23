#include "ldapsearchiter.h"
#include "ldapconnection.h"

/* Dealloc the LDAPSearchIter object. */
static void
ldapsearchiter_dealloc(LDAPSearchIter* self) {
    DEBUG("ldapsearchiter_dealloc (self:%p)", self);
    Py_XDECREF(self->buffer);
    Py_XDECREF(self->conn);

    free_search_params(self->params);

    /* Free VLVInfo struct. */
    if (self->vlv_info != NULL) {
        if (self->vlv_info->ldvlv_attrvalue != NULL) {
            free(self->vlv_info->ldvlv_attrvalue->bv_val);
            free(self->vlv_info->ldvlv_attrvalue);
        }
        free(self->vlv_info);
    }
    free(self->cookie);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

/*  Create a new LDAPSearchIter object. */
static PyObject *
ldapsearchiter_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
    LDAPSearchIter *self = NULL;

    self = (LDAPSearchIter *)type->tp_alloc(type, 0);

    if (self != NULL) {
        self->buffer = NULL;
        self->cookie = NULL;
        self->page_size = 0;
        self->params = NULL;
        self->vlv_info = NULL;
        self->auto_acquire = 0;
    }

    DEBUG("ldapsearchiter_new [self:%p]", self);
    return (PyObject *)self;
}

/* Creates a new LDAPSearchIter object for internal use. */
LDAPSearchIter *
LDAPSearchIter_New(LDAPConnection *conn) {
    PyObject *tmp = NULL;
    LDAPSearchIter *self =
            (LDAPSearchIter *)LDAPSearchIterType.tp_new(&LDAPSearchIterType,
                    NULL, NULL);
    DEBUG("LDAPSearchIter_New (conn:%p)[self:%p]", conn, self);
    if (conn != NULL && self != NULL) {
        self->params = (ldapsearchparams *)malloc(sizeof(ldapsearchparams));
        if (self->params == NULL) return NULL;
        Py_INCREF(conn);
        self->conn = conn;

        /* Get client's auto_page_acquire property. */
        tmp = PyObject_GetAttrString(self->conn->client, "auto_page_acquire");
        if (tmp == NULL) return NULL;

        self->auto_acquire = (char)PyObject_IsTrue(tmp);
        Py_DECREF(tmp);
    }
    return self;
}

/* Get the next page of a paged LDAP search. */
static PyObject *
ldapsearchiter_acquirenextpage(LDAPSearchIter *self) {
    int msgid = -1;

    DEBUG("ldapsearchiter_acquirenextpage (self:%p) cookie:%p", self,
        (self != NULL) ? self->cookie : NULL
    );
    /* If paged LDAP search is in progress. */
    if (self->cookie != NULL && self->cookie->bv_val != NULL && self->cookie->bv_len > 0) {
        Py_INCREF(self);
        msgid = LDAPConnection_Searching(self->conn, NULL, (PyObject *)self);
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
    PyObject *tmp = NULL, *msg = tmp;

    DEBUG("ldapsearchiter_iternext (self:%p)", self);
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
        if (self->auto_acquire == 1 && self->conn->async == 0) {
            /* Get next page if the auto acquiring is on
               and the connection is synchronous. */
            msg = ldapsearchiter_acquirenextpage(self);
            if (msg == NULL) return NULL;
            if (msg == Py_None) {
                Py_DECREF(msg);
                return NULL;
            }
            self = (LDAPSearchIter *)PyObject_CallMethod((PyObject *)self->conn,
                "_evaluate", "(O)", msg);
            Py_DECREF(msg);
            if (self == NULL) return NULL;
            Py_DECREF(self);
            return PyIter_Next((PyObject *)self);
        }
    }
    return NULL;
}

static Py_ssize_t
ldapsearchiter_len(LDAPSearchIter *self) {
    if (self->buffer == NULL) return 0;
    return PyObject_Size(self->buffer);
}

#if PY_MAJOR_VERSION >= 3 && PY_MINOR_VERSION >= 5

static PyObject *
ldapsearchiter_anext(LDAPSearchIter *self) {
    PyObject *res = NULL;

    DEBUG("ldapsearchiter_anext (self:%p)", self);
    res = PyObject_CallMethod((PyObject *)self->conn, "_search_iter_anext",
                        "(O)", (PyObject *)self);

    return res;
}

static PyAsyncMethods ldapsearchiter_async = {
    0,                         /* am_await */
    (unaryfunc)ldapsearchiter_getiter,  /* am_aiter */
    (unaryfunc)ldapsearchiter_anext  /* am_anext */
};

#else
static int ldapsearchiter_async = 0;
#endif

static PySequenceMethods ldapsearchiter_sequence = {
    (lenfunc)ldapsearchiter_len,  /* sq_length */
    0,                          /* sq_concat */
    0,                          /* sq_repeat */
    0,                          /* sq_item */
    0,                          /* sq_slice */
    0,                          /* sq_ass_item */
    0,                          /* sq_ass_slice */
    0,                          /* sq_contains */
    0,                          /* sq_inplace_concat */
    0,                          /* sq_inplace_repeat */
};

static PyMethodDef ldapsearchiter_methods[] = {
    {"acquire_next_page", (PyCFunction)ldapsearchiter_acquirenextpage,
            METH_NOARGS, "Get next page of paged LDAP search."},
    {NULL, NULL, 0, NULL}  /* Sentinel */
};

PyTypeObject LDAPSearchIterType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "_bonsai.ldapsearchiter",  /* tp_name */
    sizeof(LDAPSearchIter),    /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)ldapsearchiter_dealloc, /* tp_dealloc */
    0,                         /* tp_print */
    0,                         /* tp_getattr */
    0,                         /* tp_setattr */
    &ldapsearchiter_async,     /* tp_as_async */
    0,                         /* tp_repr */
    0,                         /* tp_as_number */
    &ldapsearchiter_sequence,  /* tp_as_sequence */
    0,                         /* tp_as_mapping */
    0,                         /* tp_hash  */
    0,                         /* tp_call */
    0,                         /* tp_str */
    0,                         /* tp_getattro */
    0,                         /* tp_setattro */
    0,                         /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT |
        Py_TPFLAGS_BASETYPE,   /* tp_flags */
    "ldapsearchiter object",   /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    (getiterfunc)ldapsearchiter_getiter,  /* tp_iter */
    (iternextfunc)ldapsearchiter_iternext,/* tp_iternext */
    ldapsearchiter_methods,    /* tp_methods */
    0,                         /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    0,                         /* tp_init */
    0,                         /* tp_alloc */
    ldapsearchiter_new,        /* tp_new */
};
