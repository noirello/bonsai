#include "ldapsearchiter.h"
#include "ldapconnection.h"

static int
ldapsearchiter_clear(LDAPSearchIter *self) {
    DEBUG("ldapsearchiter_clear (self:%p)", self);
    Py_CLEAR(self->buffer);
    Py_CLEAR(self->conn);
    return 0;
}

/* Dealloc the LDAPSearchIter object. */
static void
ldapsearchiter_dealloc(LDAPSearchIter* self) {
    DEBUG("ldapsearchiter_dealloc (self:%p) cookie:%p", self,
        (self != NULL) ? self->cookie : NULL
    );
    PyObject_GC_UnTrack(self);
    ldapsearchiter_clear(self);

    free_search_params(self->params);
    if (self->params != NULL) free(self->params);

    /* Free VLVInfo struct. */
    if (self->vlv_info != NULL) {
        if (self->vlv_info->ldvlv_attrvalue != NULL) {
            free(self->vlv_info->ldvlv_attrvalue->bv_val);
            free(self->vlv_info->ldvlv_attrvalue);
        }
        free(self->vlv_info);
    }

    if (self->cookie != NULL) {
        if (self->cookie->bv_val != NULL) {
            ldap_memfree(self->cookie->bv_val);
        }
        free(self->cookie);
        self->cookie = NULL;
    }

    Py_TYPE(self)->tp_free((PyObject*)self);
}

static int
ldapsearchiter_traverse(LDAPSearchIter *self, visitproc visit, void *arg) {
    DEBUG("ldapsearchiter_traverse (self:%p)", self);
    Py_VISIT(self->buffer);
    Py_VISIT(self->conn);
    return 0;
}

/*  Create a new LDAPSearchIter object. */
static PyObject *
ldapsearchiter_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
    LDAPSearchIter *self = NULL;

    self = (LDAPSearchIter *)PyObject_GC_New(LDAPSearchIter, type);

    if (self != NULL) {
        self->conn = NULL;
        self->buffer = NULL;
        self->buffer_pos = 0;
        self->cookie = NULL;
        self->page_size = 0;
        self->params = NULL;
        self->vlv_info = NULL;
        self->auto_acquire = 0;
        self->has_iter_anext = 0;
        PyObject_GC_Track(self);
    }

    DEBUG("ldapsearchiter_new [self:%p]", self);
    return (PyObject *)self;
}

/* Creates a new LDAPSearchIter object for internal use. */
LDAPSearchIter *
LDAPSearchIter_New(LDAPConnection *conn) {
    PyObject *tmp = NULL;
    int auto_acquire;
    LDAPSearchIter *self =
            (LDAPSearchIter *)LDAPSearchIterType.tp_new(&LDAPSearchIterType,
                    NULL, NULL);
    DEBUG("LDAPSearchIter_New (conn:%p)[self:%p]", conn, self);
    if (conn != NULL && self != NULL) {
        self->params = (ldapsearchparams *)malloc(sizeof(ldapsearchparams));
        if (self->params == NULL) {
            Py_DECREF(self);
            return (LDAPSearchIter *)PyErr_NoMemory();
        }
        Py_INCREF(conn);
        self->conn = conn;

        /* Get client's auto_page_acquire property. */
        tmp = PyObject_GetAttrString(self->conn->client, "auto_page_acquire");
        if (tmp == NULL) {
            free(self->params);
            self->params = NULL;
            Py_DECREF(self);
            return NULL;
        }

        auto_acquire = PyObject_IsTrue(tmp);
        Py_DECREF(tmp);
        if (auto_acquire < 0) {
            free(self->params);
            self->params = NULL;
            Py_DECREF(self);
            return NULL;
        }
        self->auto_acquire = (char)auto_acquire;

        if (self->conn->async == 1) {
            tmp = PyObject_GetAttrString((PyObject *)self->conn, "_search_iter_anext");
            if (tmp == NULL) {
                if (PyErr_ExceptionMatches(PyExc_AttributeError)) {
                    /* Attribute doesn't exist */
                    PyErr_Clear();
                    self->has_iter_anext = 0;
                } else {
                    /* Error happened. */
                    free(self->params);
                    self->params = NULL;
                    Py_DECREF(self);
                    return NULL;
                }
            } else {
                /* Has the attribute. */
                self->has_iter_anext = 1;
                Py_DECREF(tmp);
            }
        }
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
        if (LDAPConnection_IsClosed(self->conn) != 0) return NULL;
        msgid = LDAPConnection_Searching(self->conn, NULL, (PyObject *)self);
        if (msgid < 0) return NULL;
        return PyLong_FromLong((long int)msgid);
    } else {
        if (self->cookie != NULL) {
            if (self->cookie->bv_val != NULL) {
                ldap_memfree(self->cookie->bv_val);
            }
            free(self->cookie);
            self->cookie = NULL;
        }
        Py_RETURN_NONE;
    }
}

/* Return with the LDAPSearchIter object. */
static PyObject*
ldapsearchiter_getiter(LDAPSearchIter *self) {
    Py_INCREF(self);
    return (PyObject*)self;
}

/* Return with the optional timeout object set for the paged search. */
static PyObject *
ldapsearchiter_gettimeout(LDAPSearchIter *self, void *closure) {
    if (self->params != NULL && self->params->timeout > 0) {
        return PyFloat_FromDouble(self->params->timeout);
    } else {
        Py_RETURN_NONE;
    }
}

/* Step the LDAPSearchIter iterator. */
static PyObject *
ldapsearchiter_iternext(LDAPSearchIter *self) {
    PyObject *item = NULL;
    PyObject *msgid = NULL, *timeout = NULL, *newself = NULL;

    DEBUG("ldapsearchiter_iternext (self:%p)", self);

    for (;;) {
        if (self->buffer == NULL) return NULL;

        if (self->buffer_pos < PyList_GET_SIZE(self->buffer)) {
            /* Get the next element from the buffer list. (Borrowed ref.) */
            item = PyList_GET_ITEM(self->buffer, self->buffer_pos++);
            Py_INCREF(item);
            return item;
        }

        Py_CLEAR(self->buffer);
        self->buffer_pos = 0;

        if (self->auto_acquire == 0 || self->has_iter_anext != 0) return NULL;

        msgid = ldapsearchiter_acquirenextpage(self);
        if (msgid == NULL) return NULL;
        if (msgid == Py_None) {
            Py_DECREF(msgid);
            return NULL;
        }

        timeout = ldapsearchiter_gettimeout(self, NULL);
        if (timeout == NULL) {
            Py_DECREF(msgid);
            return NULL;
        }

        newself = PyObject_CallMethod((PyObject *)self->conn, "_evaluate",
                                     "OO", msgid, timeout);
        Py_DECREF(msgid);
        Py_DECREF(timeout);
        if (newself == NULL) return NULL;

        if (newself != (PyObject *)self) {
            PyErr_SetString(PyExc_TypeError,
                            "_evaluate() must return the search iterator itself");
            Py_DECREF(newself);
            return NULL;
        }
        Py_DECREF(newself);
    }
}

static Py_ssize_t
ldapsearchiter_len(LDAPSearchIter *self) {
    if (self->buffer == NULL) return 0;
    return PyList_GET_SIZE(self->buffer) - self->buffer_pos;
}

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

static PyGetSetDef ldapsearchiter_getsetters[] = {
    {"timeout", (getter)ldapsearchiter_gettimeout,
            NULL, "Read-only attribute of timeout", NULL},
    {NULL} /* Sentinel */
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
        Py_TPFLAGS_BASETYPE |
        Py_TPFLAGS_HAVE_GC,    /* tp_flags */
    "ldapsearchiter object",   /* tp_doc */
    (traverseproc)ldapsearchiter_traverse, /* tp_traverse */
    (inquiry)ldapsearchiter_clear, /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    (getiterfunc)ldapsearchiter_getiter,  /* tp_iter */
    (iternextfunc)ldapsearchiter_iternext,/* tp_iternext */
    ldapsearchiter_methods,    /* tp_methods */
    0,                         /* tp_members */
    ldapsearchiter_getsetters, /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    0,                         /* tp_init */
    0,                         /* tp_alloc */
    ldapsearchiter_new,        /* tp_new */
};
