#include "ldapvaluelist.h"
#include "utils.h"

static int
ldapvaluelist_clear(LDAPValueList *self) {
    PyObject *tmp;

    tmp = (PyObject *)self->added;
    self->added = NULL;
    Py_XDECREF(tmp);

    tmp = (PyObject *)self->deleted;
    self->deleted = NULL;
    Py_XDECREF(tmp);

    Py_TYPE(self)->tp_base->tp_clear((PyObject *)self);

    return 0;
}

/*  Deallocate the LDAPValueList. */
static void
ldapvaluelist_dealloc(LDAPValueList *self) {
    ldapvaluelist_clear(self);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static int
ldapvaluelist_traverse(LDAPValueList *self, visitproc visit, void *arg) {
    Py_VISIT(self->deleted);
    Py_VISIT(self->added);
    return 0;
}

/*  Create a new LDAPValueList object. For tracking changes uses two other Python list,
    one for addition and an other for deletion.
*/
static PyObject *
ldapvaluelist_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
    LDAPValueList *self;

    self = (LDAPValueList *)UniqueListType.tp_new(type, args, kwds);
    if (self == NULL) return NULL;

    self->added = UniqueList_New();
    if (self->added == NULL) return NULL;

    self->deleted = UniqueList_New();
    if (self->deleted == NULL) return NULL;

    self->status = 0;

    return (PyObject *)self;
}

/*  Initialising LDAPValueList. */
static int
ldapvaluelist_init(LDAPValueList *self, PyObject *args, PyObject *kwds) {
    if (UniqueListType.tp_init((PyObject *)self, args, kwds) < 0)
        return -1;
    return 0;
}

/*  Create a new LDAPValueList object for internal use. */
LDAPValueList *
LDAPValueList_New(void) {
    LDAPValueList *self = (LDAPValueList *)LDAPValueListType.tp_new(&LDAPValueListType, NULL, NULL);
    return self;
}

/*  Append new unique item to the LDAPValueList. Case-insensitive,
    the `newitem` is also appended to the added list, or remove from the deleted list.
*/
int
LDAPValueList_Append(LDAPValueList *self, PyObject *newitem) {
    int rc = -1;

    rc = UniqueList_Append((UniqueList *)self, newitem);
    if (rc == -1) return -1;

    rc = UniqueList_Remove_wFlg(self->deleted, newitem);
    if (rc == -1) return -1;
    if (rc == 0) {
        if (UniqueList_Append(self->added, newitem) == -1) return -1;
    }
    return 0;
}

/*  Returns 1 if obj is an instance of LDAPEntry, or 0 if not.
    On error, returns -1 and sets an exception.
*/
int
LDAPValueList_Check(PyObject *obj) {
    if (obj == NULL) return -1;
    return PyObject_IsInstance(obj, (PyObject *)&LDAPValueListType);
}

/*  Removes the same items from both list. */
static int
balancing(PyObject *l1, UniqueList *l2) {
    int rc;
    Py_ssize_t i;

    for (i = 0; i < Py_SIZE(l2); i++) {
        rc = UniqueList_Remove_wFlg((UniqueList *)l1, l2->list.ob_item[i]);
        if (rc == 1) {
            UniqueList_SetSlice(l2, i, i+1, (PyObject *)NULL);
        } else if (rc == -1) return -1;
    }
    return 0;
}

int
LDAPValueList_Extend(LDAPValueList *self, PyObject *b) {
    if (balancing(b, self->deleted) != 0) return -1;
    if (UniqueList_Extend(self->added, b) != 0) return -1;
    if (UniqueList_Extend((UniqueList *)self, b) != 0) return -1;
    return 0;
}

/*  Insert new unique item to the `where` position in LDAPValueList. Case-insensitive,
    the `newitem` is also appended to the added list, or remove from the deleted list.
*/
int
LDAPValueList_Insert(LDAPValueList *self, Py_ssize_t where, PyObject *newitem) {
    int rc = -1;

    rc = UniqueList_Remove_wFlg(self->deleted, newitem);
    if (rc == -1) return -1;
    if (rc == 0) {
        if (UniqueList_Append(self->added, newitem) == -1) return -1;
    }
    return UniqueList_Insert((UniqueList *)self, where, newitem);
}

int
LDAPValueList_Remove(LDAPValueList *self, PyObject *value) {
    int cmp;
    Py_ssize_t i;

    for (i = 0; i < Py_SIZE(self); i++) {
        cmp = lower_case_match(((PyListObject *)self)->ob_item[i], value);
        if (cmp > 0) {
            if (LDAPValueList_SetSlice(self, i, i+1, (PyObject *)NULL) == 0) return 0;
            return -1;
        } else if (cmp < 0) return -1;
    }
    PyErr_SetString(PyExc_ValueError, "LDAPListValue.remove(x): x not in list");
    return -1;
}

PyObject *
LDAPValueList_Status(LDAPValueList *self) {
    PyObject *status_dict = NULL;
    PyObject *status = NULL;

    status_dict = PyDict_New();
    if (status_dict == NULL) return NULL;

    status = PyLong_FromLong((long int)self->status);
    if (status == NULL) {
        Py_DECREF(status_dict);
        return NULL;
    }

    if (PyDict_SetItemString(status_dict, "@status", status) != 0) {
        Py_DECREF(status_dict);
        Py_DECREF(status);
        return NULL;
    }
    Py_DECREF(status);
    if (PyDict_SetItemString(status_dict, "@added",
            (PyObject *)self->added) != 0) {
        Py_DECREF(status_dict);
        return NULL;
    }
    if (PyDict_SetItemString(status_dict, "@deleted",
            (PyObject *)self->deleted) != 0) {
        Py_DECREF(status_dict);
        return NULL;
    }

    return status_dict;
}

/*  Set new unique item at `i` index in LDAPValueList to `newitem`. Case-insensitive,
    the `newitem` is also appended to the added list, or remove from the deleted list.
    Same goes for the replaced item.
*/
int
LDAPValueList_SetItem(LDAPValueList *self, Py_ssize_t i, PyObject *newitem) {
    int rc = -1;
    PyObject *olditem;

    if (UniqueList_SetItem((UniqueList *)self, i, newitem) != 0) return -1;

    olditem = PyList_GetItem((PyObject *)self, i);
    if (olditem == NULL) return -1;
    rc = UniqueList_Remove_wFlg(self->added, olditem);
    if (rc == -1) return -1;
    if (rc == 0) {
        if (UniqueList_Append(self->deleted, olditem) == -1) return -1;
    }

    rc = UniqueList_Remove_wFlg(self->deleted, newitem);
    if (rc == -1) return -1;
    if (rc == 0) {
        if (UniqueList_Append(self->added, newitem) == -1) return -1;
    }
    return 0;
}

/*  Set the slice of LDAPValueList between `ilow` and `ihigh` to the contents of `itemlist`.
    The `itemlist` must be containing unique elements. New items are append to the added list,
    and removed items are append to the deleted list. The `itemlist` may be NULL, indicating
    the assignment of an empty list (slice deletion).
*/
int
LDAPValueList_SetSlice(LDAPValueList *self, Py_ssize_t ilow, Py_ssize_t ihigh, PyObject *itemlist) {
    PyObject *remove;

    /* Copying the removable items from LDAPValueList to deleted list.*/
    remove = PyList_GetSlice((PyObject *)self, ilow, ihigh);
    if (remove == NULL) return -1;
    if (balancing(remove, self->added) != 0) {
        Py_DECREF(remove);
        return -1;
    }
    if (UniqueList_Extend(self->deleted, remove) != 0) {
        Py_DECREF(remove);
        return -1;
    }
    Py_DECREF(remove);

    /* Copying new items to the added list.*/
    if (itemlist != NULL) {
        if (balancing(itemlist, self->deleted) != 0) return -1;
        if (UniqueList_Extend(self->added, itemlist) != 0) return -1;
    }

    return UniqueList_SetSlice((UniqueList *)self, ilow, ihigh, itemlist);
}

static PyObject *
ldapvaluelist_append(LDAPValueList *self, PyObject *newitem) {
    if (LDAPValueList_Append(self, newitem) == 0) {
        self->status = 1;
        Py_RETURN_NONE;
    }
    return NULL;
}

static PyObject *
ldapvaluelist_extend(LDAPValueList *self, PyObject *b) {
    if (LDAPValueList_Extend(self, b) == 0) {
        self->status = 1;
        Py_RETURN_NONE;
    }
    return NULL;
}

static PyObject *
ldapvaluelist_insert(LDAPValueList *self, PyObject *args) {
    Py_ssize_t i;
    PyObject *v;

    if (!PyArg_ParseTuple(args, "nO:insert", &i, &v)) return NULL;
    if (LDAPValueList_Insert(self, i, v) == 0) {
        self->status = 1;
        Py_RETURN_NONE;
    }
    return NULL;
}

static PyObject *
ldapvaluelist_pop(LDAPValueList *self, PyObject *args) {
    int status;
    Py_ssize_t i = -1;
    PyObject *value;

    if (!PyArg_ParseTuple(args, "|n:pop", &i))
        return NULL;

    if (Py_SIZE(self) == 0) {
        PyErr_SetString(PyExc_IndexError, "pop from empty list");
        return NULL;
    }
    if (i < 0) i += Py_SIZE(self);
    if (i < 0 || i >= Py_SIZE(self)) {
        PyErr_SetString(PyExc_IndexError, "pop index out of range");
        return NULL;
    }
    value = ((PyListObject *)self)->ob_item[i];
    Py_INCREF(value);

    status = LDAPValueList_SetSlice(self, i, i+1, (PyObject *)NULL);
    if (status != 0) return NULL;

    self->status = 2;
    return value;
}

static PyObject *
ldapvaluelist_remove(LDAPValueList *self, PyObject *value) {
    if (LDAPValueList_Remove(self, value) == 0) {
        self->status = 2;
        Py_RETURN_NONE;
    }
    return NULL;
}

static PyMethodDef ldapvaluelist_methods[] = {
    {"append",  (PyCFunction)ldapvaluelist_append,
            METH_O, "Append new item to the LDAPValueList." },
    {"extend",  (PyCFunction)ldapvaluelist_extend,
            METH_O, "Extend LDAPValueList."},
    {"insert",  (PyCFunction)ldapvaluelist_insert,
            METH_VARARGS, "Insert new item in the LDAPValueList."},
    {"pop",     (PyCFunction)ldapvaluelist_pop,
            METH_VARARGS, "Pop-pop."},
    {"remove",  (PyCFunction)ldapvaluelist_remove,
            METH_O, "Remove item from LDAPValueList."},
    {NULL, NULL, 0, NULL}  /* Sentinel */
};

static int
ldapvaluelist_ass_item(LDAPValueList *self, Py_ssize_t i, PyObject *v) {
    if (i < 0 || i >= Py_SIZE(self)) {
        PyErr_SetString(PyExc_IndexError,
                        "list assignment index out of range");
        return -1;
    }
    if (v == NULL) return LDAPValueList_SetSlice(self, i, i+1, v);
    return LDAPValueList_SetItem(self, i, v);
}

static PySequenceMethods ldapvaluelist_as_sequence = {
    0,                              /* sq_length */
    0,          /* sq_concat */
    0,        /* sq_repeat */
    0,                              /* sq_item */
    0,                              /* sq_slice */
    (ssizeobjargproc)ldapvaluelist_ass_item,    /* sq_ass_item */
    0,                              /* sq_ass_slice */
    0,       /* sq_contains */
    0,  /* sq_inplace_concat */
    0,        /* sq_inplace_repeat */
};

/*  This function is based on list_ass_subscript from Python source listobject.c.
    But it uses LDAPValueList's setslice and setitem functions instead of memory opertation.
    It is probably a much more slower, but cleaner solution.
*/
static int
ldapvaluelist_ass_subscript(LDAPValueList *self, PyObject *item, PyObject *value) {
    size_t cur;
    Py_ssize_t i;
    Py_ssize_t start, stop, step, slicelength;
    PyObject *seq;
    PyObject **seqitems;

    if (PyIndex_Check(item)) {
        i = PyNumber_AsSsize_t(item, PyExc_IndexError);
        if (i == -1 && PyErr_Occurred()) return -1;
        if (i < 0) i += PyList_GET_SIZE(self);
        return ldapvaluelist_ass_item(self, i, value);
    } else if (PySlice_Check(item)) {
        if (PySlice_GetIndicesEx(item, Py_SIZE(self), &start, &stop, &step, &slicelength) < 0) {
            return -1;
        }

        if (step == 1) return LDAPValueList_SetSlice(self, start, stop, value);

        /* Make sure s[5:2] = [..] inserts at the right place:
           before 5, not before 2. */
        if ((step < 0 && start < stop) || (step > 0 && start > stop)) {
            stop = start;
        }

        if (value == NULL) {
            /* delete slice */
            if (slicelength <= 0) return 0;

            if (step < 0) {
                stop = start + 1;
                start = stop + step*(slicelength - 1) - 1;
                step = -step;
            }

            for (cur = start, i = 0; cur < (size_t)stop; cur += step, i++) {
                if (LDAPValueList_SetSlice(self, cur-i, cur+1-i, (PyObject *)NULL) != 0) {
                    return -1;
                }
            }
            return 0;
        } else {
            /* assign slice */
            /* protect against a[::-1] = a */
            if (self == (LDAPValueList*)value) {
                seq = PyList_GetSlice(value, 0, PyList_GET_SIZE(value));
            } else {
                seq = PySequence_Fast(value, "must assign iterable to extended slice");
            }
            if (!seq) return -1;

            if (PySequence_Fast_GET_SIZE(seq) != slicelength) {
                PyErr_Format(PyExc_ValueError, "attempt to assign sequence of size %zd to extended slice of "
                        "size %zd", PySequence_Fast_GET_SIZE(seq), slicelength);
                Py_DECREF(seq);
                return -1;
            }

            if (!slicelength) {
                Py_DECREF(seq);
                return 0;
            }

            seqitems = PySequence_Fast_ITEMS(seq);
            for (cur = start, i = 0; i < slicelength; cur += (size_t)step, i++) {
                if (LDAPValueList_SetItem(self, cur, seqitems[i]) != 0) {
                    return -1;
                }
            }
            Py_DECREF(seq);
            return 0;
        }
    } else {
        PyErr_Format(PyExc_TypeError, "list indices must be integers, not %.200s", item->ob_type->tp_name);
        return -1;
    }
}

static PyMappingMethods ldapvaluelist_as_mapping = {
    0,                                  /* mp_length */
    0,                                  /* mp_subscript */
    (objobjargproc)ldapvaluelist_ass_subscript, /* mp_ass_subscript */
};

PyTypeObject LDAPValueListType = {
    PyObject_HEAD_INIT(NULL)
    "_bonsai.ldapvaluelist",      /* tp_name */
    sizeof(LDAPValueList),       /* tp_basicsize */
    0,                       /* tp_itemsize */
    (destructor)ldapvaluelist_dealloc,       /* tp_dealloc */
    0,                       /* tp_print */
    0,                       /* tp_getattr */
    0,                       /* tp_setattr */
    0,                       /* tp_reserved */
    0,                       /* tp_repr */
    0,                       /* tp_as_number */
    &ldapvaluelist_as_sequence,        /* tp_as_sequence */
    &ldapvaluelist_as_mapping,       /* tp_as_mapping */
    0,                       /* tp_hash */
    0,                       /* tp_call */
    0,                       /* tp_str */
    0,                       /* tp_getattro */
    0,                       /* tp_setattro */
    0,                       /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT |
        Py_TPFLAGS_BASETYPE |
        Py_TPFLAGS_HAVE_GC, /* tp_flags */
    0,                       /* tp_doc */
    (traverseproc)ldapvaluelist_traverse, /* tp_traverse */
    (inquiry)ldapvaluelist_clear, /* tp_clear */
    0,                       /* tp_richcompare */
    0,                       /* tp_weaklistoffset */
    0,                       /* tp_iter */
    0,                       /* tp_iternext */
    ldapvaluelist_methods,   /* tp_methods */
    0,                       /* tp_members */
    0,                       /* tp_getset */
    0,                      /* tp_base */
    0,                       /* tp_dict */
    0,                       /* tp_descr_get */
    0,                       /* tp_descr_set */
    0,                       /* tp_dictoffset */
    (initproc)ldapvaluelist_init,/* tp_init */
    0,                       /* tp_alloc */
    ldapvaluelist_new,      /* tp_new */
};
