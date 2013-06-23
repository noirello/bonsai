#include "ldapvaluelist.h"
#include "utils.h"

/*	Deallocate the LDAPValueList. */
static void
LDAPValueList_dealloc(LDAPValueList *self) {
	Py_XDECREF(self->added);
	Py_XDECREF(self->deleted);
	Py_TYPE(self)->tp_free((PyObject*)self);
}

/*	Create a new LDAPValueList object. For tracking changes uses two other Python list,
	one for addition and an other for deletion.
*/
static PyObject *
LDAPValueList_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
	LDAPValueList *self;

	self = (LDAPValueList *)PyList_Type.tp_new(type, args, kwds);
	if (self == NULL) return NULL;

	self->added = PyList_New(0);
	if (self->added == NULL) return NULL;

	self->deleted = PyList_New(0);
	if (self->deleted == NULL) return NULL;

	self->status = -1;

	return (PyObject *)self;
}

/*	Convert `list` object to a tuple, which contains only lowercase Python string elements. */
static PyObject *
get_lowercase_tuple(PyObject *list) {
	char *str;
	Py_ssize_t i, n;
	PyObject *tup = NULL;
	PyObject *seq, *item;

	if (list == NULL) return NULL;

	seq = PySequence_Fast(list, "Argument is not iterable.");
	n = PySequence_Fast_GET_SIZE(seq);
	tup = PyTuple_New(n);
	if (tup == NULL) return PyErr_NoMemory();

	for (i = 0; i < n; i++) {
		item = PySequence_Fast_GET_ITEM(seq, i);
		str = lowercase(PyObject2char(item));
		if (PyTuple_SetItem(tup, i, PyUnicode_FromString(str)) != 0) {
			PyErr_BadInternalCall();
			return NULL;
		}
		free(str);
	}

	Py_XDECREF(seq);
	return tup;
}

/*	Initializing LDAPValueList. */
static int
LDAPValueList_init(LDAPValueList *self, PyObject *args, PyObject *kwds) {
	Py_ssize_t i;
	PyObject *tmp;
	PyObject *item, *obj = NULL;

	if (!PyArg_ParseTuple(args, "|O", &obj))
	        return -1;

	/* Checking, that the argument is containing unique values. */
	if (obj != NULL) {
	    tmp = get_lowercase_tuple(obj);
		for (i = 0; i < Py_SIZE(tmp); i++) {
			item = PyTuple_GetItem(tmp, i);
			if (PySequence_Count(tmp, item) > 1) {
				Py_DECREF(tmp);
				PyErr_SetString(PyExc_AttributeError, "LDAPListValue's argument is containing non-unique values. (Bool types converted to number)");
				return -1;
			}
		}
		Py_DECREF(tmp);
	}
	if (PyList_Type.tp_init((PyObject *)self, args, kwds) < 0)
		return -1;
	return 0;
}

/*	Create a new LDAPValueList object for internal use. */
LDAPValueList *
LDAPValueList_New(void) {
	LDAPValueList *self = (LDAPValueList *)LDAPValueListType.tp_new(&LDAPValueListType, NULL, NULL);
	return self;
}

/*	Returns 1 if the `newitem` is not in the list, 0 otherwise.
	The function uses the lowerCaseMatch() to compare the list's items and the `newitem`
	to lower-case C string.
*/
static int
isLowerCaseUnique(LDAPValueList *list, PyObject *newitem) {
	Py_ssize_t i;

	for (i = 0; i < Py_SIZE(list); i++) {
		if (lowerCaseMatch(list->list.ob_item[i], newitem) == 1) {
			return 0;
		}
	}
	return 1;
}

/*	Removes case-insensitive `item` from the `list` object.
	Returns 1 if `item` is foun, and removed, 0 otherwise.
*/
static int
removeItemFromList(PyObject *list, PyObject *item) {
	Py_ssize_t i;

	for (i = 0; i < Py_SIZE(list); i++) {
		if (lowerCaseMatch(((PyListObject *)list)->ob_item[i], item) == 1) {
			if (PyList_SetSlice(list, i, i+1, (PyObject *)NULL) != 0) return -1;
			return 1;
		}
	}
	return 0;
}

/*	Append new unique item to the LDAPValueList. Case-insensitive,
  	the `newitem` is also appended to the added list, or remove from the deleted list.
*/
int
LDAPValueList_Append(LDAPValueList *self, PyObject *newitem) {
	int rc = -1;

	if (isLowerCaseUnique(self, newitem) == 0) {
		PyErr_Format(PyExc_ValueError, "%R is already in the list.", newitem);
		return -1;
	}

	rc = removeItemFromList(self->deleted, newitem);
	if (rc == -1) return -1;
	if (rc == 0) {
		if (PyList_Append(self->added, newitem) == -1) {
			PyErr_BadInternalCall();
			return -1;
		}
	}
	return PyList_Append((PyObject *)self, newitem);
}

/*	Returns 1 if obj is an instance of LDAPEntry, or 0 if not.
	On error, returns -1 and sets an exception.
*/
int
LDAPValueList_Check(PyObject *obj) {
	if (obj == NULL) return -1;
	return PyObject_IsInstance(obj, (PyObject *)&LDAPValueListType);
}

/*	Removes the same items from both list. */
static int
balancing(PyObject *l1, PyObject *l2) {
	int rc;
	Py_ssize_t i;

	for (i = 0; i < Py_SIZE(l2); i++) {
		rc = removeItemFromList(l1, ((PyListObject *)l2)->ob_item[i]);
		if (rc == 1) {
			PyList_SetSlice(l2, i, i+1, (PyObject *)NULL);
		} else if (rc == -1) return -1;
	}
	return 0;
}

int
LDAPValueList_Extend(LDAPValueList *self, PyObject *b) {
	PyObject *iter = NULL, *newitem;
	PyObject *concat, *tmp, *ret;

	if (b != NULL) iter = PyObject_GetIter(b);

	if (iter != NULL) {
		for (newitem = PyIter_Next(iter); newitem != NULL; newitem = PyIter_Next(iter)) {
			if (isLowerCaseUnique(self, newitem) == 0){
				PyErr_SetString(PyExc_TypeError, "List is containing non-unique values.");
				return -1;
			}
		}
	}

	if (balancing(b, self->deleted) != 0) return -1;
	concat = PySequence_Concat(self->added, b);
	if (concat) {
		tmp = self->added;
		Py_INCREF(concat);
		self->added = concat;
		Py_XDECREF(tmp);
	}
	ret = _PyList_Extend((PyListObject *)self, b);
	if (ret != Py_None) return -1;
	return 0;
}

/*	Insert new unique item to the `where` position in LDAPValueList. Case-insensitive,
	the `newitem` is also appended to the added list, or remove from the deleted list.
*/
int
LDAPValueList_Insert(LDAPValueList *self, Py_ssize_t where, PyObject *newitem) {
	int rc = -1;

	if (isLowerCaseUnique(self, newitem) == 0) {
		PyErr_Format(PyExc_ValueError, "%R is already in the list.", newitem);
		return -1;
	}

	rc = removeItemFromList(self->deleted, newitem);
	if (rc == -1) return -1;
	if (rc == 0) {
		if (PyList_Append(self->added, newitem) == -1) {
			PyErr_BadInternalCall();
			return -1;
		}
	}
	if (PyList_Append(self->added, newitem) == -1) return -1;
    return PyList_Insert((PyObject *)self, where, newitem);
}

int
LDAPValueList_Remove(LDAPValueList *self, PyObject *value) {
	int cmp;
	Py_ssize_t i;

	for (i = 0; i < Py_SIZE(self); i++) {
		cmp = lowerCaseMatch(self->list.ob_item[i], value);
		if (cmp > 0) {
			if (LDAPValueList_SetSlice(self, i, i+1, (PyObject *)NULL) == 0) return 0;
			return -1;
		} else if (cmp < 0) return -1;
	}
	PyErr_SetString(PyExc_ValueError, "LDAPListValue.remove(x): x not in list");
	return -1;
}

/*	Set new unique item at `i` index in LDAPValueList to `newitem`. Case-insensitive,
	the `newitem` is also appended to the added list, or remove from the deleted list.
	Same goes for the replaced item.
*/
int
LDAPValueList_SetItem(LDAPValueList *self, Py_ssize_t i, PyObject *newitem) {
	int rc = -1;
	PyObject *olditem;

	if (isLowerCaseUnique(self, newitem) == 0) {
		PyErr_Format(PyExc_ValueError, "%R is already in the list.", newitem);
		return -1;
	}

	olditem = PyList_GetItem((PyObject *)self, i);
	if (olditem == NULL) return -1;
	rc = removeItemFromList(self->added, olditem);
	if (rc == -1) return -1;
	if (rc == 0) {
		if (PyList_Append(self->deleted, olditem) == -1) {
			PyErr_BadInternalCall();
			return -1;
		}
	}

	rc = removeItemFromList(self->deleted, newitem);
	if (rc == -1) return -1;
	if (rc == 0) {
		if (PyList_Append(self->added, newitem) == -1) {
			PyErr_BadInternalCall();
			return -1;
		}
	}
	return PyList_SetItem((PyObject *)self, i, newitem);
}

/*	Set the slice of LDAPValueList between `ilow` and `ihigh` to the contents of `itemlist`.
	The `itemlist` must be containing unique elements. New items are append to the added list,
	and removed items are append to the deleted list. The `itemlist` may be NULL, indicating
	the assignment of an empty list (slice deletion).
*/
int
LDAPValueList_SetSlice(LDAPValueList *self, Py_ssize_t ilow, Py_ssize_t ihigh, PyObject *itemlist) {
	PyObject *remove, *tmp = NULL, *concat;
	PyObject *iter = NULL;
	PyObject *newitem;

	if (itemlist != NULL) iter = PyObject_GetIter(itemlist);

	if (iter != NULL) {
		for (newitem = PyIter_Next(iter); newitem != NULL; newitem = PyIter_Next(iter)) {
			if (isLowerCaseUnique(self, newitem) == 0) {
				PyErr_Format(PyExc_ValueError, "%R is already in the list.", newitem);
				return -1;
			}
		}
	}

	/* Copying the removable items from LDAPValueList to deleted list.*/
	remove = PyList_GetSlice((PyObject *)self, ilow, ihigh);
	if (remove == NULL) return -1;
	if (balancing(remove, self->added) != 0) return -1;
	concat = PySequence_Concat(self->deleted, remove);
	if (concat) {
		tmp = self->deleted;
		Py_INCREF(concat);
		self->deleted = concat;
		Py_XDECREF(tmp);
	} else {
		Py_XDECREF(remove);
		return -1;
	}
	Py_XDECREF(remove);

	/* Copying new items to the added list.*/
	if (itemlist != NULL) {
		if (balancing(itemlist, self->deleted) != 0) return -1;
		concat = PySequence_Concat(self->added, itemlist);
		if (concat) {
			tmp = self->added;
			Py_INCREF(concat);
			self->added = concat;
			Py_XDECREF(tmp);
		} else {
			Py_XDECREF(remove);
			return -1;
		}
	}

    return PyList_SetSlice((PyObject *)self, ilow, ihigh, itemlist);
}

static PyObject *
LVL_append(LDAPValueList *self, PyObject *newitem) {
    if (LDAPValueList_Append(self, newitem) == 0) {
    	self->status = 1;
    	return Py_None;
    }
    return NULL;
}

static PyObject *
LVL_extend(LDAPValueList *self, PyObject *b) {
	if (LDAPValueList_Extend(self, b) == 0) {
		self->status = 1;
		return Py_None;
	}
	return NULL;
}

static PyObject *
LVL_insert(LDAPValueList *self, PyObject *args) {
    Py_ssize_t i;
    PyObject *v;

    if (!PyArg_ParseTuple(args, "nO:insert", &i, &v)) return NULL;
    if (LDAPValueList_Insert(self, i, v) == 0) {
    	self->status = 1;
    	return Py_None;
    }
    return NULL;
}

static PyObject *
LVL_pop(LDAPValueList *self, PyObject *args) {
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
	value = self->list.ob_item[i];
	Py_INCREF(value);

	status = LDAPValueList_SetSlice(self, i, i+1, (PyObject *)NULL);
	if (status != 0) return NULL;

	self->status = 1;
	return value;
}

static PyObject *
LVL_remove(LDAPValueList *self, PyObject *value) {
	if (LDAPValueList_Remove(self, value) == 0) {
		self->status = 1;
		return Py_None;
	}
	return NULL;
}

static PyMethodDef LDAPValueList_methods[] = {
    {"append", 	(PyCFunction)LVL_append, 	METH_O, "Append new item to the LDAPValueList." },
    {"extend",  (PyCFunction)LVL_extend,  	METH_O, "Extend LDAPValueList."},
    {"insert", 	(PyCFunction)LVL_insert,	METH_VARARGS, "Insert new item in the LDAPValueList."},
    {"pop",		(PyCFunction)LVL_pop, 		METH_VARARGS, "Pop-pop."},
    {"remove", 	(PyCFunction)LVL_remove, 	METH_O, "Remove item from LDAPValueList."},
    {NULL, NULL, 0, NULL}  /* Sentinel */
};

static PyObject *
LVL_concat(LDAPValueList *self, PyObject *bb) {
	LDAPValueList *np = LDAPValueList_New();

	if (np == NULL) return PyErr_NoMemory();

	if (LVL_extend(np, (PyObject *)self) == NULL) return NULL;
	if (LVL_extend(np, bb) == NULL) return NULL;

	return (PyObject *)np;
}

static int
LVL_ass_item(LDAPValueList *self, Py_ssize_t i, PyObject *v) {
    if (i < 0 || i >= Py_SIZE(self)) {
        PyErr_SetString(PyExc_IndexError,
                        "list assignment index out of range");
        return -1;
    }
    if (v == NULL) return LDAPValueList_SetSlice(self, i, i+1, v);
    return LDAPValueList_SetItem(self, i, v);
}

static int
LVL_contains(LDAPValueList *self, PyObject *el) {
    int cmp;
	Py_ssize_t i;
	PyObject *tup;

	tup = get_lowercase_tuple((PyObject *)self);
	if (tup == NULL) return -1;

    for (i = 0, cmp = 0 ; cmp == 0 && i < Py_SIZE(tup); ++i) {
    	cmp = lowerCaseMatch(PyTuple_GetItem(tup, i), el);
    }
    return cmp;
}

static PyObject *
LVL_inplace_concat(LDAPValueList *self, PyObject *other) {
    PyObject *result;

    result = LVL_extend(self, other);
    if (result == NULL)
        return result;
    Py_DECREF(result);
    Py_INCREF(self);
    return (PyObject *)self;
}

static PyObject *
LVL_dummy(LDAPValueList *self, Py_ssize_t n) {
	PyErr_SetString(PyExc_TypeError, "unsupported operand.");
	return NULL;
}

static PySequenceMethods LVL_as_sequence = {
    0,                      		/* sq_length */
    (binaryfunc)LVL_concat,			/* sq_concat */
    (ssizeargfunc)LVL_dummy,        /* sq_repeat */
    0,                    			/* sq_item */
    0,                             	/* sq_slice */
    (ssizeobjargproc)LVL_ass_item,	/* sq_ass_item */
    0,                              /* sq_ass_slice */
    (objobjproc)LVL_contains,       /* sq_contains */
    (binaryfunc)LVL_inplace_concat,	/* sq_inplace_concat */
    (ssizeargfunc)LVL_dummy,        /* sq_inplace_repeat */
};

/*	This function is based on list_ass_subscript from Python source listobject.c.
	But it uses LDAPValueList's setslice and setitem functions instead of memory opertation.
	It is probably a much more slower, but cleaner solution.
*/
static int
LVL_ass_subscript(LDAPValueList *self, PyObject *item, PyObject *value) {
    size_t cur;
	Py_ssize_t i;
	Py_ssize_t start, stop, step, slicelength;
    PyObject *seq;
    PyObject **seqitems;

	if (PyIndex_Check(item)) {
		i = PyNumber_AsSsize_t(item, PyExc_IndexError);
		if (i == -1 && PyErr_Occurred()) return -1;
		if (i < 0) i += PyList_GET_SIZE(self);
		return LVL_ass_item(self, i, value);
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

static PyMappingMethods LVL_as_mapping = {
    0,									/* mp_length */
    0,									/* mp_subscript */
    (objobjargproc)LVL_ass_subscript,	/* mp_ass_subscript */
};

PyTypeObject LDAPValueListType = {
    PyObject_HEAD_INIT(NULL)
    "pyLDAP.LDAPValueList",      /* tp_name */
    sizeof(LDAPValueList),       /* tp_basicsize */
    0,                       /* tp_itemsize */
    (destructor)LDAPValueList_dealloc,       /* tp_dealloc */
    0,                       /* tp_print */
    0,                       /* tp_getattr */
    0,                       /* tp_setattr */
    0,                       /* tp_reserved */
    0,                       /* tp_repr */
    0,                       /* tp_as_number */
    &LVL_as_sequence,        /* tp_as_sequence */
    &LVL_as_mapping,		 /* tp_as_mapping */
    0,                       /* tp_hash */
    0,                       /* tp_call */
    0,                       /* tp_str */
    0,                       /* tp_getattro */
    0,                       /* tp_setattro */
    0,                       /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT |
        Py_TPFLAGS_BASETYPE, /* tp_flags */
    0,                       /* tp_doc */
    0,                       /* tp_traverse */
    0,                       /* tp_clear */
    0,                       /* tp_richcompare */
    0,                       /* tp_weaklistoffset */
    0,                       /* tp_iter */
    0,                       /* tp_iternext */
    LDAPValueList_methods,   /* tp_methods */
    0,       				 /* tp_members */
    0,    					 /* tp_getset */
    &PyList_Type,            /* tp_base */
    0,                       /* tp_dict */
    0,                       /* tp_descr_get */
    0,                       /* tp_descr_set */
    0,                       /* tp_dictoffset */
    (initproc)LDAPValueList_init,/* tp_init */
    0,                       /* tp_alloc */
    LDAPValueList_new,      /* tp_new */
};
