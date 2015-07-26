/*
 * ldapmodlist.c
 *
 *  Created on: 7 Nov 2014
 *      Author: noirello
 */

#include "ldapmodlist.h"

#include "utils.h"
#include "uniquelist.h"

/*	Dealloc the LDAPModList object. */
static void
LDAPModList_dealloc(LDAPModList* self) {
	int i, j;
	struct berval **bvals;

	if (self->mod_list != NULL) {
		for (i = 0; self->mod_list[i] != NULL; i++) {
			bvals = self->mod_list[i]->mod_vals.modv_bvals;
			if (bvals != NULL) {
				for (j = 0; bvals[j] != NULL; j++) {
					free(bvals[j]->bv_val);
					free(bvals[j]);
				}
				free(bvals);
			}
			free(self->mod_list[i]->mod_type);
			free(self->mod_list[i]);
		}
		free(self->mod_list);
	}
	Py_TYPE(self)->tp_free((PyObject*)self);
}

/*	Create a new LDAPModList object. */
static PyObject *
LDAPModList_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
	LDAPModList *self = NULL;

	self = (LDAPModList *)type->tp_alloc(type, 0);
	if (self != NULL) {
		self->mod_list = NULL;
		self->entry = NULL;
		self->last = 0;
	}

	return (PyObject *)self;
}

/*	Create a new LDAPModList object for internal use with a `size` length LDAPMod list,
    that represents the `entry` object modifications. */
LDAPModList *
LDAPModList_New(PyObject* entry, unsigned short int size) {
	LDAPModList *self = (LDAPModList *)LDAPModListType.tp_new(&LDAPModListType, NULL, NULL);
	if (self == NULL) return NULL;
	/*  Malloc a new `size` length LDAPMod list. */
	self->mod_list  = (LDAPMod **)malloc(sizeof(LDAPMod *) * (size + 1));
	if (self->mod_list != NULL) self->mod_list[0] = NULL;
	self->size = size;
	self->entry = entry;
	return self;
}

int
LDAPModList_Add(LDAPModList *self, int mod_op, PyObject *key, PyObject *value) {
	LDAPMod *mod;

	/* Malloc a new LDAPMod struct. */
	mod = (LDAPMod *)malloc(sizeof(LDAPMod));
	if (mod == NULL) return -1;

	/* Set the values with the parameters. */
	mod->mod_op = mod_op;
	mod->mod_type = CONVERTTO(PyObject2char(key), 1);
	mod->mod_vals.modv_bvals = PyList2BervalList(value);

	/* Add to the next free slot, if there is one. */
	if (self->last == self->size) {
		PyErr_Format(PyExc_OverflowError, "The LDAPModList is full.");
		return -1;
	}
	self->mod_list[self->last++] = mod;
	self->mod_list[self->last] = NULL;

	return 0;
}

PyObject *
LDAPModList_Pop(LDAPModList *self) {
	int i;
	LDAPMod *mod;
	PyObject *berval = NULL;
	PyObject *ret = NULL;
	PyObject *mod_type = NULL;
	UniqueList *list = NULL;
	struct berval **mod_bvals;

	if (self->last > 0) {
		mod = self->mod_list[--self->last];
		mod_bvals = mod->mod_vals.modv_bvals;

		mod_type = PyUnicode_FromUSTR(mod->mod_type);
		if (mod_type == NULL) return NULL;

		if (mod_bvals != NULL) {
			list = UniqueList_New();
			if (list == NULL) return NULL;

			for (i = 0; mod_bvals[i] != NULL; i++) {
				/* Convert bervals to PyObject. */
				berval = berval2PyObject(mod_bvals[i], 0);
				if (berval == NULL) return NULL;
				/* Append to the list. */
				if (UniqueList_Append(list, berval) != 0) return NULL;
				Py_DECREF(berval);
				/* Free bervals. */
				free(mod_bvals[i]->bv_val);
				free(mod_bvals[i]);
			}
			free(mod->mod_vals.modv_bvals);
			/* Create tuple with return values. */
			ret = Py_BuildValue("(OiO)", mod_type,
					mod->mod_op ^ LDAP_MOD_BVALUES, (PyObject *)list);
		} else {
			ret = Py_BuildValue("(OiO)", mod_type,
					mod->mod_op ^ LDAP_MOD_BVALUES, Py_None);
		}
		/* Free LDAPMod and Move NULL to the new end of the LDAPMods. */
		free(mod->mod_type);
		free(mod);
		self->mod_list[self->last] = NULL;
	}

	return ret;
}

/* Return 1, if the LDAPModList has no item, 0 otherwise. */
int
LDAPModList_Empty(LDAPModList *self) {
    /* It is possible that LDAPModList is casted from None.
    In this case the value of last prop might be invalid. */
	if (self->last == 0 || (PyObject *)self == Py_None) {
		return 1;
	}
	return 0;
}

PyTypeObject LDAPModListType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "pyldap._LDAPModList",       /* tp_name */
    sizeof(LDAPModList),        /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)LDAPModList_dealloc, /* tp_dealloc */
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
    "Wrapper around LDAPMod struct.",   /* tp_doc */
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
    0,						 /* tp_init */
    0,                         /* tp_alloc */
    LDAPModList_new,            /* tp_new */
};
