#include <Python.h>

#include "ldapconnection.h"
#include "ldapentry.h"
#include "ldapvaluelist.h"
#include "ldapsearchiter.h"

static PyModuleDef pyldap2module = {
    PyModuleDef_HEAD_INIT,
    "_cpyldap",
    "Module to access directory servers using LDAP.",
    -1,
    NULL, NULL, NULL, NULL, NULL
};

PyMODINIT_FUNC
PyInit__cpyldap(void) {
    PyObject* m;

    UniqueListType.tp_base = &PyList_Type;
    LDAPValueListType.tp_base = &UniqueListType;
    LDAPEntryType.tp_base = &PyDict_Type;

    if (PyType_Ready(&LDAPConnectionType) < 0) return NULL;
    if (PyType_Ready(&LDAPSearchIterType) < 0) return NULL;
    if (PyType_Ready(&LDAPEntryType) < 0) return NULL;
    if (PyType_Ready(&LDAPValueListType) < 0) return NULL;

    m = PyModule_Create(&pyldap2module);
    if (m == NULL) return NULL;

    Py_INCREF(&LDAPEntryType);
    PyModule_AddObject(m, "_LDAPEntry", (PyObject *)&LDAPEntryType);

    Py_INCREF(&LDAPConnectionType);
    PyModule_AddObject(m, "_LDAPConnection", (PyObject *)&LDAPConnectionType);

    Py_INCREF(&LDAPValueListType);
    PyModule_AddObject(m, "LDAPValueList", (PyObject *)&LDAPValueListType);

    return m;
}
