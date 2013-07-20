#include <Python.h>

#include "errors.h"
#include "ldapclient.h"
#include "ldapentry.h"
#include "ldapvaluelist.h"

static PyModuleDef pyldap2module = {
    PyModuleDef_HEAD_INIT,
    "_cpyLDAP",
    "Module to access directory servers using LDAP.",
    -1,
    NULL, NULL, NULL, NULL, NULL
};

PyMODINIT_FUNC
PyInit__cpyLDAP(void) {
    PyObject* m;

    if (PyType_Ready(&LDAPClientType) < 0) return NULL;
    if (PyType_Ready(&LDAPEntryType) < 0) return NULL;
    if (PyType_Ready(&LDAPValueListType) < 0) return NULL;

    m = PyModule_Create(&pyldap2module);
    if (m == NULL) return NULL;

	LDAPError = PyErr_NewException("pyLDAP.LDAPError", NULL, NULL);
    Py_INCREF(LDAPError);
    PyModule_AddObject(m, "LDAPError", LDAPError);

    LDAPExc_NotConnected = PyErr_NewException("pyLDAP.LDAPError.NotConnected", LDAPError, NULL);
    Py_INCREF(LDAPExc_NotConnected);
    PyModule_AddObject(m, "LDAPError.NotConnected", LDAPExc_NotConnected);

	LDAPExc_UrlError = PyErr_NewException("pyLDAP.LDAPError.UrlError", LDAPError, NULL);
    Py_INCREF(LDAPExc_UrlError);
    PyModule_AddObject(m, "LDAPError.UrlError", LDAPExc_UrlError);

    Py_INCREF(&LDAPEntryType);
    PyModule_AddObject(m, "LDAPEntry", (PyObject *)&LDAPEntryType);

    Py_INCREF(&LDAPClientType);
    PyModule_AddObject(m, "LDAPClient", (PyObject *)&LDAPClientType);

    Py_INCREF(&LDAPValueListType);
    PyModule_AddObject(m, "LDAPValueList", (PyObject *)&LDAPValueListType);

    return m;
}
