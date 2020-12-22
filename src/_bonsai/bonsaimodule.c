#define PY_SSIZE_T_CLEAN

#include <Python.h>

#include "ldapconnection.h"
#include "ldapentry.h"
#include "ldapsearchiter.h"
#include "ldapmodlist.h"
#include "ldapconnectiter.h"
#include "utils.h"

PyObject *LDAPDNObj = NULL;
PyObject *LDAPEntryObj = NULL;
PyObject *LDAPValueListObj = NULL;
char _g_debugmod = 0;

/* The asynchronous connection build does not function properly on macOS */
char _g_asyncmod = 0;

/* Set if async connections will be used. */
static PyObject *
bonsai_set_connect_async(PyObject *self, PyObject *args) {
    PyObject *flag;

    if (!PyArg_ParseTuple(args,"O!", &PyBool_Type, &flag)) {
        return NULL;
    }

    _g_asyncmod = (char)PyObject_IsTrue(flag);

    Py_RETURN_NONE;
}

/* Turn on and off debug mod. */
static PyObject *
bonsai_set_debug(PyObject *self, PyObject *args, PyObject *kwds) {
    int deb_level = 0;
    PyObject *flag = NULL;
    static char *kwlist[] = {"debug", "level", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!|i", kwlist,
        &PyBool_Type, &flag, &deb_level)) {
        return NULL;
    }

    _g_debugmod = (char)PyObject_IsTrue(flag);
#ifndef WIN32
    ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, &deb_level);
#endif
    Py_RETURN_NONE;
}

/* Get the vendor's name and version of the LDAP library. */
static PyObject *
bonsai_get_vendor_info(PyObject *self) {
    int rc = 0;
    LDAPAPIInfo info;

    info.ldapai_info_version = LDAP_API_INFO_VERSION;
    rc = ldap_get_option(NULL, LDAP_OPT_API_INFO, &info);
    if (rc != LDAP_SUCCESS) {
        PyErr_SetString(PyExc_Exception, "Failed to receive API info.");
        return NULL;
    }

    return Py_BuildValue("(s,i)", info.ldapai_vendor_name,
            info.ldapai_vendor_version);
}


/* Get the name of the underlying TLS library implementation. */
static PyObject *
bonsai_get_tls_impl_name(PyObject *self) {
    int rc = 0;
    char *package = NULL;
    PyObject *str = NULL;

    rc = ldap_get_option(NULL, LDAP_OPT_X_TLS_PACKAGE, &package);
    if (rc != LDAP_SUCCESS || package == NULL) {
        PyErr_SetString(PyExc_Exception, "Failed to receive name of the"
                " TLS implementation.");
        return NULL;
    }

    str = PyUnicode_FromString(package);
    ldap_memfree(package);
    return str;
}

/* Check that the module is build with additional KRB5 support. */
static PyObject *
bonsai_has_krb5_support(PyObject *self) {
#if defined(HAVE_KRB5) || defined(WIN32)
    Py_RETURN_TRUE;
#else
    Py_RETURN_FALSE;
#endif
}

/* Check that the `value` is in the `list` in a ces-insensitive manner.
   The return value is a tuple of two: first is a bool value that indicates
   whether the item is found or not, the second one is the found item. */
static PyObject *
bonsai_unique_contains(PyObject *self, PyObject *args) {
    PyObject *list = NULL;
    PyObject *value = NULL;

    if (!PyArg_ParseTuple(args, "OO", &list, &value)) return NULL;

    return unique_contains(list, value);
}

static void
bonsai_free(PyObject *self) {
    Py_DECREF(LDAPDNObj);
    Py_DECREF(LDAPValueListObj);
    Py_XDECREF(LDAPEntryObj);
    //Py_TYPE(self)->tp_free((PyObject*)self); // Causes segfault on 3.8.
}

static PyMethodDef bonsai_methods[] = {
    {"set_connect_async", (PyCFunction)bonsai_set_connect_async, METH_VARARGS,
        "Sets if bonsai will attempt async connections."},
    {"get_vendor_info", (PyCFunction)bonsai_get_vendor_info, METH_NOARGS,
        "Returns the vendor information of LDAP library."},
    {"get_tls_impl_name", (PyCFunction)bonsai_get_tls_impl_name, METH_NOARGS,
        "Returns the name of the underlying TLS implementation."},
    {"has_krb5_support", (PyCFunction)bonsai_has_krb5_support, METH_NOARGS,
        "Check that the module is build with additional Kerberos support."},
    {"set_debug", (PyCFunction)bonsai_set_debug, METH_VARARGS | METH_KEYWORDS,
        "Turn on and off debug mode."},
    {"_unique_contains", (PyCFunction)bonsai_unique_contains, METH_VARARGS,
        "Check that the item is in the LDAPValueList. Returns with a tuple of"
        "status of the search and the matched element."},
    {NULL, NULL, 0, NULL}  /* Sentinel */
};

static PyModuleDef bonsai2module = {
    PyModuleDef_HEAD_INIT,
    "_bonsai",
    "Python C extension for accessing directory servers using LDAP.",
    -1,
    bonsai_methods, NULL, NULL, NULL, (freefunc)bonsai_free
};

PyMODINIT_FUNC
PyInit__bonsai(void) {
    PyObject* module = NULL;

    /* Import LDAPDN object. */
    LDAPDNObj = load_python_object("bonsai.ldapdn", "LDAPDN");
    if (LDAPDNObj == NULL) return NULL;

    /* Import LDAPValueList object. */
    LDAPValueListObj = load_python_object("bonsai.ldapvaluelist", "LDAPValueList");
    if (LDAPValueListObj == NULL) return NULL;

    module = PyModule_Create(&bonsai2module);
    if (module == NULL) return NULL;

    LDAPEntryType.tp_base = &PyDict_Type;

    if (PyType_Ready(&LDAPConnectionType) < 0) return NULL;
    if (PyType_Ready(&LDAPSearchIterType) < 0) return NULL;
    if (PyType_Ready(&LDAPConnectIterType) < 0) return NULL;
    if (PyType_Ready(&LDAPEntryType) < 0) return NULL;
    if (PyType_Ready(&LDAPModListType) < 0) return NULL;

    Py_INCREF(&LDAPEntryType);
    PyModule_AddObject(module, "ldapentry", (PyObject *)&LDAPEntryType);

    Py_INCREF(&LDAPConnectionType);
    PyModule_AddObject(module, "ldapconnection", (PyObject *)&LDAPConnectionType);

    Py_INCREF(&LDAPSearchIterType);
    PyModule_AddObject(module, "ldapsearchiter", (PyObject *)&LDAPSearchIterType);

    return module;
}
