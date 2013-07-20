#ifndef ERRORS_H_
#define ERRORS_H_

#include <Python.h>
#include <ldap.h>

extern PyObject *LDAPError;
extern PyObject *LDAPExc_UrlError;
extern PyObject *LDAPExc_NotConnected;

#endif /* ERRORS_H_ */
