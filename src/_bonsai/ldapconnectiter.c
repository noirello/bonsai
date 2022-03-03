#include "ldapconnectiter.h"

#include "utils.h"

#ifdef WIN32
//MS Windows

/* Poll the answer of the separate thread that runs the binding process.
Returns NULL in case of error, Py_None for timeout, and the LDAPConnection
object if successfully finished the binding. */
static PyObject *
binding(LDAPConnectIter *self) {
    int rc;
    char buff[1];
    PyObject *value = NULL;

    DEBUG("binding [state:%d]", self->state);
    if (self->state == 3) {
        /* First call of bind. */
        rc = _ldap_bind(self->conn->ld, self->info, self->conn->ppolicy,
            NULL, &(self->message_id));
        if (rc != LDAP_SUCCESS) {
            set_exception(self->conn->ld, rc);
            return NULL;
        }
        self->state = 4;
        Py_RETURN_NONE;
    } else {
        if (self->conn->async == 0) {
            rc = WaitForSingleObject(self->info->thread, self->timeout);
        } else {
            rc = WaitForSingleObject(self->info->thread, 10);
        }
        switch (rc) {
        case WAIT_TIMEOUT:
            if (self->conn->async == 0) {
                TerminateThread(self->info->thread, -1);
                CloseHandle(self->info->thread);
                ldap_unbind_ext(self->conn->ld, NULL, NULL);
                set_exception(NULL, LDAP_TIMEOUT);
                return NULL;
            }
            Py_RETURN_NONE;
        case WAIT_OBJECT_0:
            GetExitCodeThread(self->info->thread, &rc);
            CloseHandle(self->info->thread);
            if (rc != LDAP_SUCCESS) {
                /* The ldap_connect is failed. Set a Python error. */
                set_exception(self->conn->ld, rc);
                return NULL;
            }
            if (self->conn->csock != -1) {
                /* Read and drop the data from the dummy socket. */
                if (recv(self->conn->csock, buff, 1, 0) == -1) return NULL;
                /* Dummy sockets are no longer needed. */
                self->conn->csock = -1;
                close_socketpair(self->conn->socketpair);
            }
            /* The binding is successfully finished. */
            self->state = 5;
            self->conn->closed = 0;
            if (self->conn->ppolicy == 1) {
                /* Create (result, ctrl) tuple as return value.
                   Because WinLDAP does not support password policy control,
                   it is always None. */
                value = Py_BuildValue("(O,O)", self->conn, Py_None);
                if (value == NULL) return NULL;
                return value;
            }
            else {
                Py_INCREF(self->conn);
                return (PyObject *)self->conn;
            }
        default:
            /* The thread is failed. */
            PyErr_BadInternalCall();
            return NULL;
        }
    }
}


/* Dummy function, because there are no options for setting
   CA or client certs for WinLDAP. */
static int
set_certificates(LDAPConnectIter *self) {
    return 0;
}

static int
check_tls_result(LDAP *ld, HANDLE msgid, int timeout, char async, SOCKET csock) {
    int rc = 0;
    char buff[1];
    DWORD x = 0;

    DEBUG("check_tls_result (ld:%p, msgid:%p, timeout:%d, async:%d, csock:%d)",
        ld, msgid, timeout, async, (int)csock);
    if (async == 0) {
        rc = WaitForSingleObject(msgid, timeout);
    } else {
        rc = WaitForSingleObject(msgid, 10);
    }
    switch (rc) {
    case WAIT_TIMEOUT:
        if (async == 0) {
            TerminateThread(msgid, -1);
            CloseHandle(msgid);
            set_exception(NULL, LDAP_TIMEOUT);
            return -1;
        }
        return 0;
    case WAIT_OBJECT_0:
        GetExitCodeThread(msgid, &rc);
        CloseHandle(msgid);
        if (rc != LDAP_SUCCESS) {
            /* The ldap_connect is failed. Set a Python error. */
            set_exception(ld, rc);
            return -1;
        }
        if (csock != -1) {
            /* Read and drop the data from the dummy socket. */
            if (recv(csock, buff, 1, 0) == -1) return -1;
        }
        return 1;
    default:
        /* The thread is failed. */
        PyErr_BadInternalCall();
        return -1;
    }
}

#else

 /* Poll the answer of the async function calls of the binding process.
 Returns NULL in case of error, Py_None for timeout, and the LDAPConnection
 object if successfully finished the binding. */
static PyObject *
binding(LDAPConnectIter *self) {
    int rc = -1;
    int err = 0;
    int ppres = 0;
    unsigned int pperr = 0;
    struct timeval polltime;
    LDAPControl **returned_ctrls = NULL;
    LDAPMessage *res;
    PyObject *ctrl_obj = NULL;
    PyObject *value = NULL;

    if (self->timeout == -1) {
        polltime.tv_sec = 0L;
        polltime.tv_usec = 10L;
    } else {
        polltime.tv_sec = self->timeout / 1000;
        polltime.tv_usec = (self->timeout % 1000) * 1000;
    }

    DEBUG("binding [state:%d]", self->state);
    if (self->state == 3) {
        /* First call of bind. */
        rc = _ldap_bind(self->conn->ld, self->info, self->conn->ppolicy,
                NULL, &(self->message_id));
        if (rc != LDAP_SUCCESS && rc != LDAP_SASL_BIND_IN_PROGRESS) {
            close_socketpair(self->conn->socketpair);
            set_exception(self->conn->ld, rc);
            return NULL;
        }
        if (self->conn->csock != -1) {
            /* Dummy sockets are no longer needed. Dispose. */
            self->conn->csock = -1;
            close_socketpair(self->conn->socketpair);
        }
        self->state = 4;
        Py_RETURN_NONE;
    } else {
        if (self->conn->async == 0) {
            /* Block until the server response. */
            if (self->timeout == -1) {
                rc = ldap_result(self->conn->ld, self->message_id, LDAP_MSG_ALL, NULL, &res);
            } else {
                rc = ldap_result(self->conn->ld, self->message_id, LDAP_MSG_ALL, &polltime, &res);
            }
        } else {
            /* Binding is already in progress, poll result from the server. */
            rc = ldap_result(self->conn->ld, self->message_id, LDAP_MSG_ALL, &polltime, &res);
        }
        switch (rc) {
        case -1:
            /* Error occurred during the operation. */
            ldap_msgfree(res);
            set_exception(self->conn->ld, 0);
            return NULL;
        case 0:
            /* Timeout exceeded.*/
            ldap_msgfree(res);
            if (self->conn->async == 0) {
                set_exception(self->conn->ld, -5);
                return NULL;
            }
            Py_RETURN_NONE;
        case LDAP_RES_BIND:
            /* Response is arrived from the server. */
            rc = ldap_parse_result(self->conn->ld, res, &err, NULL, NULL, NULL, &returned_ctrls, 0);
            if (rc != LDAP_SUCCESS) {
                ldap_msgfree(res);
                return NULL;
            }

            ppres = create_ppolicy_control(self->conn->ld, returned_ctrls,
                    &ctrl_obj, &pperr);
            if (returned_ctrls != NULL) ldap_controls_free(returned_ctrls);
            if (ppres == -1) return NULL;

            if (err != LDAP_SASL_BIND_IN_PROGRESS && err != LDAP_SUCCESS) {
                /* Connection is failed. */
                ldap_msgfree(res);
                if (ppres == 1 && pperr != 65535) set_ppolicy_err(pperr, ctrl_obj);
                else set_exception(self->conn->ld, err);

                return NULL;
            }

            if (strcmp(self->info->mech, "SIMPLE") != 0) {
                /* Continue SASL binding procedure. */
                rc = _ldap_bind(self->conn->ld, self->info, self->conn->ppolicy,
                        res, &(self->message_id));

                if (rc != LDAP_SUCCESS && rc != LDAP_SASL_BIND_IN_PROGRESS) {
                    set_exception(self->conn->ld, rc);
                    return NULL;
                }

                if (rc == LDAP_SASL_BIND_IN_PROGRESS) {
                    Py_RETURN_NONE;
                }
            } else {
                ldap_msgfree(res);
            }

            if (rc == LDAP_SUCCESS) {
                /* The binding is successfully finished. */
                self->state = 5;
                self->conn->closed = 0;
                if (self->conn->ppolicy == 1) {
                    /* If ppolicy is not available set control to None. */
                    if (ppres != 1) ctrl_obj = Py_None;

                    /* Create (result, ctrl) tuple as return value. */
                    value = Py_BuildValue("(O,O)", self->conn, ctrl_obj);
                    Py_DECREF(ctrl_obj);
                    if (value == NULL) return NULL;
                    return value;
                } else {
                    Py_INCREF(self->conn);
                    return (PyObject *)self->conn;
                }
            }
            Py_RETURN_NONE;
        default:
            /* Invalid return value, it never should happen. */
            PyErr_BadInternalCall();
            return NULL;
        }
    }
}

/* Return a char* attribute from the LDAPClient object. */
static int
get_tls_attribute(PyObject *client, const char *name, char **value) {
    PyObject *tmp = NULL;

    tmp = PyObject_GetAttrString(client, name);
    if (tmp == NULL) return -1;

    if (tmp == Py_None) *value = NULL;
    else *value= PyObject2char(tmp);
    Py_DECREF(tmp);

    return 0;
}

/* Set CA and client certificates for the connection. */
static int
set_certificates(LDAPConnectIter* self) {
    int rc = 0;
    const int true_val = 1;
    char *ca_cert_dir = NULL;
    char *ca_cert = NULL;
    char *client_cert = NULL;
    char *client_key = NULL;

    DEBUG("set_certificates (self:%p)", self);
    /* Set CA cert directory from LDAPClient. */
    rc = get_tls_attribute(self->conn->client, "ca_cert_dir", &ca_cert_dir);
    if (rc != 0) goto error;
    /* Set CA cert from LDAPClient. */
    rc = get_tls_attribute(self->conn->client, "ca_cert", &ca_cert);
    if (rc != 0) goto error;
    /* Set client cert from LDAPClient. */
    rc = get_tls_attribute(self->conn->client, "client_cert", &client_cert);
    if (rc != 0) goto error;
    /* Set client key from LDAPClient. */
    rc = get_tls_attribute(self->conn->client, "client_key", &client_key);
    if (rc != 0) goto error;

    if (ca_cert_dir == NULL || strcmp(ca_cert_dir, "") != 0) {
        ldap_set_option(self->conn->ld, LDAP_OPT_X_TLS_CACERTDIR, ca_cert_dir);
    }
    if (ca_cert == NULL || strcmp(ca_cert, "") != 0) {
        ldap_set_option(self->conn->ld, LDAP_OPT_X_TLS_CACERTFILE, ca_cert);
    }
    if (client_cert == NULL || strcmp(client_cert, "") != 0) {
        ldap_set_option(self->conn->ld, LDAP_OPT_X_TLS_CERTFILE, client_cert);
    }
    if (client_key == NULL || strcmp(client_key, "") != 0) {
        ldap_set_option(self->conn->ld, LDAP_OPT_X_TLS_KEYFILE, client_key);
    }
    /* Force libldap to create new context for the connection. */
    ldap_set_option(self->conn->ld, LDAP_OPT_X_TLS_NEWCTX, &true_val);

error:
    free(ca_cert);
    free(ca_cert_dir);
    free(client_cert);
    free(client_key);
    return rc;
}

static int
check_tls_result(LDAP *ld, int msgid, int timeout, char async, SOCKET csock) {
    int rc = 0;
    int err = 0;
    char *errstr = NULL;
    LDAPMessage *res;
    LDAPControl **ctrls = NULL;
    struct timeval polltime;
    PyObject *ldaperror = NULL, *errmsg = NULL;

    DEBUG("check_tls_result (ld:%p, msgid:%d, timeout:%d, async:%d, csock:%d)",
        ld, msgid, timeout, async, csock);
    if (timeout == -1) {
        polltime.tv_sec = 0L;
        polltime.tv_usec = 10L;
    } else {
        polltime.tv_sec = timeout / 1000;
        polltime.tv_usec = (timeout % 1000) * 1000;
    }

    if (async == 0) {
        Py_BEGIN_ALLOW_THREADS
        if (timeout == -1) {
            rc = ldap_result(ld, msgid, LDAP_MSG_ALL, NULL, &res);
        } else {
            rc = ldap_result(ld, msgid, LDAP_MSG_ALL, &polltime, &res);
        }
        Py_END_ALLOW_THREADS
    } else {
        rc = ldap_result(ld, msgid, LDAP_MSG_ALL, &polltime, &res);
    }

    switch (rc) {
    case -1:
        /* Error occurred during the operation. */
        ldap_msgfree(res);
        set_exception(ld, 0);
        return -1;
    case 0:
        /* Timeout exceeded.*/
        ldap_msgfree(res);
        if (async == 0) {
            set_exception(ld, -5);
            return -1;
        }
        return 0;
    case LDAP_RES_EXTENDED:
        rc = ldap_parse_result(ld, res, &err, NULL, &errstr, NULL, &ctrls, 0);
        if (rc != LDAP_SUCCESS || err != LDAP_SUCCESS) {
            ldaperror = get_error_by_code(err);
            if (ldaperror == NULL) return -1;
            if (errstr != NULL) errmsg = PyUnicode_FromFormat("%s.", errstr);
            if (errmsg != NULL) {
                PyErr_SetObject(ldaperror, errmsg);
                Py_DECREF(errmsg);
            } else PyErr_SetString(ldaperror, "");
            Py_DECREF(ldaperror);
            return -1;
        }

        rc = ldap_parse_extended_result(ld, res, NULL, NULL, 1);
        if (rc != LDAP_SUCCESS) {
            set_exception(ld, rc);
            return -1;
        }
        rc = ldap_install_tls(ld);
        if (rc != LDAP_SUCCESS) {
            set_exception(ld, rc);
            return -1;
        }
        return 1;
    default:
        PyErr_BadInternalCall();
        return -1;
    }
}

#endif

/*  Dealloc the LDAPConnectIter object. */
static void
ldapconnectiter_dealloc(LDAPConnectIter* self) {
    DEBUG("ldapconnectiter_dealloc (self:%p)", self);
    Py_XDECREF(self->conn);
    if (self->info != NULL) dealloc_conn_info(self->info);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

/*  Create a new LDAPConnectIter object. */
static PyObject *
ldapconnectiter_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
    LDAPConnectIter *self = NULL;
    PyObject *ts_empty_tuple = PyTuple_New(0);
    PyObject *ts_empty_dict = PyDict_New();

    if (ts_empty_tuple == NULL || ts_empty_dict == NULL) {
        Py_XDECREF(ts_empty_tuple);
        Py_XDECREF(ts_empty_dict);
        return NULL;
    }

    self = (LDAPConnectIter *)PyBaseObject_Type.tp_new(type, ts_empty_tuple,
                                                       ts_empty_dict);

    if (self != NULL) {
        self->conn = NULL;
        self->state = 0;
        self->message_id = 0;
        self->init_thread_data = NULL;
        self->init_thread = 0;
        self->timeout = -1;
        self->tls = 0;
    }

    Py_DECREF(ts_empty_tuple);
    Py_DECREF(ts_empty_dict);
    DEBUG("ldapconnectiter_new [self:%p]", self);
    return (PyObject *)self;
}

/* Create and return a ldapInitThreadData struct for the initialisation thread. */
static ldapInitThreadData *
create_init_thread_data(PyObject *client, SOCKET sock) {
    ldapInitThreadData *data = NULL;
    PyObject *url = NULL;
    PyObject *tmp = NULL;

    DEBUG("create_init_thread_data (client:%p, sock:%d)", client, (int)sock);
    data = (ldapInitThreadData *)malloc(sizeof(ldapInitThreadData));
    if (data == NULL) {
        PyErr_NoMemory();
        return NULL;
    }
    data->url = NULL;

    /* Get URL policy from LDAPClient. */
    url = PyObject_GetAttrString(client, "url");
    if (url == NULL) goto error;

    /* Get URL address information from the LDAPClient's LDAPURL object. */
    tmp = PyObject_CallMethod(url, "get_address", NULL);
    Py_DECREF(url);
    if (tmp == NULL) goto error;
    data->url = PyObject2char(tmp);
    Py_DECREF(tmp);
    if (data->url == NULL) goto error;

    /* Set cert policy from LDAPClient. */
    tmp = PyObject_GetAttrString(client, "cert_policy");
    if (tmp == NULL) return NULL;
    data->cert_policy = (int)PyLong_AsLong(tmp);
    Py_DECREF(tmp);

     /* Set referrals from LDAPClient. */
    tmp = PyObject_GetAttrString(client, "server_chase_referrals");
    if (tmp == NULL) goto error;
    data->referrals = PyObject_IsTrue(tmp);
    Py_DECREF(tmp);

     /* Set sasl sec properties from LDAPClient. */
    tmp = PyObject_GetAttrString(client, "sasl_security_properties");
    if (tmp == NULL) goto error;
    if (tmp != Py_None) {
        data->sasl_sec_props = PyObject2char(tmp);
    } else {
        data->sasl_sec_props = NULL;
    }
    Py_DECREF(tmp);

    data->ld = NULL;
    data->sock = sock;
    data->retval = 0;
    return data;
error:
    free(data->url);
    free(data->sasl_sec_props);
    free(data);
    PyErr_BadInternalCall();
    return NULL;
}

/* Create a new LDAPConnectIter object for internal use. */
LDAPConnectIter *
LDAPConnectIter_New(LDAPConnection *conn, ldap_conndata_t *info, SOCKET sock) {
    PyObject *tmp = NULL;
    LDAPConnectIter *self =
            (LDAPConnectIter *)LDAPConnectIterType.tp_new(&LDAPConnectIterType,
                    NULL, NULL);

    if (conn != NULL && self != NULL) {
        Py_INCREF(conn);
        self->conn = conn;
        self->info = info;

        /* Check the TLS state. */
        tmp = PyObject_GetAttrString(self->conn->client, "tls");
        if (tmp == NULL) return NULL;
        self->tls = PyObject_IsTrue(tmp);
        Py_DECREF(tmp);


        self->init_thread_data = create_init_thread_data(self->conn->client, sock);
        if (self->init_thread_data == NULL) return NULL;

        if (create_init_thread(self->init_thread_data, self->info, &(self->init_thread))
                != 0) return NULL;

        self->timeout = -1;
    }

    return self;
}

/* Step the connection process into the next stage. */
PyObject *
LDAPConnectIter_Next(LDAPConnectIter *self, int timeout) {
    int rc = -1;
    PyObject *val = NULL;
    char buff[1];

    /* The connection is already binded. */
    if (self->conn->closed == 0) {
        return PyErr_Format(PyExc_StopIteration, "Connection is already open.");
    }

    DEBUG("LDAPConnectIter_Next (self:%p, timeout:%d)"
        " [tls:%d, state:%d]", self, timeout, self->tls, self->state);
    if (self->timeout == -1 && timeout >= 0) {
        self->timeout = timeout;
    }

    /* Initialise LDAP struct. */
    if (self->state == 0) {
        rc = _ldap_finish_init_thread(self->conn->async, self->init_thread, &(self->timeout),
                self->init_thread_data, &(self->conn->ld));
        if (rc == -1) return NULL; /* Error is happened. */
        if (rc == 1) {
            /* Initialisation is finished. */
            self->state = 1;
            if (self->conn->csock != -1) {
                /* Read and drop the data from the dummy socket. */
                if (recv(self->conn->csock, buff, 1, 0) == -1) return NULL;
            }
            /* Set CA cert dir, CA cert and client cert. */
            if (set_certificates(self) != 0) {
                PyErr_BadInternalCall();
                return NULL;
            }
        }
    }

    /* Start building TLS Connection, if needed. */
    if (self->state == 1) {
        if (self->tls == 1) {
            rc = ldap_start_tls(self->conn->ld, NULL, NULL, &(self->tls_id));
            if (rc == LDAP_SUCCESS) {
                self->state = 2;
            } else {
                set_exception(self->conn->ld, rc);
                return NULL;
            }
        } else {
            /* TLS connection is not needed. */
            self->state = 3;
        }
    }

    /* Finish building TLS connection. */
    if (self->state == 2) {
        rc = check_tls_result(self->conn->ld, self->tls_id, self->timeout,
            self->conn->async, self->conn->csock);
        if (rc == -1) return NULL;
        if (rc == 1) {
            self->state = 3;
        }
    }

    /* Start binding procedure. */
    if (self->state > 2) {
        val = binding(self);
        if (val == NULL) return NULL; /* It is an error. */
        if (val != Py_None) return val;
        Py_DECREF(val);
    }

    if (self->conn->async == 0) {
        /* If the function is blocking, then call next() */
        /* automatically, until an error or the LDAPConnection occurs.  */
        return LDAPConnectIter_Next(self, self->timeout);
    } else {
        Py_RETURN_NONE;
    }
}

PyTypeObject LDAPConnectIterType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "_bonsai.ldapconnectiter",       /* tp_name */
    sizeof(LDAPConnectIter),        /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)ldapconnectiter_dealloc, /* tp_dealloc */
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
    "ldapconnectiter object, implemented in C.",       /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                          /* tp_iternext */
    0,                      /* tp_methods */
    0,                         /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    0,                          /* tp_init */
    0,                         /* tp_alloc */
    ldapconnectiter_new,            /* tp_new */
};
