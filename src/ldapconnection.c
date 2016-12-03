#include "ldapconnection.h"
#include "ldapentry.h"
#include "ldapsearchiter.h"
#include "ldapconnectiter.h"

/*  Dealloc the LDAPConnection object. */
static void
ldapconnection_dealloc(LDAPConnection* self) {
    Py_XDECREF(self->client);
    Py_XDECREF(self->pending_ops);
    //Py_XDECREF(self->socketpair); // Cause invalid freeing random occasion.

    Py_TYPE(self)->tp_free((PyObject*)self);
}

/*  Create a new LDAPConnection object. */
static PyObject *
ldapconnection_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
    LDAPConnection *self = NULL;

    self = (LDAPConnection *)type->tp_alloc(type, 0);
    if (self != NULL) {
        self->client = NULL;
        self->pending_ops = NULL;
        /* The connection should be closed. */
        self->closed = 1;
        self->async = 0;
        self->ppolicy = 0;
        self->csock = -1;
        self->socketpair = NULL;
    }

    return (PyObject *)self;
}

/*  Initialise the LDAPConnection. */
static int
ldapconnection_init(LDAPConnection *self, PyObject *args, PyObject *kwds) {
    PyObject *client = NULL;
    PyObject *async = NULL;
    PyObject *ldapclient_type = NULL;
    PyObject *tmp = NULL;
    static char *kwlist[] = {"client", "async", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OO!", kwlist, &client,
            &PyBool_Type, &async)) {
        return -1;
    }

    /* Validate that the Python object parameter is type of an LDAPClient. */
    ldapclient_type = load_python_object("bonsai.ldapclient", "LDAPClient");
    if (ldapclient_type == NULL ||
        !PyObject_IsInstance(client, ldapclient_type)) {
        PyErr_SetString(PyExc_TypeError, "Type of the client parameter must be an LDAPClient.");
        return -1;
    }
    Py_DECREF(ldapclient_type);

    /* Create a dict for pending LDAP operations. */
    self->pending_ops = PyDict_New();
    if (self->pending_ops == NULL) return -1;

    /* Convert PyBool to char and set to async. */
    self->async = (char)PyObject_IsTrue(async);

    /* Set password policy option. */
    tmp = PyObject_GetAttrString(client, "password_policy");
    if (tmp == NULL) return -1;
    self->ppolicy = (char)PyObject_IsTrue(tmp);
    Py_DECREF(tmp);

    /* Set client object to LDAPConnection. */
    tmp = self->client;
    Py_INCREF(client);
    self->client = client;
    Py_XDECREF(tmp);

    return 0;
}

/* Check, that the connection is not closed.
   Set Python exception if it is.
*/
int
LDAPConnection_IsClosed(LDAPConnection *self) {
    if (self->closed) {
        /* The connection is closed. */
        PyObject *ldaperror = get_error_by_code(-101);
        PyErr_SetString(ldaperror, "The connection is closed.");
        Py_DECREF(ldaperror);
        return -1;
    }
    return 0;
}

/*  Open a connection to the LDAP server. Initialises LDAP structure.
    If TLS is true, starts TLS session.
*/
static int
connecting(LDAPConnection *self, LDAPConnectIter **conniter) {
    int rc = -1;
    char *mech = NULL;
    SOCKET ssock = -1;
    PyObject *tmp = NULL;
    PyObject *creds = NULL;
    ldap_conndata_t *info = NULL;

    /* Get mechanism and credentials. */
    creds = PyObject_GetAttrString(self->client, "credentials");
    if (creds == NULL) return -1;

    tmp = PyObject_GetAttrString(self->client, "mechanism");
    if (tmp == NULL) {
        Py_DECREF(creds);
        return -1;
    }
    mech = PyObject2char(tmp);
    Py_DECREF(tmp);

    if (self->async) {
        /* Init the socketpair. */
        rc = get_socketpair(self->client, &(self->socketpair), &(self->csock), &ssock);
        if (rc != 0) {
            free(mech);
            return -1;
        }
    }

    info = create_conn_info(mech, ssock, creds);
    Py_DECREF(creds);
    free(mech);
    if (info == NULL) return -1;

    *conniter = LDAPConnectIter_New(self, info, ssock);
    if (*conniter == NULL) return -1;

    return 0;
}

/* Open the LDAP connection. */
static PyObject *
ldapconnection_open(LDAPConnection *self) {
    int rc = 0;
    LDAPConnectIter *iter = NULL;

    rc = connecting(self, &iter);
    if (rc != 0) return NULL;

    /* Add binding operation to the pending_ops. */
    if (add_to_pending_ops(self->pending_ops, (int)(self->csock),
        (PyObject *)iter) != 0) {
        return NULL;
    }

    return PyLong_FromLong((long int)(self->csock));
}

/*  Close the LDAP connection. */
static PyObject *
ldapconnection_close(LDAPConnection *self) {
    int rc;
    int msgid;
    PyObject *keys = PyDict_Keys(self->pending_ops);
    PyObject *iter, *key, *tmp;

    if (keys == NULL) return NULL;

    if (self->closed == 1) {
        /* Connection is already close, nothing to do. */
        Py_DECREF(keys);
        Py_RETURN_NONE;
    }

    iter = PyObject_GetIter(keys);
    Py_DECREF(keys);
    if (iter == NULL) return NULL;

    for (key = PyIter_Next(iter); key != NULL; key = PyIter_Next(iter)) {
        /* Key should be an integer by design, if it is not rather not process. */
        tmp = PyLong_FromUnicodeObject(key, 10);
        if (tmp == NULL) continue;
        msgid = (int)PyLong_AsLong(tmp);
        Py_DECREF(tmp);
        /* Remove item from the dict. */
        if (PyDict_DelItem(self->pending_ops, key) != 0) {
            Py_DECREF(iter);
            Py_DECREF(key);
            PyErr_BadInternalCall();
            return NULL;
        }
        Py_DECREF(key);

        /* Skip negatives, cause assertion error. */
        if (msgid <= 0) continue;
        /* Abandon the pending operations from the server. */
        rc = ldap_abandon_ext(self->ld, msgid, NULL, NULL);
        if (rc != LDAP_SUCCESS) {
            Py_DECREF(iter);
            set_exception(self->ld, rc);
            return NULL;
        }
    }
    Py_DECREF(iter);

    rc = ldap_unbind_ext(self->ld, NULL, NULL);
    if (rc != LDAP_SUCCESS) {
        set_exception(self->ld, rc);
        return NULL;
    }
    self->closed = 1;
    Py_RETURN_NONE;
}

/* Add new LDAPEntry to the server. */
static PyObject *
ldapconnection_add(LDAPConnection *self, PyObject *args) {
    PyObject *param = NULL;
    PyObject *msgid = NULL;

    if (LDAPConnection_IsClosed(self) != 0) return NULL;

    if (!PyArg_ParseTuple(args, "O!", &LDAPEntryType, &param)) return NULL;

    /* Set this connection to the LDAPEntry, before add to the server. */
    if (LDAPEntry_SetConnection((LDAPEntry *)param, self) == 0) {
        msgid = LDAPEntry_AddOrModify((LDAPEntry *)param, 0);
        if (msgid != NULL) {
            return msgid;
        }
    }

    return NULL;
}

/* Delete an entry on the server. */
static PyObject *
ldapconnection_delentry(LDAPConnection *self, PyObject *args) {
    int rc = 0;
    char *dnstr = NULL;
    int msgid = -1;
    PyObject *recursive = NULL;
    LDAPControl *tree_ctrl = NULL;
    LDAPControl **server_ctrls = NULL;

    if (LDAPConnection_IsClosed(self) != 0) return NULL;

    if (!PyArg_ParseTuple(args, "s|O!", &dnstr, &PyBool_Type, &recursive)) {
        return NULL;
    }
    if (dnstr == NULL) return NULL;

    if (recursive != NULL && PyObject_IsTrue(recursive)) {
        /* Create an LDAP_SERVER_TREE_DELETE control . */
        server_ctrls = (LDAPControl **)malloc(sizeof(LDAPControl *) * 2);
        if (server_ctrls == NULL) return PyErr_NoMemory();

        rc = ldap_control_create(LDAP_SERVER_TREE_DELETE_OID, 0, NULL, 1, &tree_ctrl);
        if (rc != LDAP_SUCCESS) {
            free(server_ctrls);
            PyErr_BadInternalCall();
            return NULL;
        }

        server_ctrls[0] = tree_ctrl;
        server_ctrls[1] = NULL;
    }

    rc = ldap_delete_ext(self->ld, dnstr, server_ctrls, NULL, &msgid);

    /* Clear the control. */
    if (tree_ctrl != NULL) _ldap_control_free(tree_ctrl);
    free(server_ctrls);

    /* Check the return value of the delete function. */
    if (rc != LDAP_SUCCESS) {
        set_exception(self->ld, rc);
        return NULL;
    }

    /* Add new delete operation to the pending_ops. */
    if (add_to_pending_ops(self->pending_ops, msgid, Py_None) != 0) {
        return NULL;
    }

    return PyLong_FromLong((long int)msgid);
}

/* Perform an LDAP search using an LDAPSearchIter object that contains
   the parameters of the search. */
int
LDAPConnection_Searching(LDAPConnection *self, ldapsearchparams *params_in,
        PyObject *iterator) {
    int rc;
    int msgid = -1;
    int num_of_ctrls = 0;
    int extdn_format = -1;
    ldapsearchparams *params = NULL;
    LDAPControl *page_ctrl = NULL;
    LDAPControl *sort_ctrl = NULL;
    LDAPControl *vlv_ctrl = NULL;
    LDAPControl *edn_ctrl = NULL;
    LDAPControl **server_ctrls = NULL;
    LDAPSearchIter *search_iter = (LDAPSearchIter *)iterator;
    struct timeval timeout;
    struct timeval *timeout_p;
    int tout_ms = 0;
    PyObject *value = NULL;

    /* Get extended dn format attribute form LDAPClient. */
    value = PyObject_GetAttrString(self->client, "extended_dn_format");
    if (value == NULL) return -1;
    if (value == Py_None) {
        extdn_format = -1;
    }  else {
        extdn_format = PyLong_AsLong(value);
    }
    Py_DECREF(value);

    if (search_iter != NULL) {
        params = search_iter->params;
        value = (PyObject *)search_iter;
    } else {
        params = params_in;
        value = Py_None;
    }

    /* Check the number of server controls and allocate it. */
    if (extdn_format != -1) num_of_ctrls++;
    if (params->sort_list != NULL) num_of_ctrls++;
    if (search_iter != NULL && search_iter->page_size > 0) num_of_ctrls++;
    if (search_iter != NULL && search_iter->vlv_info != NULL) num_of_ctrls++;
    if (num_of_ctrls > 0) {
        server_ctrls = (LDAPControl **)malloc(sizeof(LDAPControl *)
                * (num_of_ctrls + 1));
        if (server_ctrls == NULL) {
            PyErr_NoMemory();
            return -1;
        }
        num_of_ctrls = 0;
    }

    if (server_ctrls != NULL) {
        if (search_iter != NULL && search_iter->page_size > 1) {
            /* Create page control and add to the server controls. */
            rc = ldap_create_page_control(self->ld, search_iter->page_size,
                    search_iter->cookie, 0, &page_ctrl);
            if (rc != LDAP_SUCCESS) {
                PyErr_BadInternalCall();
                msgid = -1;
                goto end;
            }
            server_ctrls[num_of_ctrls++] = page_ctrl;
            server_ctrls[num_of_ctrls] = NULL;
        }

        if (params->sort_list != NULL) {
            /* Create sort control. */
            rc = ldap_create_sort_control(self->ld, params->sort_list, 0,
                    &sort_ctrl);
            if (rc != LDAP_SUCCESS) {
                PyErr_BadInternalCall();
                msgid = -1;
                goto end;
            }
            server_ctrls[num_of_ctrls++] = sort_ctrl;
            server_ctrls[num_of_ctrls] = NULL;
        }

        if (search_iter != NULL && search_iter->vlv_info != NULL) {
            /* Create virtual list value control. */
            rc = ldap_create_vlv_control(self->ld, search_iter->vlv_info, &vlv_ctrl);
            if (rc != LDAP_SUCCESS) {
                PyErr_BadInternalCall();
                msgid = -1;
                goto end;
            }
            server_ctrls[num_of_ctrls++] = vlv_ctrl;
            server_ctrls[num_of_ctrls] = NULL;
        }

        if (extdn_format != -1) {
            /* Create extended dn control. */
            rc = _ldap_create_extended_dn_control(self->ld, extdn_format, &edn_ctrl);
            if (rc != LDAP_SUCCESS) {
                PyErr_BadInternalCall();
                msgid = -1;
                goto end;
            }
            server_ctrls[num_of_ctrls++] = edn_ctrl;
            server_ctrls[num_of_ctrls] = NULL;
        }

    }

    if (params == NULL) {
        PyErr_BadInternalCall();
        msgid= -1;
        goto end;
    }

    tout_ms = (int)(params->timeout * 1000);

    if (tout_ms > 0) {
        timeout.tv_sec = tout_ms / 1000;
        timeout.tv_usec = (tout_ms % 1000) * 1000;
        timeout_p = &timeout;
    } else {
        timeout_p = NULL;
    }

    rc = ldap_search_ext(self->ld, params->base,
            params->scope,
            params->filter,
            params->attrs,
            params->attrsonly,
            server_ctrls, NULL,
            timeout_p,
            params->sizelimit, &msgid);

    if (rc != LDAP_SUCCESS) {
        set_exception(self->ld, rc);
        msgid = -1;
        goto end;
    }

    if (add_to_pending_ops(self->pending_ops, msgid, value) != 0) {
        msgid = -1;
        goto end;
    }
end:
    /* Cleanup. */
    if (page_ctrl != NULL) ldap_control_free(page_ctrl);
    if (sort_ctrl != NULL) ldap_control_free(sort_ctrl);
    if (vlv_ctrl != NULL) ldap_control_free(vlv_ctrl);
    if (edn_ctrl != NULL) _ldap_control_free(edn_ctrl);
    free(server_ctrls);

    return msgid;
}

/* Search for LDAP entries. */
static PyObject *
ldapconnection_search(LDAPConnection *self, PyObject *args, PyObject *kwds) {
    int rc = 0;
    int scope = -1;
    int msgid = -1;
    int sizelimit = 0, attrsonly = 0;
    int page_size = 0;
    int offset = 0, after_count = 0, before_count = 0, list_count = 0;
    long int len = 0;
    double timeout = 0;
    char *basestr = NULL;
    char *filterstr = NULL;
    char **attrs = NULL;
    struct berval *attrvalue = NULL;
    PyObject *attrlist = NULL;
    PyObject *attrsonlyo = NULL;
    PyObject *sort_order = NULL;
    PyObject *attrvalue_obj = NULL;
    ldapsearchparams params;
    LDAPSortKey **sort_list = NULL;
    LDAPSearchIter *search_iter = NULL;
    static char *kwlist[] = {"base", "scope", "filter", "attrlist", "timeout",
            "sizelimit", "attrsonly", "sort_order", "page_size", "offset",
            "before_count", "after_count", "est_list_count", "attrvalue", NULL};

    if (LDAPConnection_IsClosed(self) != 0) return NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|ziz#O!diO!O!iiiiiO", kwlist,
            &basestr, &scope, &filterstr, &len, &PyList_Type, &attrlist, &timeout,
            &sizelimit, &PyBool_Type, &attrsonlyo, &PyList_Type, &sort_order,
            &page_size, &offset, &before_count, &after_count, &list_count,
            &attrvalue_obj)) {
        PyErr_SetString(PyExc_TypeError,
                "Wrong parameters (base<str|LDAPDN>, scope<int>, filter<str>,"
                " attrlist<List>, timeout<float>, attrsonly<bool>,"
                " sort_order<List>, page_size<int>, offset<int>,"
                " before_count<int>, after_count<int>, est_list_count<int>,"
                " attrvalue<object>).");
        return NULL;
    }

    /* Check that scope's value is not remained the default. */
    if (scope == -1) {
        PyErr_SetString(PyExc_ValueError, "Search scope must be set.");
        return NULL;
    }

    /* If attrvalue_obj is None, then it is not set.*/
    if (attrvalue_obj == Py_None) attrvalue_obj = NULL;

    if (sort_order != NULL && PyList_Size(sort_order) > 0) {
        /* Convert the attribute, reverse order pairs to LDAPSortKey struct. */
        sort_list = PyList2LDAPSortKeyList(sort_order);
        if (sort_list == NULL) {
            PyErr_BadInternalCall();
            return NULL;
        }
    }

    /* Convert Python objects to C types. */
    if (attrsonlyo != NULL) attrsonly = PyObject_IsTrue(attrsonlyo);
    if (attrlist != NULL) attrs = PyList2StringList(attrlist);

    if (set_search_params(&params, attrs, attrsonly, basestr,
            filterstr, len, scope, sizelimit, timeout, sort_list) != 0) {
        return NULL;
    }

    if (page_size > 0 || offset != 0 || attrvalue_obj != NULL) {
        /* Create a SearchIter for storing the search params and result. */
        search_iter = LDAPSearchIter_New(self);
        if (search_iter == NULL) return PyErr_NoMemory();

        memcpy(search_iter->params, &params, sizeof(ldapsearchparams));

        /* Create cookie for the page result. */
        search_iter->cookie = (struct berval *)malloc(sizeof(struct berval));
        if (search_iter->cookie == NULL) return PyErr_NoMemory();

        search_iter->cookie->bv_len = 0;
        search_iter->cookie->bv_val = NULL;
        search_iter->page_size = page_size;

        if (offset != 0 || attrvalue_obj != NULL) {
            search_iter->vlv_info = (LDAPVLVInfo *)malloc(sizeof(LDAPVLVInfo));
            if (search_iter->vlv_info == NULL) {
                Py_DECREF(search_iter);
                PyErr_NoMemory();
                return NULL;
            }
            search_iter->vlv_info->ldvlv_after_count = after_count;
            search_iter->vlv_info->ldvlv_before_count = before_count;
            search_iter->vlv_info->ldvlv_offset = offset;
            search_iter->vlv_info->ldvlv_context = NULL;
            search_iter->vlv_info->ldvlv_version = 1;
            search_iter->vlv_info->ldvlv_count = list_count;

            if (attrvalue_obj != NULL) {
                attrvalue = (struct berval *)malloc(sizeof(struct berval));
                if (attrvalue == NULL) {
                    Py_DECREF(search_iter);
                    PyErr_NoMemory();
                    return NULL;
                }
                rc = PyObject2char_withlength(attrvalue_obj,
                        &(attrvalue->bv_val), &len);
                if (rc != 0 || attrvalue->bv_val == NULL) {
                    PyErr_BadInternalCall();
                    free(attrvalue);
                    Py_DECREF(search_iter);
                    return NULL;
                }
                attrvalue->bv_len = len;
            }
            search_iter->vlv_info->ldvlv_attrvalue = attrvalue;
        }
    }

    msgid = LDAPConnection_Searching(self, &params, (PyObject *)search_iter);
    if (search_iter == NULL) free_search_params(&params);

    if (msgid < 0) return NULL;

    return PyLong_FromLong((long int)msgid);
}

/* Perform an LDAP Who Am I operation. */
static PyObject *
ldapconnection_whoami(LDAPConnection *self) {
    int rc = -1;
    int msgid = -1;
    PyObject *oid = NULL;

    if (LDAPConnection_IsClosed(self) != 0) return NULL;
    /* Start an LDAP Who Am I operation. */
    rc = ldap_extended_operation(self->ld, "1.3.6.1.4.1.4203.1.11.3", NULL,
            NULL, NULL, &msgid);
    if (rc != LDAP_SUCCESS) {
        set_exception(self->ld, rc);
        return NULL;
    }

    /* Add the new operation to the pending_ops with the proper OID. */
    oid = PyUnicode_FromString("1.3.6.1.4.1.4203.1.11.3");
    if (oid == NULL) return NULL;
    if (add_to_pending_ops(self->pending_ops, msgid, oid) != 0) {
        return NULL;
    }

    return PyLong_FromLong((long int)msgid);
}

static PyObject *
ldapconnection_modpasswd(LDAPConnection *self, PyObject *args, PyObject *kwds) {
    int rc = -1;
    int msgid = -1;
    int user_len = 0, newpwd_len = 0, oldpwd_len = 0;
    struct berval user, newpwd, oldpwd;
    struct berval *data = NULL;
    BerElement *ber = NULL;
    PyObject *oid = NULL;
    LDAPControl *ppolicy_ctrl = NULL;
    LDAPControl **server_ctrls = NULL;
    static char *kwlist[] = { "user", "new_password", "old_password", NULL };

    if (LDAPConnection_IsClosed(self) != 0) return NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|z#z#z#", kwlist,
            &user.bv_val, &user_len, &newpwd.bv_val, &newpwd_len,
            &oldpwd.bv_val, &oldpwd_len)) {
        return NULL;
    }

    /* Set lengths. */
    user.bv_len = user_len;
    newpwd.bv_len = newpwd_len;
    oldpwd.bv_len = oldpwd_len;

    ber = ber_alloc_t(LBER_USE_DER);
    if (ber == NULL) return PyErr_NoMemory();

    /* Create a valid BER object with the provided parameters. */
    ber_printf(ber, "{");
    if (user.bv_val != NULL && user.bv_len != 0) {
        ber_printf(ber, "to", 0x80U, user.bv_val, user.bv_len);
    }
    if (oldpwd.bv_val != NULL && oldpwd.bv_len != 0) {
        ber_printf(ber, "to", 0x81U, oldpwd.bv_val, oldpwd.bv_len);
    }
    if (newpwd.bv_val != NULL && newpwd.bv_len != 0) {
        ber_printf(ber, "to", 0x82U, newpwd.bv_val, newpwd.bv_len);
    }
    ber_printf(ber, "n}");

    /* Load the BER value into a berval. */
    rc = ber_flatten(ber, &data);
    ber_free(ber, 1);
    if (rc != 0) {
        set_exception(NULL, LDAP_ENCODING_ERROR);
        return NULL;
    }

    if (self->ppolicy == 1) {
        /* Create password policy control if it is set. */
        rc = ldap_create_passwordpolicy_control(self->ld, &ppolicy_ctrl);
        if (rc != LDAP_SUCCESS) {
            PyErr_BadInternalCall();
            return NULL;
        }

        server_ctrls = (LDAPControl **)malloc(sizeof(LDAPControl *) * (1 + 1));
        if (server_ctrls == NULL) return PyErr_NoMemory();

        server_ctrls[0] = ppolicy_ctrl;
        server_ctrls[1] = NULL;
    }

    /* Start an LDAP Password Modify operation. */
    rc = ldap_extended_operation(self->ld, "1.3.6.1.4.1.4203.1.11.1",
            data, server_ctrls, NULL, &msgid);

    /* Clear the mess. */
    ber_bvfree(data);
    if (ppolicy_ctrl != NULL) ldap_control_free(ppolicy_ctrl);
    free(server_ctrls);

    if (rc != LDAP_SUCCESS) {
        set_exception(self->ld, rc);
        return NULL;
    }

    /* Add the new operation to the pending_ops with the proper OID. */
    oid = PyUnicode_FromString("1.3.6.1.4.1.4203.1.11.1");
    if (oid == NULL) return NULL;
    if (add_to_pending_ops(self->pending_ops, msgid, oid) != 0) {
       return NULL;
    }

    return PyLong_FromLong((long int)msgid);
}

/* Process the server result after a search request. */
static PyObject *
parse_search_result(LDAPConnection *self, LDAPMessage *res, char *msgidstr){
    int rc = -1;
    int err = 0;
    int target_pos = 0, list_count = 0;
    LDAPMessage *entry;
    LDAPControl **returned_ctrls = NULL;
    LDAPEntry *entryobj = NULL;
    LDAPSearchIter *search_iter = NULL;
    PyObject *buffer = NULL;
    PyObject *value = NULL;
    PyObject *ctrl_obj = NULL;

    /* Get SearchIter from pending operations. */
    value = PyDict_GetItemString(self->pending_ops, msgidstr);
    Py_XINCREF(value);

    if (value == NULL || PyDict_DelItemString(self->pending_ops,
            msgidstr) != 0) {
        PyErr_BadInternalCall();
        return NULL;
    }

    if (value != Py_None) search_iter = (LDAPSearchIter *)value;
    buffer = PyList_New(0);
    if (buffer == NULL) {
        Py_DECREF(value);
        return PyErr_NoMemory();
    }

    /* Iterate over the received LDAP messages. */
    for (entry = ldap_first_entry(self->ld, res); entry != NULL;
        entry = ldap_next_entry(self->ld, entry)) {
        entryobj = LDAPEntry_FromLDAPMessage(entry, self);
        if (entryobj == NULL) {
            Py_DECREF(buffer);
            Py_DECREF(value);
            return NULL;
        }
        if (PyList_Append(buffer, (PyObject *)entryobj) != 0) {
            Py_DECREF(entryobj);
            Py_DECREF(buffer);
            Py_DECREF(value);
            return PyErr_NoMemory();
        }
        Py_DECREF(entryobj);
    }
    /* Check for any error during the searching. */
    rc = ldap_parse_result(self->ld, res, &err, NULL, NULL, NULL,
            &returned_ctrls, 1);

    if (rc != LDAP_SUCCESS && rc != LDAP_MORE_RESULTS_TO_RETURN) {
        set_exception(self->ld, rc);
        goto error;
    }

    if (err == LDAP_NO_SUCH_OBJECT) {
        Py_DECREF(value);
        return buffer;
    }

    if (err != LDAP_SUCCESS && err != LDAP_PARTIAL_RESULTS) {
        set_exception(self->ld, err);
        goto error;
    }

    if (search_iter != NULL) {
        rc = ldap_parse_pageresponse_control(self->ld,
                ldap_control_find(LDAP_CONTROL_PAGEDRESULTS, returned_ctrls, NULL),
                NULL, search_iter->cookie);

        if (search_iter->vlv_info != NULL) {
            rc = ldap_parse_vlvresponse_control(self->ld,
                    ldap_control_find(LDAP_CONTROL_VLVRESPONSE, returned_ctrls, NULL),
                    &target_pos, &list_count, NULL, &err);

            if (rc != LDAP_SUCCESS || err != LDAP_SUCCESS) {
                set_exception(self->ld, err);
                goto error;
            }

            /* Create ctrl dict. */
            ctrl_obj = Py_BuildValue("{s,s,s,i,s,i}",
                    "oid", LDAP_CONTROL_VLVRESPONSE,
                    "target_position", target_pos,
                    "list_count", list_count);
            if (ctrl_obj == NULL) goto error;

            /* Create (result, ctrl) tuple as return value. */
            value = Py_BuildValue("(O,O)", buffer, ctrl_obj);
            Py_DECREF(ctrl_obj);
            if (value == NULL) {
                goto error;
            }
            Py_DECREF(buffer);
            Py_DECREF(search_iter);
        } else {
            /* Return LDAPSearchIter for paged search. */
            Py_XDECREF(search_iter->buffer);
            search_iter->buffer = buffer;
            value = (PyObject *)search_iter;
            Py_INCREF(value);
        }

    } else {
        /* Return simple list for normal search. */
        value = buffer;
    }

    /* Cleanup. */
    if (returned_ctrls != NULL) ldap_controls_free(returned_ctrls);

    return value;
error:
    if (returned_ctrls != NULL) ldap_controls_free(returned_ctrls);
    Py_DECREF(buffer);
    Py_DECREF(value);
    return NULL;
}

/* Process the server response after an extended operation. */
static PyObject *
parse_extended_result(LDAPConnection *self, LDAPMessage *res, char *msgidstr) {
    int rc = -1;
    int err = 0;
    int ppres = 0;
    unsigned int pperr = 0;
    struct berval *data = NULL;
    struct berval *newpasswd = NULL;
    char *errstr = NULL, *retoid = NULL;
    PyObject *oid = NULL;
    PyObject *retval = NULL, *ldaperror = NULL, *errmsg = NULL;
    PyObject *ctrl_obj = NULL;
    LDAPControl **ctrls = NULL;
    BerElement *ber = NULL;
    ber_tag_t tag;

    /* Get oid and remove operations from pending_ops. */
    oid = PyDict_GetItemString(self->pending_ops, msgidstr);
    if (oid == NULL) return NULL;
    Py_INCREF(oid);
    if (PyDict_DelItemString(self->pending_ops, msgidstr) != 0) {
        PyErr_BadInternalCall();
        return NULL;
    }

    rc = ldap_parse_result(self->ld, res, &err, NULL, &errstr, NULL, &ctrls, 0);

    ppres = create_ppolicy_control(self->ld, ctrls, &ctrl_obj, &pperr);
    if (ppres == -1) {
        Py_DECREF(oid);
        return NULL;
    }

    if (rc != LDAP_SUCCESS || err != LDAP_SUCCESS) {
        Py_DECREF(oid);
        if (ppres == 1 && pperr != 65535) {
            set_ppolicy_err(pperr, ctrl_obj);
        } else {
            ldaperror = get_error_by_code(err);
            if (ldaperror == NULL) return NULL;
            errmsg = PyUnicode_FromFormat("%s.", errstr);
            if (errmsg != NULL) {
                PyErr_SetObject(ldaperror, errmsg);
                Py_DECREF(errmsg);
            } else PyErr_SetString(ldaperror, "");
            Py_DECREF(ldaperror);
        }

        return NULL;
    }

    rc = ldap_parse_extended_result(self->ld, res, &retoid, &data, 1);
    ldap_memfree(retoid);

    if (rc != LDAP_SUCCESS ) {
        Py_DECREF(oid);
        set_exception(self->ld, rc);
        return NULL;
    }
    /* LDAP Who Am I operation. */
    if (PyUnicode_CompareWithASCIIString(oid,
            "1.3.6.1.4.1.4203.1.11.3") == 0) {
        Py_DECREF(oid);
        if (data == NULL) return PyUnicode_FromString("anonymous");

        if(data->bv_len == 0) {
            data->bv_val = strdup("anonymous");
            data->bv_len = 9;
        }

        retval = PyUnicode_FromStringAndSize(data->bv_val, data->bv_len);
    /* LDAP Password Modify operation. */
    } else if (PyUnicode_CompareWithASCIIString(oid,
            "1.3.6.1.4.1.4203.1.11.1") == 0) {
        Py_DECREF(oid);
        if (data == NULL) Py_RETURN_NONE;

        ber = ber_init(data);
        if (ber == NULL) {
            ber_bvfree(data);
            return PyErr_NoMemory();
        }

        tag = ber_scanf(ber, "{O}", &newpasswd);
        ber_free(ber, 1);

        if (tag == LBER_ERROR) {
            set_exception(NULL, LDAP_DECODING_ERROR);
            ber_bvfree(data);
            return NULL;
        }
        retval = PyUnicode_FromStringAndSize(newpasswd->bv_val, newpasswd->bv_len);
        ber_bvfree(newpasswd);
    } else {
        Py_DECREF(oid);
    }
    ber_bvfree(data);
    return retval;
}

/* Poll and process the result of an ongoing asynchronous LDAP operation. */
PyObject *
LDAPConnection_Result(LDAPConnection *self, int msgid, int millisec) {
    int rc = -1;
    int err = 0;
    int ppres = 0;
    char msgidstr[8];
    unsigned int pperr = 0;
    LDAPMessage *res;
    LDAPControl **returned_ctrls = NULL;
    LDAPModList *mods = NULL;
    LDAPEntry *entry = NULL;
    struct timeval timeout;
    PyObject *obj = NULL;
    PyObject *newdn = NULL;
    PyObject *conniter = NULL;
    PyObject *ret = NULL;
    PyObject *ctrl_obj = NULL;

    /*- Create a char* from int message id. */
    sprintf(msgidstr, "%d", msgid);

    if (self->closed) {
        /* The function is called on a initialising and binding procedure. */
        conniter = PyDict_GetItemString(self->pending_ops, msgidstr);
        if (conniter == NULL) return NULL;
        /* Check, that we get the right object. */
        if (!PyObject_IsInstance(conniter, (PyObject *)&LDAPConnectIterType)) {
            PyErr_BadInternalCall();
            return NULL;
        }
        ret = LDAPConnectIter_Next((LDAPConnectIter *)conniter, millisec);
        if (ret == NULL) {
            /* An error is happened. */
            /* Remove operations from pending_ops. */
            if (PyDict_DelItemString(self->pending_ops, msgidstr) != 0) {
                PyErr_BadInternalCall();
                return NULL;
            }
            return NULL;
        }
        if (ret == Py_None) Py_RETURN_NONE;
        else {
            /* The init and bind are finished. */
            /* Remove operations from pending_ops. */
            if (PyDict_DelItemString(self->pending_ops, msgidstr) != 0) {
                PyErr_BadInternalCall();
                return NULL;
            }
            /* Return with the result of the connectiter. */
            return ret;
        }
    }

    if (millisec >= 0) {
        timeout.tv_sec = millisec / 1000;
        timeout.tv_usec = (millisec % 1000) * 1000;
    } else {
        timeout.tv_sec = 0L;
        timeout.tv_usec = 0L;
    }

    if (self->async == 0) {
        /* The ldap_result will block, and wait for server response or timeout. */
        Py_BEGIN_ALLOW_THREADS
        if (millisec >= 0)  {
            rc = ldap_result(self->ld, msgid, LDAP_MSG_ALL, &timeout, &res);
        } else {
            /* Wait until response or global timeout. */
            rc = ldap_result(self->ld, msgid, LDAP_MSG_ALL, NULL, &res);
        }
        Py_END_ALLOW_THREADS
    } else {
        rc = ldap_result(self->ld, msgid, LDAP_MSG_ALL, &timeout, &res);
    }

    switch (rc) {
    case -1:
        /* Error occurred during the operation. */
        /* Call set_exception with 0 param to get error code from session. */
        set_exception(self->ld, 0);
        return NULL;
    case 0:
        /* Timeout exceeded.*/
        if (self->async == 0) {
            /* Set TimeoutError. */
            set_exception(self->ld, -5);
            /* Abandon the operation on the server. */
            rc = ldap_abandon_ext(self->ld, msgid, NULL, NULL);
            if (rc != LDAP_SUCCESS) {
                set_exception(self->ld, rc);
            }
            mods = (LDAPModList *)PyDict_GetItemString(self->pending_ops, msgidstr);
            if (mods != NULL && (PyObject *)mods != Py_None && !PyUnicode_Check(mods)) {
                /* LDAP add or modify operation is failed,
                   then rollback the changes. */
                if (LDAPEntry_Rollback((LDAPEntry *)mods->entry, mods) != 0) {
                    return NULL;
                }
            }
            /* Remove operations from pending_ops. */
            if (PyDict_DelItemString(self->pending_ops, msgidstr) != 0) {
                PyErr_BadInternalCall();
            }

            return NULL;
        }
        break;
    case LDAP_RES_SEARCH_ENTRY:
        /* Received one of the entries from the server. */
        /* Only matters when ldap_result is set with LDAP_MSG_ONE. */
        break;
    case LDAP_RES_SEARCH_RESULT:
        return parse_search_result(self, res, msgidstr);
    case LDAP_RES_EXTENDED:
        obj = parse_extended_result(self, res, msgidstr);
        if (obj == NULL && PyErr_Occurred()) return NULL;
        if (obj != NULL) return obj;
        break;
    case LDAP_RES_MODRDN:
        /* Rename an LDAP entry. */
        rc = ldap_parse_result(self->ld, res, &err, NULL, NULL, NULL,
                        &returned_ctrls, 1);
        /* Get the modification list from the pending_ops. */
        obj = PyDict_GetItemString(self->pending_ops, msgidstr);
        if (obj == NULL) return NULL;
        Py_INCREF(obj);

        /* Remove operations from pending_ops. */
        if (PyDict_DelItemString(self->pending_ops, msgidstr) != 0) {
            PyErr_BadInternalCall();
            Py_DECREF(obj);
            return NULL;
        }

        if (rc != LDAP_SUCCESS || err != LDAP_SUCCESS) {
           set_exception(self->ld, err);
           Py_DECREF(obj);
           return NULL;
       }

        if (PyArg_ParseTuple(obj, "OO", &entry, &newdn)) {
            /* Validate and set new LDAP DN. */
            if (LDAPEntry_SetDN(entry, newdn) != 0) {
                Py_DECREF(obj);
                return NULL;
            }
            Py_DECREF(obj);
        } else {
            Py_DECREF(obj);
            return NULL;
        }
        Py_RETURN_TRUE;
    default:
        rc = ldap_parse_result(self->ld, res, &err, NULL, NULL, NULL,
                &returned_ctrls, 1);

        /* Get the modification list from the pending_ops. */
        mods = (LDAPModList *)PyDict_GetItemString(self->pending_ops, msgidstr);
        if (mods == NULL) return NULL;
        Py_INCREF(mods);

        /* Remove operations from pending_ops. */
        if (PyDict_DelItemString(self->pending_ops, msgidstr) != 0) {
            PyErr_BadInternalCall();
            Py_DECREF(obj);
            return NULL;
        }

        ppres = create_ppolicy_control(self->ld, returned_ctrls, &ctrl_obj, &pperr);
        if (ppres == -1) return NULL;

        if (rc != LDAP_SUCCESS || err != LDAP_SUCCESS) {
            /* LDAP add or modify operation is failed,
               then rollback the changes. */
            if (LDAPEntry_Rollback((LDAPEntry *)mods->entry, mods) != 0) {
                Py_DECREF(mods);
                return NULL;
            }
            /* Set Python error. */
            if (ppres == 1 && pperr != 65535) set_ppolicy_err(pperr, ctrl_obj);
            else set_exception(self->ld, err);

            return NULL;
        }

        Py_DECREF(mods);
        Py_RETURN_TRUE;
    }
    Py_RETURN_NONE;
}

/* Check the result of an ongoing asynchronous LDAP operation. */
static PyObject *
ldapconnection_result(LDAPConnection *self, PyObject *args, PyObject *kwds) {
    int msgid = 0;
    int timeout = -1;
    char msgidstr[8];
    PyObject *msgid_obj = NULL;
    PyObject *res = NULL;
    PyObject *timeout_obj = NULL;
    PyObject *keys = PyDict_Keys(self->pending_ops);
    PyObject *tmp = NULL;

    static char *kwlist[] = {"msgid", "timeout", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "i|O", kwlist, &msgid,
            &timeout_obj)) {
        PyErr_SetString(PyExc_TypeError, "Wrong parameter.");
        goto end;
    }

    if (timeout_obj == Py_None || timeout_obj == NULL) {
        timeout = -1;
    } else if (PyNumber_Check(timeout_obj) && !PyBool_Check(timeout_obj)) {
        tmp = PyNumber_Float(timeout_obj);
        if (tmp == NULL) goto end;

        timeout = (int)(PyFloat_AsDouble(tmp) * 1000);
        if (timeout < 0) {
            PyErr_SetString(PyExc_ValueError, "Wrong timeout parameter. "
                    "Timeout must be non-negative.");
            goto end;
        }
        Py_DECREF(tmp);
    } else {
        PyErr_SetString(PyExc_TypeError, "Wrong timeout parameter.");
        goto end;
    }

    sprintf(msgidstr, "%d", msgid);
    msgid_obj = PyUnicode_FromString(msgidstr);
    if (keys == NULL || msgid_obj == NULL) return NULL;

    if (PySequence_Contains(keys, msgid_obj) < 1)  {
        PyObject *ldaperror = get_error_by_code(-100);
        PyErr_SetString(ldaperror, "Given message ID is invalid or the"
                " associated operation is already finished.");
        Py_DECREF(ldaperror);
        res = NULL;
    } else {
        res = LDAPConnection_Result(self, msgid, timeout);
    }
end:
    Py_XDECREF(keys);
    Py_XDECREF(msgid_obj);
    return res;
}

/* Abandon an ongoing LDAP operation. */
static PyObject *
ldapconnection_abandon(LDAPConnection *self, PyObject *args) {
    int msgid = -1;
    char msgidstr[8];
    int rc = 0;

    if (!PyArg_ParseTuple(args, "i", &msgid)) {
        return NULL;
    }

    rc = ldap_abandon_ext(self->ld, msgid, NULL, NULL);
    if (rc != LDAP_SUCCESS) {
        set_exception(self->ld, rc);
        return NULL;
    }

    /* Remove message id from the pending_ops. */
    sprintf(msgidstr, "%d", msgid);
    if (PyDict_DelItemString(self->pending_ops, msgidstr) != 0) {
        PyErr_BadInternalCall();
        return NULL;
    }

    Py_RETURN_NONE;
}

/* Get the underlying socket descriptor of the LDAP connection. */
static PyObject *
ldapconnection_fileno(LDAPConnection *self) {
    int rc = 0;
    int desc = 0;

    /* For ongoing initialisation return the dummy socket descriptor,
    that will be pinged when the init thread is finished. */
    if (self->closed && self->csock != -1) {
        return PyLong_FromLong((long int)self->csock);
    }

    rc = ldap_get_option(self->ld, LDAP_OPT_DESC, &desc);
    if (rc != LDAP_SUCCESS) {
        set_exception(self->ld, rc);
        return NULL;
    }
    return PyLong_FromLong((long int)desc);
}

static PyMemberDef ldapconnection_members[] = {
    {"is_async", T_BOOL, offsetof(LDAPConnection, async), READONLY,
     "Asynchronous connection"},
    {"closed", T_BOOL, offsetof(LDAPConnection, closed), READONLY,
     "Connection is closed"},
    {NULL}  /* Sentinel */
};

static PyMethodDef ldapconnection_methods[] = {
    {"abandon", (PyCFunction)ldapconnection_abandon, METH_VARARGS,
            "Abandon ongoing operation associated with the given message id." },
    {"add", (PyCFunction)ldapconnection_add, METH_VARARGS,
            "Add new LDAPEntry to the LDAP server."},
    {"close", (PyCFunction)ldapconnection_close, METH_NOARGS,
            "Close connection with the LDAP Server."},
    {"delete", (PyCFunction)ldapconnection_delentry, METH_VARARGS,
            "Delete an LDAPEntry with the given distinguished name."},
    {"fileno", (PyCFunction)ldapconnection_fileno, METH_NOARGS,
            "Get the socket descriptor that belongs to the connection."},
    {"get_result", (PyCFunction)ldapconnection_result, METH_VARARGS | METH_KEYWORDS,
            "Poll the status of the operation associated with the given message id from LDAP server."},
    {"open", (PyCFunction)ldapconnection_open, METH_NOARGS,
            "Open connection with the LDAP Server."},
    {"modify_password", (PyCFunction)ldapconnection_modpasswd, METH_VARARGS | METH_KEYWORDS,
            "Modify password for the user."},
    {"search", (PyCFunction)ldapconnection_search, METH_VARARGS | METH_KEYWORDS,
            "Search for LDAP entries."},
    {"whoami", (PyCFunction)ldapconnection_whoami, METH_NOARGS,
            "LDAPv3 Who Am I operation."},
    {NULL, NULL, 0, NULL}  /* Sentinel */
};

PyTypeObject LDAPConnectionType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "_bonsai.ldapconnection",       /* tp_name */
    sizeof(LDAPConnection),        /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)ldapconnection_dealloc, /* tp_dealloc */
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
    "ldapconnection object, implemented in C.",   /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    ldapconnection_methods,    /* tp_methods */
    ldapconnection_members,    /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)ldapconnection_init, /* tp_init */
    0,                         /* tp_alloc */
    ldapconnection_new,            /* tp_new */
};
