#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__)

#include <stdio.h>

#include "wldap-utf8.h"

/* Get size of a list by reaching the terminating NULL. */
static int
get_size(void **list) {
    int size = 0;

    if (list == NULL) return 0;

    while (list[size] != NULL) size++;

    return size;
}

/* Copy the items of a list into a new list using the `copyfunc` function. */
static int
copy_list(void **list, void **newlist, int(*copyfunc)(void *, void**)) {
    int i = 0;
    int rc = 0;

    if (list == NULL || newlist == NULL) return LDAP_PARAM_ERROR;

    for (i = 0; list[i] != NULL; i++) {
        rc = (copyfunc)(list[i], &newlist[i]);
        if (rc != LDAP_SUCCESS) {
            /* Copy is failed, break the cycle and set the failed
            item to NULL thus the successfully converted items
            can be freed without overrunning the list. */
            break;
        }
    }
    newlist[i] = NULL;
    return rc;
}

/* Free the list element using the `freefunc` function.  */
static void
free_list(void **list, void freefunc(void*)) {
    int i = 0;

    if (list != NULL) {
        for (i = 0; list[i] != NULL; i++) {
            (freefunc)(list[i]);
        }
        free(list);
    }
}


/* Convert a wide character string into a UTF-8 (narrow) string. */
static int
convert_to_mbs(wchar_t *tmp, char **str) {
    int size = 0;
    int rc = 0;

    if (tmp == NULL) return LDAP_SUCCESS;

    /* Get necessary size for the new UTF-8 encoded char*. */
    size = WideCharToMultiByte(CP_UTF8, 0, tmp, -1, NULL, 0, NULL, NULL);
    *str = (char *)malloc(sizeof(char) * size);
    if (*str == NULL) return LDAP_NO_MEMORY;

    rc = WideCharToMultiByte(CP_UTF8, 0, tmp, -1, *str, size, NULL, NULL);
    if (rc == 0) {
        free(*str);
        *str = NULL;
        return LDAP_ENCODING_ERROR;
    }

    return LDAP_SUCCESS;
}

/* Convert an narrow character string into a UTF-16 (wide) string. */
static int
convert_to_wcs(char *tmp, wchar_t **str) {
    int size = 0;
    int rc = 0;

    if (tmp == NULL) return LDAP_SUCCESS;

    /* Get necessary size for the new wchar_t*. */
    size = MultiByteToWideChar(CP_UTF8, 0, tmp, -1, NULL, 0);
    *str = (wchar_t *)malloc(sizeof(wchar_t) * size);
    if (*str == NULL) return LDAP_NO_MEMORY;

    rc = MultiByteToWideChar(CP_UTF8, 0, tmp, -1, *str, size);
    if (rc == 0) {
        free(*str);
        *str = NULL;
        return LDAP_DECODING_ERROR;
    }

    return LDAP_SUCCESS;
}


/* Convert a list of narrow character strings into a list of UTF-16 (wide)
   strings. */
static int
convert_char_list(char **list, wchar_t ***wlist) {
    int size = 0;
    int rc = 0;

    if (list == NULL) return LDAP_SUCCESS;

    size = get_size(list);

    *wlist = (wchar_t **)malloc(sizeof(wchar_t*) * (size + 1));
    if (*wlist == NULL) return LDAP_NO_MEMORY;

    rc = copy_list(list, *wlist, ((int(*)(void*, void**))convert_to_wcs));

    if (rc != LDAP_SUCCESS) {
        /* At least one of the item's conversion is failed,
        thus the list is not converted properly. */
        free_list(*wlist, &free);
    }

    return rc;
}

/* Convert a list of UTf-16 (wide) character strings into a list of narrow
strings. */
static int
convert_wchar_list(wchar_t **wlist, char ***list) {
    int size = 0;
    int rc = 0;

    if (wlist == NULL) return LDAP_SUCCESS;

    size = get_size(wlist);

    *list = (char **)malloc(sizeof(char *) * (size + 1));
    if (*list == NULL) return LDAP_NO_MEMORY;

    rc = copy_list(wlist, *list, ((int(*)(void*, void**))convert_to_mbs));

    if (rc != LDAP_SUCCESS) {
        /* At least one of the item's conversion is failed,
        thus the list is not converted properly. */
        free_list(*list, &free);
    }

    return rc;
}

/* Convert an "ANSI" LDAPControl struct into an UTF-16 wide LDAPControl. */
static int
convert_ctrl(LDAPControlA *ctrl, LDAPControlW **wctrl) {
    int rc = 0;
    wchar_t *woid = NULL;

    if (ctrl == NULL) return LDAP_SUCCESS;

    *wctrl = (LDAPControlW *)malloc(sizeof(LDAPControlW));
    if (*wctrl == NULL) return LDAP_NO_MEMORY;

    (*wctrl)->ldctl_iscritical = ctrl->ldctl_iscritical;
    (*wctrl)->ldctl_value = ctrl->ldctl_value;

    if (rc = convert_to_wcs(ctrl->ldctl_oid, &woid) != LDAP_SUCCESS) {
        free(*wctrl);
        return rc;
    }

    (*wctrl)->ldctl_oid = woid;

    return LDAP_SUCCESS;
}

/* Free a converted wide LDAPControl. */
static void 
free_ctrl(LDAPControlW *ctrl) {
    if (ctrl != NULL) {
        free(ctrl->ldctl_oid);
        free(ctrl);
    }
}

/* Convert a list of "ANSI" LDAPControl struct into a list of UTF-16
   wide LDAPControl. */
static int
convert_ctrl_list(LDAPControlA **ctrls, LDAPControlW ***wctrls) {
    int size = 0;
    int rc = 0;

    if (ctrls == NULL) return LDAP_SUCCESS;

    size = get_size(ctrls);
    *wctrls = (LDAPControlW **)malloc(sizeof(LDAPControlW*) * (size + 1));
    if (*wctrls == NULL) return LDAP_NO_MEMORY;

    rc = copy_list(ctrls, *wctrls, ((int(*)(void*, void**))convert_ctrl));

    if (rc != LDAP_SUCCESS) {
        /* At least one of the item's conversion is failed,
        thus the list is not converted properly. */
        free_list(*wctrls, &free_ctrl);
    }

    return rc;
}

/* Convert an "ANSI" LDAPMod struct into an UTF-16 wide LDAPMod. */
static int
convert_mod(LDAPModA *mod, LDAPModW **wmod) {
    int rc = 0;

    if (mod == NULL) return LDAP_SUCCESS;

    *wmod = (LDAPModW *)malloc(sizeof(LDAPModW));
    if (*wmod == NULL) return LDAP_NO_MEMORY;

    (*wmod)->mod_op = mod->mod_op;

    if (((*wmod)->mod_op & LDAP_MOD_BVALUES) == LDAP_MOD_BVALUES) {
        (*wmod)->mod_vals.modv_bvals = mod->mod_vals.modv_bvals;
    } else {
        rc = convert_char_list(mod->mod_vals.modv_strvals, &((*wmod)->mod_vals.modv_strvals));
        if (rc != LDAP_SUCCESS) {
            free(*wmod);
            return rc;
        }
    }

    rc = convert_to_wcs(mod->mod_type, &((*wmod)->mod_type));
    if (rc != LDAP_SUCCESS) {
        if ((mod->mod_op & LDAP_MOD_BVALUES) != LDAP_MOD_BVALUES) {
            free_list((*wmod)->mod_vals.modv_strvals, &free);
        }
        free(*wmod);
    }

    return rc;
}

/* Free a converted wide LDAPMod. */
static void
free_mod(LDAPModW *mod) {
    if (mod != NULL) {
        free(mod->mod_type);
        if ((mod->mod_op & LDAP_MOD_BVALUES) != LDAP_MOD_BVALUES) {
            if (mod->mod_vals.modv_strvals) free_list(mod->mod_vals.modv_strvals, &free);
        }
        free(mod);
    }
}

/* Convert a list of "ANSI" LDAPMod struct into a list of UTF-16
   wide LDAPMod. */
static int
convert_mod_list(LDAPModA **mods, LDAPModW ***wmods) {
    int rc = 0;
    int size = 0;

    if (mods == NULL) return LDAP_SUCCESS;

    size = get_size(mods);
    *wmods = (LDAPModW **)malloc(sizeof(LDAPModW *) * (size + 1));
    if (*wmods == NULL) return LDAP_NO_MEMORY;

    rc = copy_list(mods, *wmods, (void *)&convert_mod);

    if (rc != LDAP_SUCCESS) {
        /* At least one of the item's conversion is failed,
        thus the list is not converted properly. */
        free_list(*wmods, &free_mod);
    }

    return rc;
}

/******************************************************************************
* All of the following functions behave just like they documented in the WinLDAP
* or OpenLDAP documentations (except where the comment says otherwise), but they
* can return with encoding or decoding error code, if the conversation is failed.
******************************************************************************/

int
ldap_unbind_ext(LDAP *ld, LDAPControlA **sctrls, LDAPControlA **cctrls) {
    return ldap_unbind(ld);
}

int
ldap_abandon_ext(LDAP *ld, int msgid, LDAPControlA **sctrls, LDAPControlA **cctrls) {
    return ldap_abandon(ld, msgid);
}

char *
ldap_get_dnU(LDAP *ld, LDAPMessage *entry) {
    char *dn = NULL;
    wchar_t *wdn = NULL;

    wdn = ldap_get_dnW(ld, entry);

    convert_to_mbs(wdn, &dn);

    ldap_memfreeW(wdn);

    return dn;
}

int
ldap_add_extU(LDAP *ld, char *dn, LDAPModA **attrs, LDAPControlA **sctrls, LDAPControlA **cctrls,
        int *msgidp) {
    
    int rc = 0;
    wchar_t *wdn = NULL;
    LDAPModW **wattrs = NULL;
    LDAPControlW **wsctrls = NULL;
    LDAPControlW **wcctrls = NULL;

    if (rc = convert_to_wcs(dn, &wdn) != LDAP_SUCCESS) goto end;
    if (rc = convert_ctrl_list(sctrls, &wsctrls) != LDAP_SUCCESS) goto end;
    if (rc = convert_ctrl_list(cctrls, &wcctrls) != LDAP_SUCCESS) goto end;
    if (rc = convert_mod_list(attrs, &wattrs) != LDAP_SUCCESS) goto end;

    rc = ldap_add_extW(ld, wdn, wattrs, wsctrls, wcctrls, msgidp);

end:
    free(wdn);
    free_list((void **)wsctrls, (void *)free_ctrl);
    free_list((void **)wcctrls, (void *)free_ctrl);
    free_list((void **)wattrs, (void *)free_mod);

    return rc;
}

int
ldap_modify_extU(LDAP *ld, char *dn, LDAPModA **attrs, LDAPControlA **sctrls, LDAPControlA **cctrls,
        int *msgidp) {
    
    int rc = 0;
    wchar_t *wdn = NULL;
    LDAPModW **wattrs = NULL;
    LDAPControlW **wsctrls = NULL;
    LDAPControlW **wcctrls = NULL;

    if (rc = convert_to_wcs(dn, &wdn) != LDAP_SUCCESS) goto end;
    if (rc = convert_ctrl_list(sctrls, &wsctrls) != LDAP_SUCCESS) goto end;
    if (rc = convert_ctrl_list(cctrls, &wcctrls) != LDAP_SUCCESS) goto end;
    if (rc = convert_mod_list(attrs, &wattrs) != LDAP_SUCCESS) goto end;

    rc = ldap_modify_extW(ld, wdn, wattrs, wsctrls, wcctrls, msgidp);

end:
    free(wdn);
    free_list((void **)wsctrls, (void *)free_ctrl);
    free_list((void **)wcctrls, (void *)free_ctrl);
    free_list((void **)wattrs, (void *)free_mod);

    return rc;
}

int
ldap_delete_extU(LDAP *ld, char *dn, LDAPControlA **sctrls, LDAPControlA **cctrls, int *msgidp) {
    int rc = 0;
    wchar_t *wdn = NULL;
    LDAPControlW **wsctrls = NULL;
    LDAPControlW **wcctrls = NULL;

    if (rc = convert_to_wcs(dn, &wdn) != LDAP_SUCCESS) goto end;
    if (rc = convert_ctrl_list(sctrls, &wsctrls) != LDAP_SUCCESS) goto end;
    if (rc = convert_ctrl_list(cctrls, &wcctrls) != LDAP_SUCCESS) goto end;

    rc = ldap_delete_extW(ld, wdn, wsctrls, wcctrls, msgidp);

end:
    free(wdn);
    free_list((void **)wsctrls, (void *)free_ctrl);
    free_list((void **)wcctrls, (void *)free_ctrl);

    return rc;
}

char *
ldap_first_attributeU(LDAP *ld, LDAPMessage *entry, BerElement **ber) {
    char *attr = NULL;
    wchar_t *wattr = NULL;

    wattr = ldap_first_attributeW(ld, entry, ber);

    convert_to_mbs(wattr, &attr);

    ldap_memfreeW(wattr);

    return attr;
}

char *
ldap_next_attributeU(LDAP *ld, LDAPMessage *entry, BerElement *ber) {
    char *attr = NULL;
    wchar_t *wattr = NULL;

    wattr = ldap_next_attributeW(ld, entry, ber);

    convert_to_mbs(wattr, &attr);

    ldap_memfreeW(wattr);

    return attr;
}

struct berval **
ldap_get_values_lenU(LDAP *ld, LDAPMessage *entry, char *target) {
    struct berval **ret = NULL;
    wchar_t *wtarget = NULL;

    convert_to_wcs(target, &wtarget);

    ret = ldap_get_values_lenW(ld, entry, wtarget);

    free(wtarget);

    return ret;
}

int
ldap_renameU(LDAP *ld, char *dn, char *newrdn, char *newSuperior, int deleteoldrdn,
        LDAPControlA **sctrls, LDAPControlA **cctrls, int *msgidp) {
    
    int rc = 0;
    wchar_t *wdn = NULL; 
    wchar_t *wnewrdn = NULL;
    wchar_t *wnewSuperior = NULL;
    LDAPControlW **wsctrls = NULL;
    LDAPControlW **wcctrls = NULL;
    
    if (rc = convert_to_wcs(dn, &wdn) != LDAP_SUCCESS) goto end;
    if (rc = convert_to_wcs(newrdn, &wnewrdn) != LDAP_SUCCESS) goto end;
    if (rc = convert_to_wcs(newSuperior, &wnewSuperior) != LDAP_SUCCESS) goto end;
    if (rc = convert_ctrl_list(sctrls, &wsctrls) != LDAP_SUCCESS) goto end;
    if (rc = convert_ctrl_list(cctrls, &wcctrls) != LDAP_SUCCESS) goto end;

    rc = ldap_rename_extW(ld, wdn, wnewrdn, wnewSuperior, deleteoldrdn, wsctrls, wcctrls, msgidp);

end:
    free(wdn);
    free(wnewrdn);
    free(wnewSuperior);
    free_list((void **)wsctrls, (void *)free_ctrl);
    free_list((void **)wcctrls, (void *)free_ctrl);

    return rc;
}

int
ldap_search_extU(LDAP *ld, char *base, int scope, char *filter, char **attrs, int attrsonly,
        LDAPControlA **sctrls, LDAPControlA **cctrls, struct timeval *timeout, int sizelimit, int *msgidp) {
    
    int rc = 0;
    wchar_t *wbase = NULL;
    wchar_t *wfilter = NULL;
    wchar_t **wattrs = NULL;
    LDAPControlW **wsctrls = NULL;
    LDAPControlW **wcctrls = NULL;
    unsigned long timelimit = 0;

    if (timeout != NULL) {
        timelimit = (unsigned long)timeout->tv_sec;
    } else {
        timelimit = 0;
    }

    if (rc = convert_to_wcs(base, &wbase) != LDAP_SUCCESS) goto end;
    if (rc = convert_to_wcs(filter, &wfilter) != LDAP_SUCCESS) goto end;
    if (rc = convert_char_list(attrs, &wattrs) != LDAP_SUCCESS) goto end;
    if (rc = convert_ctrl_list(sctrls, &wsctrls) != LDAP_SUCCESS) goto end;
    if (rc = convert_ctrl_list(cctrls, &wcctrls) != LDAP_SUCCESS) goto end;

    rc = ldap_search_extW(ld, wbase, scope, wfilter, wattrs, attrsonly, wsctrls, wcctrls, timelimit,
            sizelimit, msgidp);

end:
    free(wbase);
    free(wfilter);
    free_list((void **)wattrs, (void *)free);
    free_list((void **)wsctrls, (void *)free_ctrl);
    free_list((void **)wcctrls, (void *)free_ctrl);

    return rc;
}

int
ldap_extended_operationU(LDAP *ld, char *reqoid, struct berval *reqdata, LDAPControlA **sctrls,
        LDAPControlA **cctrls, int *msgidp) {
    
    int rc = 0;
    wchar_t *woid = NULL;
    LDAPControlW **wsctrls = NULL;
    LDAPControlW **wcctrls = NULL;

    if (rc = convert_to_wcs(reqoid, &woid) != LDAP_SUCCESS) goto end;
    if (rc = convert_ctrl_list(sctrls, &wsctrls) != LDAP_SUCCESS) goto end;
    if (rc = convert_ctrl_list(cctrls, &wcctrls) != LDAP_SUCCESS) goto end;

    rc = ldap_extended_operationW(ld, woid, reqdata, wsctrls, wcctrls, msgidp);

end:
    free(woid);
    free_list((void **)wsctrls, (void *)free_ctrl);
    free_list((void **)wcctrls, (void *)free_ctrl);

    return rc;
}

int
ldap_parse_extended_resultU(LDAP *ld, LDAPMessage *res, char **retoidp, struct berval **retdatap,
        int freeit) {
    
    int rc = 0;
    char *oid = NULL;
    wchar_t *wretoid = NULL;

    rc = ldap_parse_extended_resultW(ld, res, &wretoid, retdatap, freeit);
    if (rc != LDAP_SUCCESS) return rc;
    if (rc = convert_to_mbs(wretoid, &oid) != LDAP_SUCCESS) return rc;

    if (wretoid) ldap_memfreeW(wretoid);

    *retoidp = oid;

    return rc;
}

/* This function receive a list of LDAPControl instead of one LDAPControl, 
   because the corresponding WinLDAP function will search the page control
   object internally. */
int
ldap_parse_pageresponse_controlU(LDAP *ld, LDAPControlA **ctrls, ber_int_t *count,
        struct berval **cookie) {

    int rc = 0;
    LDAPControlW **wctrls = NULL;

    if (rc = convert_ctrl_list(ctrls, &wctrls) != LDAP_SUCCESS) goto end;

    if (*cookie != NULL && (*cookie)->bv_val != NULL) {
        ber_bvfree(*cookie);
    }

    rc = ldap_parse_page_controlW(ld, wctrls, (unsigned long *)count, cookie);
end:
    free_list((void **)wctrls, (void *)free_ctrl);

    return rc;
}

/* Create an LDAPControl struct. If `dupval` is non-zero, the berval struct `value`
   is copied. */
int ldap_control_createU(char *requestOID, int iscritical, struct berval *value,
    int dupval, LDAPControlA **ctrlp) {
    LDAPControlA *tmpControl = NULL;

    tmpControl = (LDAPControlA *)malloc(sizeof(LDAPControlA));
    if (tmpControl == NULL) return LDAP_NO_MEMORY;

    tmpControl->ldctl_oid = requestOID;
    tmpControl->ldctl_iscritical = iscritical;

    if (dupval) {
        if (value == NULL) {
            tmpControl->ldctl_value.bv_val = NULL;
            tmpControl->ldctl_value.bv_len = 0;
        } else {
            tmpControl->ldctl_value.bv_val = (char *)malloc(sizeof(char) * value->bv_len);
            if (tmpControl->ldctl_value.bv_val == NULL) {
                free(tmpControl);
                return LDAP_NO_MEMORY;
            }

            memcpy(tmpControl->ldctl_value.bv_val, value->bv_val, value->bv_len);
            tmpControl->ldctl_value.bv_len = value->bv_len;
        }
    } else {
        tmpControl->ldctl_value = *value;
    }

    *ctrlp = tmpControl;
    return LDAP_SUCCESS;
}

/* This function is a dummy function for keeping compatibility with OpenLDAP. */
LDAPControlA **
ldap_control_findU(char *oid, LDAPControlA **ctrls, LDAPControlA ***nextctrlp) {
    return ctrls;
}

int
ldap_parse_resultU(LDAP *ld, LDAPMessage *res, int *errcodep, char **matcheddnp, char **errmsgp,
        char ***referralsp, LDAPControlA ***sctrls, int freeit) {
    
    int i = 0;
    int rc = 0;
    int size = 0;
    char *err = NULL;
    char **refs = NULL;
    wchar_t *wmatcheddnp = NULL;
    wchar_t *werrmsgp = NULL;
    wchar_t **wreferralsp = NULL;
    LDAPControlW **wsctrls = NULL;
    LDAPControlA **ctrls = NULL;
    LDAPControlA *ctrla = NULL;

    rc = ldap_parse_resultW(ld, res, errcodep, &wmatcheddnp, &werrmsgp, &wreferralsp, &wsctrls, freeit);
    if (rc != LDAP_SUCCESS) return rc;

    /* Convert and assign parameters just if they are required. */
    if (matcheddnp != NULL) rc = convert_to_mbs(wmatcheddnp, matcheddnp);
    if (errmsgp != NULL) rc = convert_to_mbs(werrmsgp, errmsgp);

    if (wreferralsp != NULL && referralsp != NULL) {
        /* Copy and convert the referral strings, if it's required. */
        size = get_size(wreferralsp);
        refs = (char **)malloc(sizeof(char*) * (size + 1));
        if (refs == NULL) {
            rc = LDAP_NO_MEMORY;
            goto end;
        }
        for (i = 0; wreferralsp[i] != NULL; i++) {
            convert_to_mbs(wreferralsp[i], &refs[i]);
        }
        refs[i] = NULL;
        *referralsp = refs;
    }

    if (wsctrls != NULL && sctrls != NULL) {
        /* Copy and convert the server controls, if it's required. */
        size = get_size(wsctrls);
        ctrls = (LDAPControlA **)malloc(sizeof(LDAPControlA*) * (size + 1));
        if (ctrls == NULL) {
            rc = LDAP_NO_MEMORY;
            goto end;
        }

        for (i = 0; wsctrls[i] != NULL; i++) {
            ctrla = (LDAPControlA *)malloc(sizeof(LDAPControlA));
            if (ctrla == NULL) return LDAP_NO_MEMORY;

            ctrla->ldctl_iscritical = wsctrls[i]->ldctl_iscritical;
            rc = convert_to_mbs(wsctrls[i]->ldctl_oid, &(ctrla->ldctl_oid));
            if (rc != LDAP_SUCCESS) goto end;
            ctrla->ldctl_value.bv_val = (char *)malloc(wsctrls[i]->ldctl_value.bv_len);
            if (ctrla->ldctl_value.bv_val == NULL) {
                rc = LDAP_NO_MEMORY;
                goto end;
            }
            memcpy(ctrla->ldctl_value.bv_val, wsctrls[i]->ldctl_value.bv_val, wsctrls[i]->ldctl_value.bv_len);
            ctrla->ldctl_value.bv_len = wsctrls[i]->ldctl_value.bv_len;
            ctrls[i] = ctrla;
        }
        ctrls[i] = NULL;

        *sctrls = ctrls;
    }

end:
    ldap_memfreeW(wmatcheddnp);
    ldap_memfreeW(werrmsgp);
    ldap_value_freeW(wreferralsp);
    ldap_controls_freeW(wsctrls);

    return rc;
}

char *
ldap_err2stringU(int err) {
    char *errmsg = NULL;
    wchar_t *werr = NULL;

    /* Mustn't free the returning string. */
    werr = ldap_err2stringW(err);

    convert_to_mbs(werr, &errmsg);
    return errmsg;
}

int
ldap_initializeU(LDAP **ldp, char *url) {
    int rc = 0;
    int err = 0;
    int chunk_num = 0;
    int port = 389;
    int ssl = 0;
    int size = 0;
    char *host = NULL;
    wchar_t *whost = NULL;
    char *chunk = NULL;
    const char *token;
    char *nxtoken = NULL;

    /* Check for IPv6 address. */
    if (strchr(url, '[') != NULL) token = "[]";
    else token = ":/";

    /* Parse string address. */
    chunk = strtok_s(url, token, &nxtoken);
    while (chunk != NULL) {
        switch (chunk_num) {
        case 0:
            /* Check scheme. */
            if (strstr(chunk, "ldaps") != NULL) {
                ssl = 1;
            } else {
                ssl = 0;
            }
            chunk_num++;
            break;
        case 1:
            /* Copy hostname. */
            size = (int)strlen(chunk) + 1;
            host = (char *)malloc(sizeof(char) * size);
            if (host == NULL) return LDAP_NO_MEMORY;
            strcpy_s(host, size, chunk);
            chunk_num++;
            break;
        case 2:
            /* Convert the port. */
            if (strcmp(token, "[]") == 0) {
                /* If it's an IPv6 address the ':' needs to be cut. */
                chunk += 1;
            } 
            port = (int)strtol(chunk, NULL, 10);
            if (port <= 0) {
                if (host) free(host);
                return LDAP_PARAM_ERROR;
            }
            /* Shortcut: no useful data left. */
            goto init;
        default:
            break;
        }
        chunk = strtok_s(NULL, token, &nxtoken);
    }
init:
    if (rc = convert_to_wcs(host, &whost) != LDAP_SUCCESS) return rc;

    *ldp = ldap_sslinitW(whost, port, ssl);

    free(host);
    free(whost);

    if (*ldp == NULL) {
        err = LdapGetLastError();
        if (err != 0) return err;
        else return LDAP_LOCAL_ERROR;
    }

    return ldap_connect(*ldp, NULL);
}

int
ldap_start_tls_sU(LDAP *ld, LDAPControlA **sctrls, LDAPControlA **cctrls) {
    int rc = 0;
    LDAPControlW **wsctrls = NULL;
    LDAPControlW **wcctrls = NULL;

    if (rc = convert_ctrl_list(sctrls, &wsctrls) != LDAP_SUCCESS) goto end;
    if (rc = convert_ctrl_list(cctrls, &wcctrls) != LDAP_SUCCESS) goto end;

    rc = ldap_start_tls_sW(ld, NULL, NULL, wsctrls, wcctrls);

end:
    free_list((void **)wsctrls, (void *)free_ctrl);
    free_list((void **)wcctrls, (void *)free_ctrl);

    return rc;
}

int
ldap_simple_bind_sU(LDAP *ld, char *who, char *passwd) {
    int rc = 0;
    wchar_t *wwho = NULL;
    wchar_t *wpsw = NULL;

    if (rc = convert_to_wcs(who, &wwho) != LDAP_SUCCESS) goto end;
    if (rc = convert_to_wcs(passwd, &wpsw) != LDAP_SUCCESS) goto end;

    rc = ldap_simple_bind_sW(ld, wwho, wpsw);

end:
    free(wwho);
    free(wpsw);

    return rc;
}

/* The manually created LDAPControls (like the ones in the ldap_parse_resultU)
   can not be freed with original ldap_controls_freeA without causing heap
   corruption. */
void
ldap_controls_freeU(LDAPControlA **ctrls) {
    int i = 0;

    if (ctrls != NULL) {
        for (i = 0; ctrls[i] != NULL; i++) {
            if (ctrls[i]->ldctl_oid) free(ctrls[i]->ldctl_oid);
            if (ctrls[i]->ldctl_value.bv_val != NULL) {
                free(ctrls[i]->ldctl_value.bv_val);
            }
            free(ctrls[i]);
        }
    }
}

/* Extended ldap_get_option function with TLS package name and API info
support. */
int
ldap_get_optionU(LDAP *ld, int option, void *outvalue) {
    if (option == LDAP_OPT_X_TLS_PACKAGE) {
        *(char **)outvalue = strdup("SChannel");
        return LDAP_SUCCESS;
    }
    if (option == LDAP_OPT_API_INFO) {
        /* By default ldap_get_option returns with protocol error,
        simpler to fill out the struct manually. */
        LDAPAPIInfo *info = (LDAPAPIInfo *)outvalue;
        if (info == NULL) return LDAP_OTHER;

        info->ldapai_vendor_name = LDAP_VENDOR_NAME;
        info->ldapai_vendor_version = LDAP_VENDOR_VERSION;
        info->ldapai_api_version = LDAP_API_VERSION;
        info->ldapai_protocol_version = LDAP_VERSION3;
        info->ldapai_extensions = NULL;

        return LDAP_SUCCESS;
    }

    return ldap_get_optionW(ld, option, outvalue);
}

int
ldap_parse_sortresponse_controlU(LDAP *ld, LDAPControlA **ctrls, ber_int_t *result,
        char **attribute) {

    int rc = 0;
    wchar_t *wattr = NULL;
    LDAPControlW **wctrls = NULL;

    if (rc = convert_ctrl_list(ctrls, &wctrls) != LDAP_SUCCESS) goto end;

    rc = ldap_parse_sort_controlW(ld, wctrls, result, &wattr);
    convert_to_mbs(wattr, attribute);
    if (rc == LDAP_CONTROL_NOT_FOUND) {
        rc = LDAP_SUCCESS;
    } 
end:
    free_list((void **)wctrls, (void *)free_ctrl);
    ldap_memfreeW(wattr);
    return rc;
}

int
ldap_create_vlv_controlU(LDAP *ld, LDAPVLVInfo *vlvinfo, LDAPControlA **ctrl) {
    return ldap_create_vlv_controlA(ld, vlvinfo, FALSE, ctrl);
}

int
ldap_parse_vlvresponse_controlU(LDAP *ld, LDAPControlA **ctrls, long int *target_posp,
    long int *list_countp, struct berval **contextp, int *errcodep) {
    int rc = 0;
    LDAPControlW **wctrls = NULL;

    rc = convert_ctrl_list(ctrls, &wctrls);
    if (rc != LDAP_SUCCESS) goto end;

    rc = ldap_parse_vlv_controlW(ld, wctrls, target_posp, list_countp, contextp, errcodep);

end:
    free_list((void **)wctrls, (void *)free_ctrl);
    return rc;
}

int
ldap_parse_referenceU(LDAP *ld, LDAPMessage *reference, char ***referralsp,
    LDAPControlA ***serverctrlsp, int freeit) {
    int rc = 0;
    LDAPControlW **wctrls = NULL;
    wchar_t **wreferrals = NULL;

    rc = ldap_parse_referenceW(ld, reference, &wreferrals);
    if (rc != LDAP_SUCCESS) goto end;
    rc = convert_wchar_list(wreferrals, referralsp);
    if (freeit) ldap_msgfree(reference);

end:
    ldap_value_freeW(wreferrals);
    return rc;

}

/******************************************************************************
 Dummy functions for password policy control.
 WinLDAP fails with protocol error when the empty password policy control is
 attached to an LDAP operation.
*******************************************************************************/
int
ldap_create_passwordpolicy_controlU(LDAP *ld, LDAPControlA **ctrlp) {
    return LDAP_SUCCESS;
}

int
ldap_parse_passwordpolicy_controlU(LDAP *ld, LDAPControlA **ctrls, ber_int_t *expirep,
    ber_int_t *gracep, unsigned int *errorp) {
    return LDAP_CONTROL_NOT_FOUND;
}

/******************************************************************************
* The following functions are for SASL binding, using SSPI.
******************************************************************************/


/* Decrypt the message of a GSSAPI (Kerberos) response from the server. */
static int
decrypt_response(CtxtHandle *handle, char *inToken, int inLen, char **outToken, int *outLen) {
    SecBufferDesc buff_desc;
    SecBuffer bufs[2];
    unsigned long qop = 0;
    int res;

    buff_desc.ulVersion = SECBUFFER_VERSION;
    buff_desc.cBuffers = 2;
    buff_desc.pBuffers = bufs;

    /* This buffer is for SSPI. */
    bufs[0].BufferType = SECBUFFER_STREAM;
    bufs[0].pvBuffer = inToken;
    bufs[0].cbBuffer = inLen;

    /* This buffer holds the application data. */
    bufs[1].BufferType = SECBUFFER_DATA;
    bufs[1].cbBuffer = 0;
    bufs[1].pvBuffer = NULL;

    res = DecryptMessage(handle, &buff_desc, 0, &qop);

    if (res == SEC_E_OK) {
        int maxlen = bufs[1].cbBuffer;
        char *p = (char *)malloc(maxlen);
        *outToken = p;
        *outLen = maxlen;
        memcpy(p, bufs[1].pvBuffer, bufs[1].cbBuffer);
    }

    return res;
}

/* Encrypt the message of a GSSAPI (Kerberos) reply to the server. */
static int
encrypt_reply(CtxtHandle *handle, char *inToken, int inLen, char **outToken, int *outLen) {
    SecBufferDesc buff_desc;
    SecBuffer bufs[3];
    SecPkgContext_Sizes sizes;
    int res;

    res = QueryContextAttributesW(handle, SECPKG_ATTR_SIZES, &sizes);

    buff_desc.ulVersion = SECBUFFER_VERSION;
    buff_desc.cBuffers = 3;
    buff_desc.pBuffers = bufs;

    /* This buffer is for SSPI. */
    bufs[0].BufferType = SECBUFFER_TOKEN;
    bufs[0].cbBuffer = sizes.cbSecurityTrailer;
    bufs[0].pvBuffer = malloc(sizes.cbSecurityTrailer);
    if (bufs[0].pvBuffer == NULL) {
        res = LDAP_NO_MEMORY;
        goto error;
    }

    /* This buffer holds the application data. */
    bufs[1].BufferType = SECBUFFER_DATA;
    bufs[1].cbBuffer = inLen;
    bufs[1].pvBuffer = malloc(inLen);
    if (bufs[1].pvBuffer == NULL) {
        res = LDAP_NO_MEMORY;
        goto error;
    }

    memcpy(bufs[1].pvBuffer, inToken, inLen);

    /* This buffer is for SSPI. */
    bufs[2].BufferType = SECBUFFER_PADDING;
    bufs[2].cbBuffer = sizes.cbBlockSize;
    bufs[2].pvBuffer = malloc(sizes.cbBlockSize);
    if (bufs[2].pvBuffer == NULL) {
        res = LDAP_NO_MEMORY;
        goto error;
    }

    res = EncryptMessage(handle, SECQOP_WRAP_NO_ENCRYPT, &buff_desc, 0);

    if (res == SEC_E_OK) {
        int maxlen = bufs[0].cbBuffer + bufs[1].cbBuffer + bufs[2].cbBuffer;
        char *tokp = (char *)malloc(maxlen);
        if (tokp == NULL) {
            res = LDAP_NO_MEMORY;
            goto error;
        }
        *outToken = tokp;
        *outLen = maxlen;
        memcpy(tokp, bufs[0].pvBuffer, bufs[0].cbBuffer);
        tokp += bufs[0].cbBuffer;
        memcpy(tokp, bufs[1].pvBuffer, bufs[1].cbBuffer);
        tokp += bufs[1].cbBuffer;
        memcpy(tokp, bufs[2].pvBuffer, bufs[2].cbBuffer);
    }
    return res;
error:
    free(bufs[0].pvBuffer);
    free(bufs[1].pvBuffer);
    free(bufs[2].pvBuffer);
    return res;
}

/* Get maximal message length for certain mechanism. */
static int
init_package(wchar_t *package_name, unsigned long *max_mgslen) {
    int rc;
    PSecPkgInfo pkginfo;

    rc = QuerySecurityPackageInfo(package_name, &pkginfo);
    if (rc != SEC_E_OK) {
        return -1;
    }

    *max_mgslen = pkginfo->cbMaxToken;
    FreeContextBuffer(pkginfo);
    return 0;
}

/* Supplement the DIGEST-MD5 server response with an authorization ID. */
static char *
create_authzid_digest_str(char *authzid, char *chunk, int *length) {
    int len = 12;
    char *concat = NULL;

    if (authzid != NULL) len += (int)strlen(authzid);
    if (chunk != NULL) len += (int)strlen(chunk);

    concat = (char *)malloc(sizeof(char) * len);
    if (concat == NULL) return NULL;

    if (sprintf_s(concat, len, "%s,authzid=\"%s\"", chunk, authzid) == -1) {
        return NULL;
    }

    *length = len - 1;
    return concat;
}

/* Concat the decrypted GSSAPI server response with an authorization ID. */
static char *
create_authzid_gssapi_str(char *authzid, char *chunk, int chunklen, int *length) {
    int len = chunklen;
    char *concat = NULL;
    char *p;

    if (chunk == NULL) return NULL;
    if (authzid == NULL) return chunk;

    len += (int)strlen(authzid);
    concat = (char *)malloc(sizeof(char) * len);
    if (concat == NULL) return NULL;
    p = concat;

    /* Copy the authzid after the server response. */
    memcpy(p, chunk, chunklen);
    p += chunklen;
    memcpy(p, authzid, strlen(authzid));
    free(chunk);

    *length = len;
    return concat;
}

/* Create the credentials handle for the certain authentication. */
static int
create_credentials(CredHandle *hcred, wchar_t *package_name, sasl_defaults_t *defs) {
    int rc = 0;
    SEC_WINNT_AUTH_IDENTITY_W wincreds;
    wchar_t *wauthcid = NULL;
    wchar_t *wpasswd = NULL;
    wchar_t *wrealm = NULL;

    if (strcmp(defs->authcid, "") == 0 && strcmp(defs->passwd, "") == 0) {
        /* If authentication id and password are not set, then
           use NULL SEC_WINNT_AUTH_IDENTITY for logon user credentials. */
        return AcquireCredentialsHandleW(NULL, package_name, SECPKG_CRED_OUTBOUND,
            NULL, NULL, NULL, NULL, hcred, NULL);
    }

    memset(&wincreds, 0, sizeof(wincreds));

    if (rc = convert_to_wcs(defs->authcid, &wauthcid) != LDAP_SUCCESS) goto end;
    if (rc = convert_to_wcs(defs->passwd, &wpasswd) != LDAP_SUCCESS) goto end;
    if (rc = convert_to_wcs(defs->realm, &wrealm) != LDAP_SUCCESS) goto end;

    wincreds.User = (unsigned short *)wauthcid;
    if (wincreds.User != NULL) wincreds.UserLength = (unsigned long)wcslen(wauthcid);
    else wincreds.UserLength = 0;
    wincreds.Password = (unsigned short *)wpasswd;
    if (wincreds.Password != NULL) wincreds.PasswordLength = (unsigned long)wcslen(wpasswd);
    else wincreds.PasswordLength = 0;
    wincreds.Domain = (unsigned short *)wrealm;
    if (wincreds.Domain != NULL) wincreds.DomainLength = (unsigned long)wcslen(wrealm);
    else wincreds.DomainLength = 0;
    wincreds.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

    rc = AcquireCredentialsHandleW(NULL, package_name, SECPKG_CRED_OUTBOUND, NULL,
        &wincreds, NULL, NULL, hcred, NULL);
end:
    free(wauthcid);
    free(wpasswd);
    free(wrealm);
    return rc;
}

/* Generate the client context that will be used as a response to the server
   during the authetication porcess. */
static int
generate_client_ctxt(CredHandle *hcred, SecHandle *hctxt, wchar_t *package_name,
    wchar_t *target_name, sasl_defaults_t *defs, char *input, int inlen,
    char *output, int *outlen, int *crypted, char **crypted_msg) {
    int rc = 0, newctxt = 0, len = 0, isauthz = 0;
    unsigned long ctxtattr;
    char *data = NULL;
    SecBufferDesc out_buff_desc;
    SecBuffer out_buff;
    SecBufferDesc in_buff_desc;
    SecBuffer in_buff;

    if (!input) {
        newctxt = 1;

        rc = create_credentials(hcred, package_name, defs);
        if (rc < 0) goto end;
    }

    /* Prepare output buffer. */
    out_buff_desc.ulVersion = SECBUFFER_VERSION;
    out_buff_desc.cBuffers = 1;
    out_buff_desc.pBuffers = &out_buff;

    out_buff.cbBuffer = *outlen;
    out_buff.BufferType = SECBUFFER_TOKEN;
    out_buff.pvBuffer = output;

    if (!newctxt) {
        if (wcscmp(package_name, L"WDigest") == 0 &&
            defs->authzid != NULL && strlen(defs->authzid) != 0
            && input != NULL) {
            /* Authzid for DIGEST-MD5 authentication. */
            input[inlen] = '\0';
            input = create_authzid_digest_str(defs->authzid, input, &inlen);
            if (input == NULL) return -1;
            isauthz = 1;
        }

        /* Prepare intput buffer. */
        in_buff_desc.ulVersion = SECBUFFER_VERSION;
        in_buff_desc.cBuffers = 1;
        in_buff_desc.pBuffers = &in_buff;

        in_buff.cbBuffer = inlen;
        in_buff.BufferType = SECBUFFER_TOKEN;
        in_buff.pvBuffer = input;
    }

    if (*crypted == 1) {
        /* Crypting for Kerberos. */
        rc = decrypt_response(hctxt, input, inlen, &data, &len);
        data = create_authzid_gssapi_str(defs->authzid, data, len, &len);
        if (data == NULL) return LDAP_NO_MEMORY;
        rc = encrypt_reply(hctxt, data, len, crypted_msg, outlen);
        free(data);
        return 1;
    } else {
        rc = InitializeSecurityContextW(hcred, newctxt ? NULL : hctxt,
            target_name, ISC_REQ_MUTUAL_AUTH | ISC_REQ_NO_INTEGRITY,
            0, SECURITY_NATIVE_DREP, newctxt ? NULL : &in_buff_desc,
            0, hctxt, &out_buff_desc, &ctxtattr, NULL);
        if (isauthz) free(input);
    }
    if (rc < 0) goto end;

    if (rc == SEC_E_OK) *crypted = 1;

    if ((rc == SEC_I_COMPLETE_NEEDED) || (rc == SEC_I_COMPLETE_AND_CONTINUE)) {
        /* Complete token. */
        rc = CompleteAuthToken(hctxt, &out_buff_desc);
        if (rc < 0) goto end;
    }

    *outlen = out_buff.cbBuffer;
end:
    return rc;
}

/* Get the SPN target name from the LDAP struct's hostname. */
static wchar_t *
get_target_name(LDAP *ld) {
    size_t len = 0;
    wchar_t *hostname = NULL;
    wchar_t *target_name = NULL;

    convert_to_wcs(ld->ld_host, &hostname);
    if (hostname == NULL) return NULL;

    /* The new string starts with ldap/ (5 char) + 1 terminating NULL. */
    len = wcslen(hostname) + 6;
    target_name = (wchar_t *)malloc(sizeof(wchar_t) * len);
    if (target_name == NULL) return NULL;
    /* Copy hostname from LDAP struct to create a valid targetName(SPN). */
    swprintf_s(target_name, len, L"ldap/%ls", hostname);

    return target_name;
}

/* Execute a synchronous SASL binding to the directory server.
   No asynchronous function can be used because there is some bug in the
   WinLDAP library that makes impossible to process the result of the
   server with the ldap_result function. */
int
ldap_sasl_sspi_bind_sU(LDAP *ld, char *dn, char *mechanism, LDAPControlA **sctrls,
    LDAPControlA **cctrls, void *defaults) {
    int i = 0, rc = 0, maxlen = 0;
    int outlen = 0, inlen = 0, crypted = 0;
    char *output = NULL, *input = NULL, *crypted_msg = NULL;
    wchar_t *package_name = NULL, *target_name = NULL;
    wchar_t *wdn = NULL, *wmech = NULL, *error_msg = NULL;
    struct berval cred;
    struct berval *response = NULL;
    LDAPControlW **wsctrls = NULL;
    LDAPControlW **wcctrls = NULL;
    CredHandle credhandle;
    CtxtHandle ctxhandle;
    sasl_defaults_t *defs = (sasl_defaults_t *)defaults;
    /* Supported mechanisms, order matters. */
    char *mechs[] = { "DIGEST-MD5", "NTLM", "GSSAPI", "GSS-SPNEGO", "EXTERNAL", NULL };
    wchar_t *secpacks[] = { L"WDigest", L"NTLM", L"Kerberos", L"Negotiate", L"EXTERNAL", NULL };

    /* Get security package name from the mechanism. */
    for (i = 0; mechs[i] != NULL; i++) {
        if (strcmp(mechanism, mechs[i]) == 0) {
            package_name = secpacks[i];
            break;
        }
    }
    if (package_name == NULL) return LDAP_AUTH_METHOD_NOT_SUPPORTED;

    if (rc = convert_to_wcs(dn, &wdn) != LDAP_SUCCESS) goto end;
    if (rc = convert_to_wcs(mechanism, &wmech) != LDAP_SUCCESS) goto end;
    if (rc = convert_ctrl_list(sctrls, &wsctrls) != LDAP_SUCCESS) goto end;
    if (rc = convert_ctrl_list(cctrls, &wcctrls) != LDAP_SUCCESS) goto end;

    if (init_package(package_name, &maxlen) != 0) return LDAP_PARAM_ERROR;

    output = (char *)malloc(maxlen);
    if (output == NULL) return LDAP_NO_MEMORY;
    /* Fill with zeros (crtical for DIGEST-MD5). */
    memset(output, 0, maxlen);

    SecInvalidateHandle(&credhandle);
    SecInvalidateHandle(&ctxhandle);

    target_name = get_target_name(ld);
    if (target_name == NULL) return LDAP_PARAM_ERROR;

    if (strcmp(mechanism, "EXTERNAL") == 0) {
        /* Set authorization ID for EXTERNAL. */
        cred.bv_val = defs->authzid;
        if (defs->authzid != NULL) cred.bv_len = (unsigned long)strlen(defs->authzid);
        else cred.bv_len = 0;
    }

    do {
        outlen = maxlen;
        if (response) {
            input = response->bv_val;
            inlen = response->bv_len;
        } else {
            input = NULL;
            inlen = 0;
        }

        rc = generate_client_ctxt(&credhandle, &ctxhandle, package_name,
            target_name, defs, input, inlen, output, &outlen, &crypted,
            &crypted_msg);
        if (rc < 0) {
            ldap_set_option(ld, LDAP_OPT_ERROR_NUMBER, &rc);
            rc = LDAP_INVALID_CREDENTIALS;
            goto end;
        }

        if (strcmp(mechanism, "EXTERNAL") != 0) {
            cred.bv_len = outlen;
            if (crypted_msg != NULL) {
                cred.bv_val = crypted_msg;
            } else {
                cred.bv_val = output;
            }
        }

        if (response != NULL) ber_bvfree(response);
        rc = ldap_sasl_bind_sW(ld, wdn, wmech, &cred, wsctrls, wcctrls, &response);
        if (crypted_msg != NULL) free(crypted_msg);
        /* Get the last error code from the LDAP struct. */
        ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &rc);
    } while (rc == LDAP_SASL_BIND_IN_PROGRESS);

end:
    free(wdn);
    free(wmech);
    free(target_name);
    free(output);
    free_list((void **)wsctrls, (void *)free_ctrl);
    free_list((void **)wcctrls, (void *)free_ctrl);
    DeleteSecurityContext(&ctxhandle);
    FreeCredentialHandle(&credhandle);
    return rc;
}

static int WINAPI
ldap_thread_tls(void *thread_data) {
    int rc = 0;
    ldap_tls_data_t *data = (ldap_tls_data_t *)thread_data;

    rc = ldap_start_tls_sU(data->ld, data->serverctrls, data->clientctrls);
    free(data);

    return rc;
}

int
ldap_start_tlsU(LDAP *ld, LDAPControlA **serverctrls, LDAPControlA **clientctrls, HANDLE *msgidp) {
    ldap_tls_data_t *data = NULL;

    data = (ldap_tls_data_t *)malloc(sizeof(ldap_tls_data_t));
    if (data == NULL) return LDAP_NO_MEMORY;

    data->ld = ld;
    data->clientctrls = clientctrls;
    data->serverctrls = serverctrls;

    *msgidp = CreateThread(NULL, 0, ldap_thread_tls, (void *)data, 0, NULL);
    if (*msgidp == NULL) return LDAP_LOCAL_ERROR;

    return LDAP_SUCCESS;
}

/* Get the optional error message. */
char *
_ldap_get_opt_errormsgU(LDAP *ld) {
    int code = 0;
    char *opt = NULL;
    wchar_t *wopt = NULL;

    ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &code);

    if (code <= 0x80090367L && code >= 0x80090300L) {
        opt = (char *)malloc(sizeof(char) * 72);
        if (opt == NULL) return opt;
        sprintf_s(opt, 72, "SSPI authentication procedure is failed"
            " with error code: 0x%x", code);
    } else {
        /* Get additional error message from the session. */
        ldap_get_option(ld, LDAP_OPT_ERROR_STRING, &wopt);
        convert_to_mbs(wopt, &opt);
    }

    return opt;
}

#endif
