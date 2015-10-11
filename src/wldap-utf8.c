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
			/* Copy is failed, break the cicle and set the failed
			item to NULL thus the successfuly converted items
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


/* Convert a list of narrow character strings into a list of UTF-16 (narrow)
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
		if (ctrl->ldctl_oid) free(ctrl->ldctl_oid);
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
		if (mod->mod_type) free(mod->mod_type);
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
* can return with encoding or decoding error code, if the convertation is failed.
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

	if (rc = convert_to_wcs(dn, &wdn) != LDAP_SUCCESS) goto clear;
	if (rc = convert_ctrl_list(sctrls, &wsctrls) != LDAP_SUCCESS) goto clear;
	if (rc = convert_ctrl_list(cctrls, &wcctrls) != LDAP_SUCCESS) goto clear;
	if (rc = convert_mod_list(attrs, &wattrs) != LDAP_SUCCESS) goto clear;

	rc = ldap_add_extW(ld, wdn, wattrs, wsctrls, wcctrls, msgidp);

clear:
	if (wdn) free(wdn);
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

	if (rc = convert_to_wcs(dn, &wdn) != LDAP_SUCCESS) goto clear;
	if (rc = convert_ctrl_list(sctrls, &wsctrls) != LDAP_SUCCESS) goto clear;
	if (rc = convert_ctrl_list(cctrls, &wcctrls) != LDAP_SUCCESS) goto clear;
	if (rc = convert_mod_list(attrs, &wattrs) != LDAP_SUCCESS) goto clear;

	rc = ldap_modify_extW(ld, wdn, wattrs, wsctrls, wcctrls, msgidp);

clear:
	if (wdn) free(wdn);
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

	if (rc = convert_to_wcs(dn, &wdn) != LDAP_SUCCESS) goto clear;
	if (rc = convert_ctrl_list(sctrls, &wsctrls) != LDAP_SUCCESS) goto clear;
	if (rc = convert_ctrl_list(cctrls, &wcctrls) != LDAP_SUCCESS) goto clear;

	rc = ldap_delete_extW(ld, wdn, wsctrls, wcctrls, msgidp);

clear:
	if (wdn) free(wdn);
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

	if (wtarget) free(wtarget);

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
	
	if (rc = convert_to_wcs(dn, &wdn) != LDAP_SUCCESS) goto clear;
	if (rc = convert_to_wcs(newrdn, &wnewrdn) != LDAP_SUCCESS) goto clear;
	if (rc = convert_to_wcs(newSuperior, &wnewSuperior) != LDAP_SUCCESS) goto clear;
	if (rc = convert_ctrl_list(sctrls, &wsctrls) != LDAP_SUCCESS) goto clear;
	if (rc = convert_ctrl_list(cctrls, &wcctrls) != LDAP_SUCCESS) goto clear;

	rc = ldap_rename_extW(ld, wdn, wnewrdn, wnewSuperior, deleteoldrdn, wsctrls, wcctrls, msgidp);

clear:
	if (wdn) free(wdn);
	if (wnewrdn) free(wnewrdn);
	if (wnewSuperior) free(wnewSuperior);
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

	if (rc = convert_to_wcs(base, &wbase) != LDAP_SUCCESS) goto clear;
	if (rc = convert_to_wcs(filter, &wfilter) != LDAP_SUCCESS) goto clear;
	if (rc = convert_char_list(attrs, &wattrs) != LDAP_SUCCESS) goto clear;
	if (rc = convert_ctrl_list(sctrls, &wsctrls) != LDAP_SUCCESS) goto clear;
	if (rc = convert_ctrl_list(cctrls, &wcctrls) != LDAP_SUCCESS) goto clear;

	rc = ldap_search_extW(ld, wbase, scope, wfilter, wattrs, attrsonly, wsctrls, wcctrls, timelimit,
			sizelimit, msgidp);

clear:
	if (wbase) free(wbase);
	if (wfilter) free(wfilter);
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

	if (rc = convert_to_wcs(reqoid, &woid) != LDAP_SUCCESS) goto clear;
	if (rc = convert_ctrl_list(sctrls, &wsctrls) != LDAP_SUCCESS) goto clear;
	if (rc = convert_ctrl_list(cctrls, &wcctrls) != LDAP_SUCCESS) goto clear;

	rc = ldap_extended_operationW(ld, woid, reqdata, wsctrls, wcctrls, msgidp);

clear:
	if (woid) free(woid);
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
		struct berval *cookie) {
	
	int rc = 0;
	LDAPControlW **wctrls = NULL;

	if (rc = convert_ctrl_list(ctrls, &wctrls) != LDAP_SUCCESS) goto clear;

	if (cookie != NULL && cookie->bv_val != NULL) {
		/* Clear the cookie's content for the new data. */
		ber_bvfree(cookie);
		cookie = NULL;
	}

	rc = ldap_parse_page_controlW(ld, wctrls, (unsigned long *)count, &cookie);

clear:
	free_list((void **)wctrls, (void *)free_ctrl);

	return rc;
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
			goto clear;
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
			goto clear;
		}

		for (i = 0; wsctrls[i] != NULL; i++) {
			ctrla = (LDAPControlA *)malloc(sizeof(LDAPControlA));
			if (ctrla == NULL) return LDAP_NO_MEMORY;

			ctrla->ldctl_iscritical = wsctrls[i]->ldctl_iscritical;
			rc = convert_to_mbs(wsctrls[i]->ldctl_oid, &(ctrla->ldctl_oid));
			if (rc != LDAP_SUCCESS) goto clear;
			ctrla->ldctl_value.bv_len = wsctrls[i]->ldctl_value.bv_len;
			ctrla->ldctl_value.bv_val = _strdup(wsctrls[i]->ldctl_value.bv_val);
			ctrls[i] = ctrla;

		}
		ctrls[i] = NULL;

		*sctrls = ctrls;
	}

clear:
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
	char *nxtoken = NULL;

	/* Parse string address. */
	chunk = strtok_s(url, ":/", &nxtoken);
	while (chunk != NULL) {
		switch (chunk_num) {
		case 0:
			/* Check scheme. */
			if (strcmp("ldaps", chunk) == 0) {
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
		chunk = strtok_s(NULL, ":/", &nxtoken);
	}
init:
	if (rc = convert_to_wcs(host, &whost) != LDAP_SUCCESS) return rc;

	*ldp = ldap_sslinitW(whost, port, ssl);

	if (host) free(host);
	if (whost) free(whost);

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

	if (rc = convert_ctrl_list(sctrls, &wsctrls) != LDAP_SUCCESS) goto clear;
	if (rc = convert_ctrl_list(cctrls, &wcctrls) != LDAP_SUCCESS) goto clear;

	rc = ldap_start_tls_sW(ld, NULL, NULL, wsctrls, wcctrls);

clear:
	free_list((void **)wsctrls, (void *)free_ctrl);
	free_list((void **)wcctrls, (void *)free_ctrl);

	return rc;
}

int
ldap_simple_bind_sU(LDAP *ld, char *who, char *passwd) {
	int rc = 0;
	wchar_t *wwho = NULL;
	wchar_t *wpsw = NULL;

	if (rc = convert_to_wcs(who, &wwho) != LDAP_SUCCESS) goto clear;
	if (rc = convert_to_wcs(passwd, &wpsw) != LDAP_SUCCESS) goto clear;

	rc = ldap_simple_bind_sW(ld, wwho, wpsw);

clear:
	if (wwho) free(wwho);
	if (wpsw) free(wpsw);

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
		}
	}
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
	bufs[0].pvBuffer = malloc(sizes.cbSecurityTrailer);
	bufs[0].cbBuffer = sizes.cbSecurityTrailer;

	/* This buffer holds the application data. */
	bufs[1].BufferType = SECBUFFER_DATA;
	bufs[1].cbBuffer = inLen;
	bufs[1].pvBuffer = malloc(inLen);

	memcpy(bufs[1].pvBuffer, inToken, inLen);

	/* This buffer is for SSPI. */
	bufs[2].BufferType = SECBUFFER_PADDING;
	bufs[2].cbBuffer = sizes.cbBlockSize;
	bufs[2].pvBuffer = malloc(sizes.cbBlockSize);

	res = EncryptMessage(handle, SECQOP_WRAP_NO_ENCRYPT, &buff_desc, 0);

	if (res == SEC_E_OK) {
		int maxlen = bufs[0].cbBuffer + bufs[1].cbBuffer + bufs[2].cbBuffer;
		char *p = (char *)malloc(maxlen);
		*outToken = p;
		*outLen = maxlen;
		memcpy(p, bufs[0].pvBuffer, bufs[0].cbBuffer);
		p += bufs[0].cbBuffer;
		memcpy(p, bufs[1].pvBuffer, bufs[1].cbBuffer);
		p += bufs[1].cbBuffer;
		memcpy(p, bufs[2].pvBuffer, bufs[2].cbBuffer);
	}

	return res;
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

/* Create the replies for the server's responses during the SASL binding procedure. */
static int
sspi_bind_procedure(CredHandle *credhandle, CtxtHandle *ctxhandle, wchar_t *targetName, char *authzid,
	int *gssapi, struct berval **response, struct berval *creddata) {

	int rc = 0;
	int len = 0;
	unsigned long contextattr;
	SecBufferDesc out_buff_desc;
	SecBuffer out_buff;
	SecBufferDesc in_buff_desc;
	SecBuffer in_buff;
	char *data = NULL;
	char *resp_authzid = NULL;

	if (creddata == NULL || credhandle == NULL || targetName == NULL) return LDAP_PARAM_ERROR;

	/* Set creddata empty. */
	creddata->bv_len = 0;
	creddata->bv_val = NULL;

	/* Init output buffer. */
	out_buff_desc.ulVersion = 0;
	out_buff_desc.cBuffers = 1;
	out_buff_desc.pBuffers = &out_buff;

	out_buff.BufferType = SECBUFFER_TOKEN;
	out_buff.pvBuffer = NULL;

	if (*response == NULL) {
		/* First function call, no server response. */
		rc = InitializeSecurityContextW(credhandle, NULL, targetName, ISC_REQ_MUTUAL_AUTH | ISC_REQ_ALLOCATE_MEMORY,
			0, 0, NULL, 0, ctxhandle, &out_buff_desc, &contextattr, NULL);
	} else {
		if (*gssapi == 0 && authzid != NULL && (*response)->bv_val != NULL && strlen(authzid) != 0) {
			/* Authzid for DIGEST-MD5 authentication. */
			(*response)->bv_val[(*response)->bv_len] = '\0';
			resp_authzid = create_authzid_digest_str(authzid, (*response)->bv_val, &len);
			if (resp_authzid == NULL) return -1;
			ber_bvfree(*response);

			*response = (struct berval *)malloc(sizeof(struct berval));
			if (response == NULL) return -1;
			(*response)->bv_val = resp_authzid;
			(*response)->bv_len = len;
		}

		/* Set server response as an input buffer. */
		in_buff_desc.ulVersion = SECBUFFER_VERSION;
		in_buff_desc.cBuffers = 1;
		in_buff_desc.pBuffers = &in_buff;

		in_buff.cbBuffer = (*response)->bv_len;
		in_buff.BufferType = SECBUFFER_TOKEN;
		in_buff.pvBuffer = (*response)->bv_val;
		if (*gssapi == 2) {
			/* GSSAPI decrypting and encrypting is needed. */
			rc = decrypt_response(ctxhandle, (*response)->bv_val, (*response)->bv_len, &data, &len);
			data = create_authzid_gssapi_str(authzid, data, len, &len);
			rc = encrypt_reply(ctxhandle, data, len, &data, &len);
		} else {
			rc = InitializeSecurityContextW(credhandle, ctxhandle, targetName, ISC_REQ_MUTUAL_AUTH |
				ISC_REQ_ALLOCATE_MEMORY, 0, 0, &in_buff_desc, 0, ctxhandle, &out_buff_desc, &contextattr, NULL);
		}
		if (*gssapi == 0 && authzid != NULL && (*response)->bv_val != NULL && strlen(authzid) != 0) {
			/* Cleaning DIGEST-MD5 authzid. */
			free((*response)->bv_val);
			free(*response);
			*response = NULL;
		}
	}

	switch (rc) {
	case SEC_I_COMPLETE_NEEDED:
	case SEC_I_COMPLETE_AND_CONTINUE:
		CompleteAuthToken(ctxhandle, &out_buff_desc);
		break;
	case SEC_E_OK:
		if (*gssapi == 1) {
			/* This means the encrypt and decrypt functions
			   should be called in the next round. */
			*gssapi = 2;
		}
		break;
	case SEC_I_CONTINUE_NEEDED:
		break;
	case SEC_E_INVALID_HANDLE:
	case SEC_E_INVALID_TOKEN:
		return -1;
	default:
		break;
	}

	if (*gssapi == 2) {
		/* Use the encrypted data as a cred output berval struct. */
		creddata->bv_len = len;
		creddata->bv_val = data;
	} else {
		/* Allocate and copy the local buffer value into the output berval struct. */
		creddata->bv_val = (char *)malloc((out_buff.cbBuffer + 1) * sizeof(char));
		if (creddata->bv_val == NULL) return LDAP_NO_MEMORY;
		memcpy(creddata->bv_val, out_buff.pvBuffer, out_buff.cbBuffer);
		creddata->bv_len = out_buff.cbBuffer;
	}

	return LDAP_SUCCESS;
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
	int i;
	int rc = 0;
	int authmod = 0;
	/*
	Auth mode:
		0 : DIGEST-MD5;
		1 : GSSAPI (starting);
		2 : GSSAPI (ending);
		3 : EXTERNAL;
	*/
	wchar_t *secpack = NULL;
	wchar_t *wdn = NULL;
	wchar_t *wmech = NULL;
	wchar_t *wauthcid = NULL;
	wchar_t *wpasswd = NULL;
	wchar_t *wrealm = NULL;
	wchar_t *target_name = NULL;
	struct berval cred;
	struct berval *response = NULL;
	LDAPControlW **wsctrls = NULL;
	LDAPControlW **wcctrls = NULL;
	SEC_WINNT_AUTH_IDENTITY_W wincreds;
	CredHandle credhandle;
	CtxtHandle ctxhandle;
	sasl_defaults_t *defs = (sasl_defaults_t *)defaults;
	/* Supported mechanisms, order matters. */
	char *mechs[] = { "DIGEST-MD5", "GSSAPI", "EXTERNAL", NULL };
	wchar_t *secpacks[] = { L"WDigest", L"Kerberos", L"EXTERNAL", NULL };

	if (rc = convert_to_wcs(dn, &wdn) != LDAP_SUCCESS) goto clear;
	if (rc = convert_to_wcs(mechanism, &wmech) != LDAP_SUCCESS) goto clear;
	if (rc = convert_ctrl_list(sctrls, &wsctrls) != LDAP_SUCCESS) goto clear;
	if (rc = convert_ctrl_list(cctrls, &wcctrls) != LDAP_SUCCESS) goto clear;

	cred.bv_val = NULL;
	cred.bv_len = 0;

	/* Get security package name from the mechanism. */
	for (i = 0; mechs[i] != NULL; i++) {
		if (strcmp(mechanism, mechs[i]) == 0) {
			secpack = secpacks[i];
			break;
		}
	}

	if (secpack == NULL) return LDAP_PARAM_ERROR;
	if (wcscmp(secpack, L"Kerberos") == 0) authmod = 1;
	else if (wcscmp(secpack, L"EXTERNAL") == 0) authmod = 3;

	if (authmod != 3) {
		/* Set credentials and target name for WDigest and Kerberos. */
		/* Create credential data. */
		memset(&wincreds, 0, sizeof(wincreds));

		if (rc = convert_to_wcs(defs->authcid, &wauthcid) != LDAP_SUCCESS) goto clear;
		if (rc = convert_to_wcs(defs->passwd, &wpasswd) != LDAP_SUCCESS) goto clear;
		if (rc = convert_to_wcs(defs->realm, &wrealm) != LDAP_SUCCESS) goto clear;

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

		/* Create credential handler. */
		rc = AcquireCredentialsHandleW(NULL, secpack, SECPKG_CRED_OUTBOUND, NULL, &wincreds, NULL, NULL, &credhandle, NULL);
		if (rc != SEC_E_OK) return LDAP_PARAM_ERROR;

		/* Get the target name (SPN). */
		target_name = get_target_name(ld);
		if (target_name == NULL) return LDAP_PARAM_ERROR;
	} else {
		/* Set authorization ID for EXTERNAL. */
		cred.bv_val = defs->authzid;
		if (defs->authzid != NULL)  cred.bv_len = strlen(defs->authzid);
		else cred.bv_len = 0;
	}
	do {

		rc = sspi_bind_procedure(&credhandle, &ctxhandle, target_name, defs->authzid, &authmod, &response, &cred);

		if (response != NULL) ber_bvfree(response);
		rc = ldap_sasl_bind_sW(ld, wdn, wmech, &cred, wsctrls, wcctrls, &response);
		/* Free the previously allocated data (but not for EXTERNAL). */
		if (cred.bv_val != NULL && authmod != 3) {
			free(cred.bv_val);
			cred.bv_len = 0;
		}
		/* Get the last error code from the LDAP struct. */
		ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &rc);
	} while (rc == LDAP_SASL_BIND_IN_PROGRESS);

clear:
	if (wdn) free(wdn);
	if (wmech) free(wmech);
	if (wauthcid) free(wauthcid);
	if (wpasswd) free(wpasswd);
	if (wrealm) free(wrealm);
	free(target_name);
	free_list((void **)wsctrls, (void *)free_ctrl);
	free_list((void **)wcctrls, (void *)free_ctrl);

	return rc;
}

/* Get the optional error message. */
char *
_ldap_get_opt_errormsgU(LDAP *ld) {
	char *opt = NULL;
	wchar_t *wopt = NULL;

	/* Get additional error message from the session. */
	ldap_get_option(ld, LDAP_OPT_ERROR_STRING, &wopt);

	convert_to_mbs(wopt, &opt);

	return opt;
}

#endif