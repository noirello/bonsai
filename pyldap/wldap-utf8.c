#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__)

#include "wldap-utf8.h"

/* Get size of a list by reaching the terminating NULL. */
static int
get_size(void **list) {
	int size = 0;

	if (list == NULL) return 0;

	while (list[size] != NULL) size++;

	return size;
}

static void
copy_list(void **list, void **newlist, void *copyfunc(void *), int *failed) {
	int i = 0;

	*failed = 0;
	for (i = 0; list[i] != NULL; i++) {
		newlist[i] = (copyfunc)((void *)(list[i]));
		if (newlist[i] == NULL) {
			*failed = 1;
			break;
		}
	}
	newlist[i] = NULL;
}

static void
free_list(void **list, void *freefunc(void*)) {
	int i = 0;

	if (list != NULL) {
		for (i = 0; list[i] != NULL; i++) {
			(freefunc)(list[i]);
		}
		free(list);
	}
}

static char *
convert_to_mbs(wchar_t *tmp) {
	char *str = NULL;
	int size = 0;
	int rc = 0;

	if (tmp == NULL) return NULL;

	/* Get necessary size for the new UTF-8 encoded char*. */
	size = WideCharToMultiByte(CP_UTF8, 0, tmp, -1, NULL, 0, NULL, NULL);
	str = (char *)malloc(sizeof(char) * size);
	if (str == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	rc = WideCharToMultiByte(CP_UTF8, 0, tmp, -1, str, size, NULL, NULL);
	if (rc == 0) {
		free(str);
		PyErr_Format(PyExc_UnicodeError, "Converting to UTF-8 is failed.");
		return NULL;
	}

	return str;
}

static wchar_t *
convert_to_wcs(char *tmp) {
	wchar_t *str = NULL;
	int size = 0;
	int rc = 0;

	if (tmp == NULL) return NULL;

	/* Get necessary size for the new wchar_t*. */
	size = MultiByteToWideChar(CP_UTF8, 0, tmp, -1, NULL, 0);
	str = (wchar_t *)malloc(sizeof(wchar_t) * size);
	if (str == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	rc = MultiByteToWideChar(CP_UTF8, 0, tmp, -1, str, size);
	if (rc == 0) {
		free(str);
		PyErr_Format(PyExc_UnicodeError, "Converting from UTF-8 is failed.");
		return NULL;
	}

	return str;
}

static wchar_t **
convert_char_list(char **list) {
	int size = 0;
	int failed = 0;
	wchar_t **wlist = NULL;

	if (list == NULL) return NULL;

	size = get_size((void **)list);

	wlist = (wchar_t **)malloc(sizeof(wchar_t *) * (size + 1));
	if (wlist == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	copy_list((void **)list, (void **)wlist, (void *)convert_to_wcs, &failed);

	if (failed) {
		/* At least one of the item's conversion is failed,
		   thus the list is not converted properly. */
		free_list((void **)wlist, (void *)free);
		return NULL;
	}

	return wlist;
}

static LDAPControlW *
convert_ctrl(LDAPControlA *ctrl) {
	wchar_t *woid = NULL;
	LDAPControlW *wctrl = NULL;

	if (ctrl == NULL) return NULL;

	wctrl = (LDAPControlW *)malloc(sizeof(LDAPControlW));
	if (wctrl == NULL) {
		PyErr_NoMemory();
		return NULL;
	}
	
	wctrl->ldctl_iscritical = ctrl->ldctl_iscritical;
	wctrl->ldctl_value = ctrl->ldctl_value;

	woid = convert_to_wcs(ctrl->ldctl_oid);
	wctrl->ldctl_oid = woid;

	return wctrl;
}

static void 
free_ctrl(LDAPControlW *ctrl) {
	if (ctrl != NULL) {
		if (ctrl->ldctl_oid) free(ctrl->ldctl_oid);
		free(ctrl);
	}
}

static LDAPControlW **
convert_ctrl_list(LDAPControlA **ctrls) {
	int size = 0;
	int failed = 0;
	LDAPControlW **wctrls = NULL;

	if (ctrls == NULL) return NULL;

	size = get_size((void **)ctrls);
	wctrls = (LDAPControlW **)malloc(sizeof(LDAPControlW *) * (size + 1));
	if (wctrls == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	copy_list((void **)ctrls, (void **)wctrls, (void *)convert_ctrl, &failed);

	if (failed) {
		/* At least one of the item's conversion is failed,
		thus the list is not converted properly. */
		free_list((void **)wctrls, (void *)free_ctrl);
		return NULL;
	}

	return wctrls;
}

static LDAPModW *
convert_mod(LDAPModA *mod) {
	LDAPModW *wmod = NULL;

	if (mod == NULL) return NULL;

	wmod = (LDAPModW *)malloc(sizeof(LDAPModW));
	if (wmod == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	wmod->mod_op = mod->mod_op;

	if ((wmod->mod_op & LDAP_MOD_BVALUES) == LDAP_MOD_BVALUES) {
		wmod->mod_vals.modv_bvals = mod->mod_vals.modv_bvals;
	} else {
		wmod->mod_vals.modv_strvals = convert_char_list(mod->mod_vals.modv_strvals);
	}
	wmod->mod_type = convert_to_wcs(mod->mod_type);

	return wmod;
}

static void
free_mod(LDAPModW *mod) {
	if (mod != NULL) {
		if (mod->mod_type) free(mod->mod_type);
		if ((mod->mod_op & LDAP_MOD_BVALUES) != LDAP_MOD_BVALUES) {
			if (mod->mod_vals.modv_strvals) free_list((void **)(mod->mod_vals.modv_strvals), (void *)free);
		}
		free(mod);
	}
}

static LDAPModW **
convert_mod_list(LDAPModA **mods) {
	int size = 0;
	int failed = 0;
	LDAPModW **wmods = NULL;

	if (mods == NULL) return NULL;

	size = get_size((void **)mods);
	wmods = (LDAPModW **)malloc(sizeof(LDAPModW *) * (size + 1));
	if (wmods == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	copy_list((void **)mods, (void **)wmods, (void *)convert_mod, &failed);

	if (failed) {
		/* At least one of the item's conversion is failed,
		thus the list is not converted properly. */
		free_list((void **)wmods, (void *)free_mod);
		return NULL;
	}

	return wmods;
}

static LDAPSortKeyW *
convert_sortkey(LDAPSortKeyA *sortkey) {
	wchar_t *attrtype = NULL;
	wchar_t *ruleoid = NULL;
	LDAPSortKeyW *wsortkey = NULL;

	if (sortkey == NULL) return NULL;

	wsortkey = (LDAPSortKeyW *)malloc(sizeof(LDAPSortKeyW));
	if (wsortkey == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	attrtype = convert_to_wcs(sortkey->sk_attrtype);
	wsortkey->sk_attrtype = attrtype;
	
	ruleoid = convert_to_wcs(sortkey->sk_matchruleoid);
	wsortkey->sk_matchruleoid = ruleoid;

	wsortkey->sk_reverseorder = sortkey->sk_reverseorder;

	return wsortkey;
}

static void
free_sortkey(LDAPSortKeyW *sortkey) {
	if (sortkey != NULL) {
		if (sortkey->sk_attrtype) free(sortkey->sk_attrtype);
		if (sortkey->sk_matchruleoid) free(sortkey->sk_matchruleoid);
	}
}

static LDAPSortKeyW **
convert_sortkey_list(LDAPSortKeyA **keylist) {
	int size = 0;
	int failed = 0;
	LDAPSortKeyW **wkeylist = NULL;
	
	if (keylist == NULL) return NULL;

	size = get_size((void **)keylist);
	wkeylist = (LDAPSortKeyW **)malloc(sizeof(LDAPSortKeyW *) * (size + 1));
	if (wkeylist == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	copy_list((void **)keylist, (void **)wkeylist, (void *)convert_sortkey, &failed);

	if (failed) {
		/* At least one of the item's conversion is failed,
		thus the list is not converted properly. */
		free_list((void **)wkeylist, (void *)free_sortkey);
		return NULL;
	}

	return wkeylist;
}

int
ldap_unbind_ext(LDAP *ld, LDAPControl **sctrls, LDAPControl	**cctrls) {
	return ldap_unbind(ld);
}

int
ldap_abandon_ext(LDAP *ld, int msgid, LDAPControl **sctrls, LDAPControl	**cctrls) {
	return ldap_abandon(ld, msgid);
}

char *
ldap_get_dnU(LDAP *ld, LDAPMessage *entry) {
	char *dn = NULL;
	wchar_t *wdn = NULL;

	wdn = ldap_get_dnW(ld, entry);

	dn = convert_to_mbs(wdn);

	ldap_memfreeW(wdn);

	return dn;
}

int
ldap_add_extU(LDAP *ld, char *dn, LDAPMod **attrs, LDAPControl **sctrls, LDAPControl **cctrls,
		int *msgidp) {
	
	int rc = 0;
	wchar_t *wdn = NULL;
	LDAPModW **wattrs = NULL;
	LDAPControlW **wsctrls = NULL;
	LDAPControlW **wcctrls = NULL;

	wdn = convert_to_wcs(dn);
	wsctrls = convert_ctrl_list(sctrls);
	wcctrls = convert_ctrl_list(cctrls);
	wattrs = convert_mod_list(attrs);

	rc = ldap_add_extW(ld, wdn, wattrs, wsctrls, wcctrls, msgidp);

	if (wdn) free(wdn);
	free_list((void **)wsctrls, (void *)free_ctrl);
	free_list((void **)wcctrls, (void *)free_ctrl);
	free_list((void **)wattrs, (void *)free_mod);

	return rc;
}

int
ldap_modify_extU(LDAP *ld, char *dn, LDAPMod **attrs, LDAPControl **sctrls, LDAPControl **cctrls,
		int *msgidp) {
	
	int rc = 0;
	wchar_t *wdn = NULL;
	LDAPModW **wattrs = NULL;
	LDAPControlW **wsctrls = NULL;
	LDAPControlW **wcctrls = NULL;

	wdn = convert_to_wcs(dn);
	wsctrls = convert_ctrl_list(sctrls);
	wcctrls = convert_ctrl_list(cctrls);
	wattrs = convert_mod_list(attrs);

	rc = ldap_modify_extW(ld, wdn, wattrs, wsctrls, wcctrls, msgidp);

	if (wdn) free(wdn);
	free_list((void **)wsctrls, (void *)free_ctrl);
	free_list((void **)wcctrls, (void *)free_ctrl);
	free_list((void **)wattrs, (void *)free_mod);

	return rc;
}

int
ldap_delete_extU(LDAP *ld, char *dn, LDAPControl **sctrls, LDAPControl **cctrls, int *msgidp) {
	int rc = 0;
	wchar_t *wdn = NULL;
	LDAPControlW **wsctrls = NULL;
	LDAPControlW **wcctrls = NULL;

	wdn = convert_to_wcs(dn);
	wsctrls = convert_ctrl_list(sctrls);
	wcctrls = convert_ctrl_list(cctrls);

	rc = ldap_delete_extW(ld, wdn, wsctrls, wcctrls, msgidp);

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

	attr = convert_to_mbs(wattr);

	ldap_memfreeW(wattr);

	return attr;
}

char *
ldap_next_attributeU(LDAP *ld, LDAPMessage *entry, BerElement *ber) {
	char *attr = NULL;
	wchar_t *wattr = NULL;

	wattr = ldap_next_attributeW(ld, entry, ber);

	attr = convert_to_mbs(wattr);

	ldap_memfreeW(wattr);

	return attr;
}

struct berval **
ldap_get_values_lenU(LDAP *ld, LDAPMessage *entry, char *target) {
	struct berval **ret = NULL;
	wchar_t *wtarget = NULL;

	wtarget = convert_to_wcs(target);

	ret = ldap_get_values_lenW(ld, entry, wtarget);

	if (wtarget) free(wtarget);

	return ret;
}

int
ldap_renameU(LDAP *ld, char *dn, char *newrdn, char *newSuperior, int deleteoldrdn,
		LDAPControl **sctrls, LDAPControl **cctrls, int *msgidp) {
	
	int rc = 0;
	wchar_t *wdn = NULL; 
	wchar_t *wnewrdn = NULL;
	wchar_t *wnewSuperior = NULL;
	LDAPControlW **wsctrls = NULL;
	LDAPControlW **wcctrls = NULL;
	
	wdn = convert_to_wcs(dn);
	wnewrdn = convert_to_wcs(newrdn);
	wnewSuperior = convert_to_wcs(newSuperior);
	wsctrls = convert_ctrl_list(sctrls);
	wcctrls = convert_ctrl_list(cctrls);

	rc = ldap_rename_extW(ld, wdn, wnewrdn, wnewSuperior, deleteoldrdn, wsctrls, wcctrls, msgidp);

	if (wdn) free(wdn);
	if (wnewrdn) free(wnewrdn);
	if (wnewSuperior) free(wnewSuperior);
	free_list((void **)wsctrls, (void *)free_ctrl);
	free_list((void **)wcctrls, (void *)free_ctrl);

	return rc;
}

int
ldap_search_extU(LDAP *ld, char *base, int scope, char *filter, char **attrs, int attrsonly,
		LDAPControl **sctrls, LDAPControl **cctrls, struct timeval *timeout, int sizelimit, int *msgidp) {
	
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

	wbase = convert_to_wcs(base);
	wfilter = convert_to_wcs(filter);
	wattrs = convert_char_list(attrs);
	wsctrls = convert_ctrl_list(sctrls);
	wcctrls = convert_ctrl_list(cctrls);

	rc = ldap_search_extW(ld, wbase, scope, wfilter, wattrs, attrsonly, wsctrls, wcctrls, timelimit,
			sizelimit, msgidp);

	if (wbase) free(wbase);
	if (wfilter) free(wfilter);
	free_list((void **)wattrs, (void *)free);
	free_list((void **)wsctrls, (void *)free_ctrl);
	free_list((void **)wcctrls, (void *)free_ctrl);

	return rc;
}

int
ldap_create_sort_controlU(LDAP *ld, LDAPSortKey **keyList, int iscritical, LDAPControl **ctrlp) {
	int rc = 0;
	LDAPSortKeyW **wkeylist = NULL;
	LDAPControlW *wctrlp = NULL;
	LDAPControlA *ret = NULL;

	wkeylist = convert_sortkey_list(keyList);

	rc = ldap_create_sort_controlW(ld, wkeylist, iscritical, &wctrlp);

	free_list((void **)wkeylist, (void *)free_sortkey);

	ret = (LDAPControlA *)malloc(sizeof(LDAPControlA));
	if (ret == NULL) {
		PyErr_NoMemory();
		return -1;
	}

	ret->ldctl_iscritical = wctrlp->ldctl_iscritical;
	ret->ldctl_oid = convert_to_mbs(wctrlp->ldctl_oid);
	ret->ldctl_value = wctrlp->ldctl_value;

	*ctrlp = ret;

	ldap_control_freeW(wctrlp);

	return rc;
}

int
ldap_extended_operationU(LDAP *ld, char *reqoid, struct berval *reqdata, LDAPControl **sctrls,
		LDAPControl **cctrls, int *msgidp) {
	
	int rc = 0;
	wchar_t *woid = NULL;
	LDAPControlW **wsctrls = NULL;
	LDAPControlW **wcctrls = NULL;

	woid = convert_to_wcs(reqoid);
	wsctrls = convert_ctrl_list(sctrls);
	wcctrls = convert_ctrl_list(cctrls);

	rc = ldap_extended_operationW(ld, woid, reqdata, wsctrls, wcctrls, msgidp);

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
	oid = convert_to_mbs(wretoid);

	if (wretoid) ldap_memfreeW(wretoid);

	*retoidp = oid;

	return rc;
}

int
ldap_parse_pageresponse_controlU(LDAP *ld, LDAPControl **ctrls, ber_int_t *count,
		struct berval *cookie) {
	
	int rc = 0;
	LDAPControlW **wctrls = NULL;

	wctrls = convert_ctrl_list(ctrls);

	if (cookie != NULL && cookie->bv_val != NULL) {
		/* Clear the cookie's content for the new data. */
		ber_bvfree(cookie);
		cookie = NULL;
	}

	rc = ldap_parse_page_controlW(ld, wctrls, (unsigned long *)count, &cookie);

	free_list((void **)wctrls, (void *)free_ctrl);

	return rc;
}

/* This function is a dummy function for keeping compatibility with OpenLDAP. */
LDAPControl **
ldap_control_findU(char *oid, LDAPControl **ctrls, LDAPControl ***nextctrlp) {
	return ctrls;
}

int
ldap_parse_resultU(LDAP *ld, LDAPMessage *res, int *errcodep, char **matcheddnp, char **errmsgp,
		char ***referralsp, LDAPControl ***sctrls, int freeit) {
	
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

	/* Convert and assign parameters just if they are required. */
	if (matcheddnp != NULL) *matcheddnp = convert_to_mbs(wmatcheddnp);
	if (errmsgp != NULL) *errmsgp = convert_to_mbs(werrmsgp);

	if (wreferralsp != NULL && referralsp != NULL) {
		/* Copy and convert the referral strings, if it's required. */
		size = get_size(wreferralsp);
		refs = (char **)malloc(sizeof(char *) * (size + 1));
		if (refs == NULL) {
			PyErr_NoMemory();
			return -1;
		}

		for (i = 0; wreferralsp[i] != NULL; i++) {
			refs[i] = convert_to_mbs(wreferralsp[i]);
		}
		refs[i] = NULL;
		*referralsp = refs;
	}

	if (wsctrls != NULL && sctrls != NULL) {
		/* Copy and convert the server controls, if it's required. */
		size = get_size(wsctrls);
		ctrls = (LDAPControlA **)malloc(sizeof(LDAPControlA *) * (size + 1));
		if (ctrls == NULL) {
			PyErr_NoMemory();
			return -1;
		}

		for (i = 0; wsctrls[i] != NULL; i++) {
			ctrla = (LDAPControlA *)malloc(sizeof(LDAPControlA));
			if (ctrla == NULL) {
				PyErr_NoMemory();
				return -1;
			}
			ctrla->ldctl_iscritical = wsctrls[i]->ldctl_iscritical;
			ctrla->ldctl_oid = convert_to_mbs(wsctrls[i]->ldctl_oid);
			ctrla->ldctl_value = *ber_bvdup(&(wsctrls[i]->ldctl_value));
			ctrls[i] = ctrla;

		}
		ctrls[i] = NULL;

		*sctrls = ctrls;
	}

	ldap_memfreeW(wmatcheddnp);
	ldap_memfreeW(werrmsgp);
	ldap_value_freeW(wreferralsp);
	ldap_controls_freeW(wsctrls);

	return rc;
}

char *
ldap_err2stringU(int err) {
	wchar_t *werr = NULL;

	/* Mustn't free the returning string. */
	werr = ldap_err2stringW(err);

	return convert_to_mbs(werr);
}

int
ldap_initializeU(LDAP **ldp, char *url) {
	int err = 0;
	int chunk_num = 0;
	int port = 389;
	int ssl = 0;
	int size = 0;
	char *host = NULL;
	wchar_t *whost = NULL;
	char *chunk = NULL;

	chunk = strtok(url, ":/");
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
			size = (int)strlen(chunk);
			host = malloc(sizeof(char) * (size + 1));
			strcpy(host, chunk);
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
		chunk = strtok(NULL, ":/");
	}
init:
	whost = convert_to_wcs(host);

	if (ssl) {
		*ldp = ldap_sslinitW(whost, port, 1);
	} else {
		*ldp = ldap_initW(whost, port);
	}

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
ldap_start_tls_sU(LDAP *ld, LDAPControl **sctrls, LDAPControl **cctrls) {
	int rc = 0;
	LDAPControlW **wsctrls = NULL;
	LDAPControlW **wcctrls = NULL;

	wsctrls = convert_ctrl_list(sctrls);
	wcctrls = convert_ctrl_list(cctrls);

	rc = ldap_start_tls_sW(ld, NULL, NULL, wsctrls, wcctrls);

	free_list((void **)wsctrls, (void *)free_ctrl);
	free_list((void **)wcctrls, (void *)free_ctrl);

	return rc;
}

int
ldap_simple_bind_sU(LDAP *ld, char *who, char *passwd) {
	int rc = 0;
	wchar_t *wwho = NULL;
	wchar_t *wpsw = NULL;

	wwho = convert_to_wcs(who);
	wpsw = convert_to_wcs(passwd);

	rc = ldap_simple_bind_sW(ld, wwho, wpsw);

	if (wwho) free(wwho);
	if (wpsw) free(wpsw);

	return rc;
}

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

static int
encrypt_reply(CtxtHandle *handle, char *inToken, int inLen, char **outToken, int *outLen) {
	SecBufferDesc buff_desc;
	SecBuffer bufs[3];
	SecPkgContext_Sizes sizes;
	int res;

	res = QueryContextAttributes(handle, SECPKG_ATTR_SIZES, &sizes);

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

static int
sasl_bind_procedure(CredHandle *credhandle, CtxtHandle *ctxhandle, wchar_t *targetName, int gssapi,
struct berval *response, struct berval *creddata) {

	int rc = 0;
	int len = 0;
	int gssapi_decrpyt = 0;
	unsigned long contextattr;
	SecBufferDesc out_buff_desc;
	SecBuffer out_buff;
	SecBufferDesc in_buff_desc;
	SecBuffer in_buff;
	char *data = NULL;

	if (response == NULL) {
		/* First function call, no server response. */
		out_buff_desc.ulVersion = 0;
		out_buff_desc.cBuffers = 1;
		out_buff_desc.pBuffers = &out_buff;

		out_buff.BufferType = SECBUFFER_TOKEN;
		out_buff.pvBuffer = NULL;

		rc = InitializeSecurityContextW(credhandle, NULL, targetName, ISC_REQ_MUTUAL_AUTH | ISC_REQ_ALLOCATE_MEMORY,
			0, 0, NULL, 0, ctxhandle, &out_buff_desc, &contextattr, NULL);
	} else {
		/* Set server response as an input buffer. */
		in_buff_desc.ulVersion = SECBUFFER_VERSION;
		in_buff_desc.cBuffers = 1;
		in_buff_desc.pBuffers = &in_buff;

		in_buff.cbBuffer = response->bv_len;
		in_buff.BufferType = SECBUFFER_TOKEN;
		in_buff.pvBuffer = response->bv_val;
		if (gssapi_decrpyt) {
			/* GSSAPI decrypting and encrypting is needed. */
			rc = decrypt_response(ctxhandle, response->bv_val, response->bv_len, &data, &len);
			rc = encrypt_reply(ctxhandle, data, len, &data, &len);
		} else {
			rc = InitializeSecurityContextW(credhandle, ctxhandle, targetName, ISC_REQ_MUTUAL_AUTH |
				ISC_REQ_ALLOCATE_MEMORY, 0, 0, &in_buff_desc, 0, ctxhandle, &out_buff_desc, &contextattr, NULL);
		}
	}

	switch (rc) {
	case SEC_I_COMPLETE_NEEDED:
	case SEC_I_COMPLETE_AND_CONTINUE:
		CompleteAuthToken(ctxhandle, &out_buff_desc);
		break;
	case SEC_E_OK:
		if (gssapi == 1) {
			gssapi_decrpyt = 1;
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

	if (gssapi_decrpyt) {
		creddata->bv_len = len;
		creddata->bv_val = data;
	} else {
		creddata->bv_val = (char *)malloc((out_buff.cbBuffer + 1) * sizeof(char));
		if (creddata->bv_val == NULL) return LDAP_NO_MEMORY;
		memcpy(creddata->bv_val, out_buff.pvBuffer, out_buff.cbBuffer);
		creddata->bv_len = out_buff.cbBuffer;
	}

	return LDAP_SUCCESS;
}

static wchar_t *
get_target_name(LDAP *ld) {
	size_t len = 0;
	wchar_t *hostname = NULL;
	wchar_t *target_name = NULL;

	hostname = convert_to_wcs(ld->ld_host);
	if (hostname == NULL) return NULL;

	/* The new string starts with ldap/ (5 char) + 1 terminating NULL. */
	len = wcslen(hostname) + 6;
	target_name = (wchar_t *)malloc(sizeof(wchar_t) * len);
	if (target_name == NULL) return NULL;
	/* Copy hostname from LDAP struct to create a valid targetName(SPN). */
	wcscat(target_name, L"ldap/");
	wcscat(target_name, hostname);
	target_name[len - 1] = '\0';

	return target_name;
}

ldap_sasl_sspi_bind_sU(LDAP *ld, char *dn, char *mechanism, LDAPControl **sctrls,
	LDAPControl **cctrls, void *defaults) {
	int i;
	int rc = 0;
	int gssapi = 0;
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
	char *mechs[] = { "DIGEST-MD5", "GSSAPI", NULL };
	wchar_t *secpacks[] = { L"WDigest", L"Kerberos", NULL };

	wdn = convert_to_wcs(dn);
	wmech = convert_to_wcs(mechanism);
	wsctrls = convert_ctrl_list(sctrls);
	wcctrls = convert_ctrl_list(cctrls);

	/* Get security package name from the mechanism. */
	for (i = 0; mechs[i] != NULL; i++) {
		if (strcmp(mechanism, mechs[i]) == 0) {
			secpack = secpacks[i];
			break;
		}
	}

	if (secpack == NULL) return LDAP_PARAM_ERROR;
	if (wcscmp(secpack, L"Kerberos") == 0) gssapi = 1;

	/* Create credential data. */
	memset(&wincreds, 0, sizeof(wincreds));

	wauthcid = convert_to_wcs(defs->authcid);
	wpasswd = convert_to_wcs(defs->passwd);
	wrealm = convert_to_wcs(defs->realm);

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

	do {
		rc = sasl_bind_procedure(&credhandle, &ctxhandle, target_name, gssapi, response, &cred);
		if (rc != LDAP_SUCCESS) return rc;

		rc = ldap_sasl_bind_sW(ld, wdn, wmech, &cred, wsctrls, wcctrls, &response);

		/* Get the last error code from the LDAP struct. */
		ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &rc);
	} while (rc == LDAP_SASL_BIND_IN_PROGRESS);

	if (wdn) free(wdn);
	if (wmech) free(wmech);
	if (wauthcid) free(wauthcid);
	if (wpasswd) free(wpasswd);
	if (wrealm) free(wrealm);
	free_list((void **)wsctrls, (void *)free_ctrl);
	free_list((void **)wcctrls, (void *)free_ctrl);

	return rc;
}

#endif