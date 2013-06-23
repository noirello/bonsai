#include "errors.h"

PyObject *LDAPError;
PyObject *LDAPExc_UrlError;
PyObject *LDAPExc_NotConnected;

/*	Convert the ldap_url_parse() function's return code to
  	a more informative error message.
 */
char *lud_err2string(int rc) {
	switch (rc) {
		case LDAP_URL_SUCCESS:
			return "Success";
		case LDAP_URL_ERR_MEM:
			return "Can't allocate memory space";
		case LDAP_URL_ERR_PARAM:
			return "Parameter is bad";
		case  LDAP_URL_ERR_BADSCHEME:
			return "URL doesn't begin with \"ldap[si]://\"";
		case LDAP_URL_ERR_BADENCLOSURE:
			return "URL is missing trailing \">\"";
		case LDAP_URL_ERR_BADURL:
			return "URL is bad";
		case LDAP_URL_ERR_BADHOST:
			return "Host port is bad";
		case LDAP_URL_ERR_BADATTRS:
			return "Bad (or missing) attributes";
		case LDAP_URL_ERR_BADSCOPE:
			return "Scope string is invalid (or missing)";
		case LDAP_URL_ERR_BADFILTER:
			return "Bad or missing filter";
		case LDAP_URL_ERR_BADEXTS:
			return "Bad or missing extensions";
		default:
			return "Unpredicted error";
	}
}
