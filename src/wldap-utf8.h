#ifndef WLDAP_UTF8_H_
#define WLDAP_UTF8_H_

/*****************************************************************************
* These functions and structs are (mostly) redefinitions of the used WinLDAP
* functions and structs in the extension, but instead using either ANSI or
* UTF-16 encoded character string, all of the functions expect and return
* narrow UTF-8 encoded values. The inputs are encoded to wide UTF-16 format
* before the corresponding wide function (that supports unicode) is explicitly
* called. The returned values are decoded back to UTF-8. Some of the functions
* are renamed or their signatures are changed to match with the ones defined
* in the OpenLDAP's API. The disadvantage of this approach is that the
* conversations generate extra overhead for every LDAP operations on Windows,
* but better platform independent unicode support can be achieved without
* breaking the rest of the codebase's integrity with platfrom dependent code.
******************************************************************************/
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__)

#define UNICODE 1

#include <windows.h>
#include <winldap.h>
#include <winber.h>

#define SECURITY_WIN32 1

#include <security.h>
#include <Sspi.h>

/* These fields are differed from the ones in the OpenLDAP. */
#define attributeType sk_attrtype
#define orderingRule sk_matchruleoid
#define reverseOrder sk_reverseorder

#define attributeType sk_attrtype
#define timeval l_timeval

#define LDAP_OPT_X_TLS_PACKAGE 0x6011

#define LDAP_CONTROL_PAGEDRESULTS "1.2.840.113556.1.4.319"
#define LDAP_CONTROL_PASSWORDPOLICYREQUEST "1.3.6.1.4.1.42.2.27.8.5.1"
#define LDAP_CONTROL_PASSWORDPOLICYRESPONSE "1.3.6.1.4.1.42.2.27.8.5.1"
#define LDAP_CONTROL_SORTRESPONSE "1.2.840.113556.1.4.474"
#define LDAP_CONTROL_MANAGEDSAIT "2.16.840.1.113730.3.4.2"

/* All of the used WinLDAP macros are redefined. */
#undef LDAPControl
#undef LDAPMod
#undef LDAPSortKey

#undef LDAPAPIInfo

#undef ldap_create_page_control
#undef ldap_control_free
#undef ldap_controls_free
#undef ldap_create_vlv_control

#undef ldap_get_dn
#undef ldap_add_ext
#undef ldap_modify_ext
#undef ldap_delete_ext
#undef ldap_first_attribute
#undef ldap_next_attribute
#undef ldap_get_values_len
#undef ldap_rename
#undef ldap_search_ext
#undef ldap_create_sort_control
#undef ldap_extended_operation
#undef ldap_parse_extended_result
#undef ldap_parse_reference
#undef ldap_parse_result
#undef ldap_err2string
#undef ldap_memfree
#undef ldap_start_tls_s
#undef ldap_simple_bind_s

#undef ldap_get_option

#define LDAPControl LDAPControlA
#define LDAPMod LDAPModA
#define LDAPSortKey LDAPSortKeyA

#define LDAPAPIInfo LDAPAPIInfoA

#define ldap_create_page_control ldap_create_page_controlA
#define ldap_create_sort_control ldap_create_sort_controlA
#define ldap_control_free ldap_control_freeA

#define ldap_get_dn ldap_get_dnU
#define ldap_add_ext ldap_add_extU
#define ldap_modify_ext ldap_modify_extU
#define ldap_delete_ext ldap_delete_extU
#define ldap_first_attribute ldap_first_attributeU
#define ldap_next_attribute ldap_next_attributeU
#define ldap_get_values_len ldap_get_values_lenU
#define ldap_rename ldap_renameU
#define ldap_search_ext ldap_search_extU
#define ldap_extended_operation ldap_extended_operationU
#define ldap_parse_extended_result ldap_parse_extended_resultU
#define ldap_parse_result ldap_parse_resultU
#define ldap_err2string ldap_err2stringU
/* Simple free is sufficed, because no WinLDAP dependent allocation
   should be kept outside of the scope of the new functions. */
#define ldap_memfree free
#define ldap_start_tls ldap_start_tlsU
#define ldap_start_tls_s ldap_start_tls_sU
#define ldap_simple_bind_s ldap_simple_bind_sU
#define ldap_controls_free ldap_controls_freeU
#define ldap_create_vlv_control ldap_create_vlv_controlU
#define ldap_parse_vlvresponse_control ldap_parse_vlvresponse_controlU
#define ldap_create_passwordpolicy_control ldap_create_passwordpolicy_controlU
#define ldap_parse_passwordpolicy_control ldap_parse_passwordpolicy_controlU
#define ldap_parse_sortresponse_control ldap_parse_sortresponse_controlU
#define ldap_parse_reference ldap_parse_referenceU

/* These functions are not represented in the WinLDAP API. */
#define ldap_parse_pageresponse_control(ld, ctrls, count, cookie) ldap_parse_pageresponse_controlU(ld, ctrls, count, &(cookie))
#define ldap_control_create ldap_control_createU
#define ldap_control_find ldap_control_findU
#define ldap_initialize ldap_initializeU
#define ldap_sasl_sspi_bind_s ldap_sasl_sspi_bind_sU
#define _ldap_get_opt_errormsg _ldap_get_opt_errormsgU

#define ldap_get_option ldap_get_optionU

typedef struct sasl_defaults_s {
    char *authcid;
    char *passwd;
    char *realm;
    char *authzid;
} sasl_defaults_t;

typedef struct ldap_tls_data_s {
    LDAP *ld;
    LDAPControlA **serverctrls;
    LDAPControlA **clientctrls;
} ldap_tls_data_t;

int ldap_unbind_ext(LDAP *ld, LDAPControlA **sctrls, LDAPControlA **cctrls);
int ldap_abandon_ext(LDAP *ld, int msgid, LDAPControlA **sctrls, LDAPControlA **cctrls);
char *ldap_get_dnU(LDAP *ld, LDAPMessage *entry);
int ldap_add_extU(LDAP *ld, char *dn, LDAPModA **attrs, LDAPControlA **sctrls, LDAPControlA **cctrls, int *msgidp);
int ldap_modify_extU(LDAP *ld, char *dn, LDAPModA **attrs, LDAPControlA **sctrls, LDAPControlA **cctrls, int *msgidp);
int ldap_delete_extU(LDAP *ld, char *dn, LDAPControlA **sctrls, LDAPControlA **cctrls, int *msgidp);
char *ldap_first_attributeU(LDAP *ld, LDAPMessage *entry, BerElement **ber);
char *ldap_next_attributeU(LDAP *ld, LDAPMessage *entry, BerElement *ber);
struct berval **ldap_get_values_lenU(LDAP *ld, LDAPMessage *entry, char *target);
int ldap_renameU(LDAP *ld, char *dn, char *newrdn, char *newSuperior, int deleteoldrdn, LDAPControlA **sctrls, LDAPControlA **cctrls, int *msgidp);
int ldap_search_extU(LDAP *ld, char *base, int scope, char *filter, char **attrs, int attrsonly, LDAPControlA **sctrls, LDAPControlA **cctrls, struct timeval *timeout, int sizelimit, int *msgidp);
int ldap_extended_operationU(LDAP *ld, char *reqoid, struct berval *reqdata, LDAPControlA **sctrls, LDAPControlA **cctrls, int *msgidp);
int ldap_parse_extended_resultU(LDAP *ld, LDAPMessage *res, char **retoidp, struct berval **retdatap, int freeit);
int ldap_parse_pageresponse_controlU(LDAP *ld, LDAPControlA **ctrls, ber_int_t *count, struct berval **cookie);
int ldap_control_createU(char *requestOID, int iscritical, struct berval *value, int dupval, LDAPControlA **ctrlp);
LDAPControlA **ldap_control_findU(char *oid, LDAPControlA **ctrls, LDAPControlA ***nextctrlp);
int ldap_parse_sortresponse_controlU(LDAP *ld, LDAPControlA **ctrls, ber_int_t *result, char **attribute);
int ldap_create_vlv_controlU(LDAP *ld, LDAPVLVInfo *vlvinfo, LDAPControlA **ctrl);
int ldap_parse_vlvresponse_controlU(LDAP *ld, LDAPControlA **ctrls, long int *target_posp, long int *list_countp, struct berval **contextp, int *errcodep);
int ldap_parse_referenceU(LDAP *ld, LDAPMessage *reference, char ***referralsp, LDAPControlA ***serverctrlsp, int freeit);
int ldap_create_passwordpolicy_controlU(LDAP *ld, LDAPControlA **ctrlp);
int ldap_parse_passwordpolicy_controlU(LDAP *ld, LDAPControlA **ctrls, ber_int_t *expirep, ber_int_t *gracep, unsigned int *errorp);
int ldap_parse_resultU(LDAP *ld, LDAPMessage *res, int *errcodep, char **matcheddnp, char **errmsgp, char ***referralsp, LDAPControlA ***sctrls, int freeit);
char *ldap_err2stringU(int err);
int ldap_initializeU(LDAP **ldp, char *url);
int ldap_start_tlsU(LDAP *ld, LDAPControlA **serverctrls, LDAPControlA **clientctrls, HANDLE *msgidp);
int ldap_start_tls_sU(LDAP *ld, LDAPControlA **sctrls, LDAPControlA **cctrls);
int ldap_simple_bind_sU(LDAP *ld, char *who, char *passwd);
void ldap_controls_freeU(LDAPControlA **ctrls);
int ldap_sasl_sspi_bind_sU(LDAP *ld, char *dn, char *mechanism, LDAPControlA **sctrls, LDAPControlA **cctrls, void *defaults);
int ldap_get_optionU(LDAP *ld, int option, void *outvalue);
char *_ldap_get_opt_errormsgU(LDAP *ld);

#endif

#endif /* WLDAP_UTF8_H_ */