#ifndef PYLDAP_WLDAP_UTF8_H_
#define PYLDAP_WLDAP_UTF8_H_

#include <Python.h>

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__)

#include <windows.h>
#include <winldap.h>
#include <winber.h>

#define SECURITY_WIN32 1

#include <security.h>
#include <Sspi.h>

#define attributeType sk_attrtype
#define orderingRule sk_matchruleoid
#define reverseOrder sk_reverseorder

#define attributeType sk_attrtype
#define timeval l_timeval

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
#undef ldap_parse_result
#undef ldap_err2string
#undef ldap_memfree

#define ldap_get_dn ldap_get_dnU
#define ldap_add_ext ldap_add_extU
#define ldap_modify_ext ldap_modify_extU
#define ldap_delete_ext ldap_delete_extU
#define ldap_first_attribute ldap_first_attributeU
#define ldap_next_attribute ldap_next_attributeU
#define ldap_get_values_len ldap_get_values_lenU
#define ldap_rename ldap_renameU
#define ldap_search_ext ldap_search_extU
#define ldap_create_sort_control ldap_create_sort_controlU
#define ldap_extended_operation ldap_extended_operationU
#define ldap_parse_extended_result ldap_parse_extended_resultU
#define ldap_parse_result ldap_parse_resultU
#define ldap_err2string ldap_err2stringU
#define ldap_memfree free

typedef struct sasl_defaults_s {
	SEC_WINNT_AUTH_IDENTITY_W *creds;
	CredHandle *credhandle;
	CtxtHandle *ctxhandle;
} sasl_defaults_t;

typedef int(LDAP_SASL_INTERACT_PROC) (LDAP *ld, sasl_defaults_t *defaults, struct berval *response, struct berval *cred);

int ldap_unbind_ext(LDAP *ld, LDAPControl **sctrls, LDAPControl	**cctrls);
int ldap_abandon_ext(LDAP *ld, int msgid, LDAPControl **sctrls, LDAPControl	**cctrls);
char *ldap_get_dnU(LDAP *ld, LDAPMessage *entry);
int ldap_add_extU(LDAP *ld, char *dn, LDAPMod **attrs, LDAPControl **sctrls, LDAPControl **cctrls, int *msgidp);
int ldap_modify_extU(LDAP *ld, char *dn, LDAPMod **attrs, LDAPControl **sctrls, LDAPControl **cctrls, int *msgidp);
int ldap_delete_extU(LDAP *ld, char *dn, LDAPControl **sctrls, LDAPControl **cctrls, int *msgidp);
char *ldap_first_attributeU(LDAP *ld, LDAPMessage *entry, BerElement **ber);
char *ldap_next_attributeU(LDAP *ld, LDAPMessage *entry, BerElement *ber);
struct berval **ldap_get_values_lenU(LDAP *ld, LDAPMessage *entry, char *target);
int ldap_renameU(LDAP *ld, char *dn, char *newrdn, char *newSuperior, int deleteoldrdn, LDAPControl **sctrls, LDAPControl **cctrls, int *msgidp);
int ldap_search_extU(LDAP *ld, char *base, int scope, char *filter, char **attrs, int attrsonly, LDAPControl **sctrls, LDAPControl **cctrls, struct timeval *timeout, int sizelimit, int *msgidp);
int ldap_create_sort_controlU(LDAP *ld, LDAPSortKey **keyList, int iscritical, LDAPControl **ctrlp);
int ldap_extended_operationU(LDAP *ld, char *reqoid, struct berval *reqdata, LDAPControl **sctrls, LDAPControl **cctrls, int *msgidp);
int ldap_parse_extended_resultU(LDAP *ld, LDAPMessage *res, char **retoidp, struct berval **retdatap, int freeit);
int ldap_parse_pageresponse_controlU(LDAP *ld, LDAPControl *ctrl, ber_int_t *count, struct berval *cookie);
LDAPControl *ldap_control_findU(char *oid, LDAPControl **ctrls, LDAPControl ***nextctrlp);
int ldap_parse_resultU(LDAP *ld, LDAPMessage *res, int *errcodep, char **matcheddnp, char **errmsgp, char ***referralsp, LDAPControl ***sctrls, int freeit);
char *ldap_err2stringU(int err);
int ldap_simple_bind_sU(LDAP *ld, char *who, char *passwd);
int ldap_sasl_interactive_bind_sU(LDAP *ld, char *dn, char *mechanism, LDAPControl **sctrls, LDAPControl **cctrls, unsigned flags, LDAP_SASL_INTERACT_PROC *proc, void *defaults);

#endif

#endif /* PYLDAP_WLDAP_UTF8_H_ */