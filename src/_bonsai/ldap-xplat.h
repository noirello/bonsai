#ifndef LDAP_XPLAT_H_
#define LDAP_XPLAT_H_

#include <Python.h>

#ifdef WIN32
//MS Windows

#include <WinSock2.h>

#include "wldap-utf8.h"

#define XTHREAD HANDLE
#define FINDCTRL LDAPControl**

int _ldap_parse_passwordpolicy_control(LDAP *ld, LDAPControl **ctrls,
    ber_int_t *expire, ber_int_t *grace, unsigned int *error);

#else
//Unix
#include <ldap.h>
#include <lber.h>
#include <sasl/sasl.h>
#include <sys/time.h>
#include <pthread.h>
#include <sys/socket.h>

#ifdef HAVE_KRB5
#include <krb5.h>
#include <gssapi.h>
#include <gssapi/gssapi_krb5.h>
#endif

#define SOCKET int
#define XTHREAD pthread_t
#define FINDCTRL LDAPControl*

int sasl_interact(LDAP *ld, unsigned flags, void *defaults, void *in);
char *_ldap_get_opt_errormsg(LDAP *ld);
int _ldap_parse_passwordpolicy_control(LDAP *ld, LDAPControl *ctrl,
    ber_int_t *expire, ber_int_t *grace, unsigned int *error);
#endif

typedef struct ldap_conndata_s {
    char *binddn;
    char *mech;
    char *realm;
    char *authcid;
    char *passwd;
    char *authzid;
#ifdef WIN32
    /* For the Windows's thread. */
    LDAP *ld;
    HANDLE thread;
    SOCKET sock;
#else
#ifdef HAVE_KRB5
    krb5_context ctx;
    krb5_ccache ccache;
    gss_cred_id_t gsscred;
    char *errmsg;
    char request_tgt;
    char *ktname;
#endif
    char **resps;
    int nresps;
    const char *rmech;
#endif
} ldap_conndata_t;

typedef struct ldap_thread_data_s {
    LDAP *ld;
    char *url;
    char *sasl_sec_props;
    int referrals;
    int cert_policy;
    int retval;
    SOCKET sock;
#ifdef WIN32
#else
    /* For the POSIX's thread. */
    pthread_mutex_t *mux;
    int flag;
    ldap_conndata_t *info;
#endif
} ldapInitThreadData;

#define LDAP_SERVER_EXTENDED_DN_OID "1.2.840.113556.1.4.529"
#define LDAP_SERVER_TREE_DELETE_OID "1.2.840.113556.1.4.805"
#define LDAP_SERVER_SD_FLAGS_OID "1.2.840.113556.1.4.801"

int _ldap_finish_init_thread(char async, XTHREAD thread, int *timeout, void *misc, LDAP **ld);
int _ldap_bind(LDAP *ld, ldap_conndata_t *info, char ppolicy, LDAPMessage *result, int *msgid);
int _ldap_create_extended_dn_control(LDAP *ld, int format, LDAPControl **edn_ctrl);
int _ldap_create_sd_flags_control(LDAP *ld, int flags, LDAPControl **edn_ctrl);
void _ldap_control_free(LDAPControl *ctrl);

int create_init_thread(void *param, ldap_conndata_t *info, XTHREAD *thread);
void *create_conn_info(char *mech, SOCKET sock, PyObject *creds);
void dealloc_conn_info(ldap_conndata_t* info);

#endif /* LDAP_XPLAT_H_ */
