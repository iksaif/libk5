#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define SSIZE_T_DEFINED
#include <krb5.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include "kerberos.h"

#if defined(__WXMSW__) || defined(WIN32)
#define strdup _strdup
static gss_OID_desc gss_c_nt_hostbased_service =
    { 10, (void *) "\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x04" };
#define GSS_C_NT_HOSTBASED_SERVICE &gss_c_nt_hostbased_service
#endif

static krb5_error_code get_new_tickets(struct vb_krb5 *thiz,
                                krb5_context        context,
                                krb5_principal      principal,
                                krb5_ccache         ccache);
static size_t base64encode(char *dst, const char *src, size_t size);

enum vb_krb5_errno {
  VBKRB5_SUCCESS = 0,
  VBKRB5_UNKNOWN,
  KRB5_INITIALIZING,
  KRB5_PASSWORD_INCORECT,
  KRB5_INITIALIZING_CREDS,
  KRB5_OPENING_CCACHE,
  KRB5_INITIALIZING_CCACHE,
  KRB5_COPYING_CCACHE,
  KRB5_GETTING_PRINCIPAL,
  GSS_IMPORTING_NAME,
  GSS_ACQUIRING_CREDS,
  GSS_INITIALIZING_CREDS,
  MS_LSA_OPENING,
  MS_LSA_INITIALIZING,
  MS_LSA_NO_TGT,
  MS_LSA_GETTING_PRINCIPAL,
  MS_LSA_COPYING_CCACHE,
};

static const char *errstr[] =
  {
    "success",
    "unknown error",
    "while initializing kerberos library",
    "incorect password",
    "while initializing credentials (tgt)",
    "while getting default ccache",
    "when initializing ccache",
    "while storing credentials to ccache",
    "while obtaining default principal",
    "while importing service name",
    "while acquiring credentials (getting tgt)",
    "while initializing credentials (getting service ticket)",
    "while opening MS LSA ccache",
    "while initiating the cred sequence of MS LSA ccache",
    "Initial TGTs are not available from the MS LSA (registry modifications required)",
    "while obtaining MS LSA principal",
    "while copying MS LSA ccache to default ccache",
  };

struct vb_krb5
{
  char *realm;
  char *service;
  char *login;

  gss_name_t gss_name;
  gss_ctx_id_t ctx;
  gss_buffer_desc otoken;
  OM_uint32 min;

  gss_buffer_desc msg_gss;
  gss_buffer_desc msg_mech;
  enum vb_krb5_errno err;

  char *(*get_password)(void * data);
  void *get_password_data;
};

#if defined(__WXMSW__) || defined(WIN32)
/* Import MSLSA tokens */
static int vbkrb5_import_ms_tokens(struct vb_krb5 *thiz)
{
    krb5_context kcontext;
    krb5_error_code code;
    krb5_ccache ccache=NULL;
    krb5_ccache mslsa_ccache=NULL;
    krb5_cc_cursor cursor;
    krb5_creds creds;
    krb5_principal princ;
    int initial_ticket = 0;

    printf("Initialize kerberos context\n");
    code = krb5_init_context(&kcontext);
    if (code) {
        thiz->err = KRB5_INITIALIZING;
        return -1;
    }

    printf("Openning MSLSA cache\n");
    code = krb5_cc_resolve(kcontext, "MSLSA:", &mslsa_ccache);
    if (code) {
        thiz->err = MS_LSA_OPENING;
        krb5_free_context(kcontext);
        return -1;
    }

    /* Enumerate tickets from cache looking for an initial ticket */
    printf("Initiliaze MSLSA cache\n");
    code = krb5_cc_start_seq_get(kcontext, mslsa_ccache, &cursor);
    if (code) {
        thiz->err = MS_LSA_INITIALIZING;
        krb5_cc_close(kcontext, mslsa_ccache);
        krb5_free_context(kcontext);
        return -1;
    }

    while (!(code = krb5_cc_next_cred(kcontext, mslsa_ccache, &cursor, &creds)))
    {
        if ( creds.ticket_flags & TKT_FLG_INITIAL ) {
            krb5_free_cred_contents(kcontext, &creds);
            initial_ticket = 1;
            break;
        }
        krb5_free_cred_contents(kcontext, &creds);
    }
    krb5_cc_end_seq_get(kcontext, mslsa_ccache, &cursor);

    if ( !initial_ticket ) {
        thiz->err = MS_LSA_NO_TGT;
        krb5_cc_close(kcontext, mslsa_ccache);
        krb5_free_context(kcontext);
        return -1;
    }

    printf("Getting MSLSA principal\n");
    code = krb5_cc_get_principal(kcontext, mslsa_ccache, &princ);
    if (code) {
        thiz->err = MS_LSA_GETTING_PRINCIPAL;
        krb5_cc_close(kcontext, mslsa_ccache);
        krb5_free_context(kcontext);
        return -1;
    }

    printf("Openning default krb5 cache\n");
    code = krb5_cc_default(kcontext, &ccache);
    if (code) {
        thiz->err = KRB5_OPENING_CCACHE;
        krb5_free_principal(kcontext, princ);
        krb5_cc_close(kcontext, mslsa_ccache);
        krb5_free_context(kcontext);
        return -1;
    }

    printf("Initialize kerberos\n");
    code = krb5_cc_initialize(kcontext, ccache, princ);
    if (code) {
        thiz->err = KRB5_INITIALIZING_CCACHE;
        krb5_free_principal(kcontext, princ);
        krb5_cc_close(kcontext, mslsa_ccache);
        krb5_cc_close(kcontext, ccache);
        krb5_free_context(kcontext);
        return -1;
    }

    printf("Copying from MSLSA cache\n");
    code = krb5_cc_copy_creds(kcontext, mslsa_ccache, ccache);
    if (code) {
        thiz->err = MS_LSA_COPYING_CCACHE;
        krb5_free_principal(kcontext, princ);
        krb5_cc_close(kcontext, ccache);
        krb5_cc_close(kcontext, mslsa_ccache);
        krb5_free_context(kcontext);
        return -1;
    }

    krb5_free_principal(kcontext, princ);
    krb5_cc_close(kcontext, ccache);
    krb5_cc_close(kcontext, mslsa_ccache);
    krb5_free_context(kcontext);
    thiz->err = VBKRB5_SUCCESS;
    return 0;
}
#endif

void
vbkrb5_set_login(struct vb_krb5 *thiz, const char *login)
{
   if (thiz->login)
      free(thiz->login);

   if (login)
      thiz->login = strdup(login);
   else
      thiz->login = NULL;
}

void
vbkrb5_set_service(struct vb_krb5 *thiz, const char *service)
{
   if (thiz->service)
      free(thiz->service);

   if (service)
      thiz->service = strdup(service);
   else
      thiz->service = NULL;
}

void
vbkrb5_set_realm(struct vb_krb5 *thiz, const char *realm)
{
   if (thiz->realm)
      free(thiz->realm);

   if (realm)
     thiz->realm = strdup(realm);
   else
      thiz->realm = NULL;
}

/// @return 1 on success 0 on failure
int
vbkrb5_check_tokens(struct vb_krb5 *thiz)
{
  if (!vbkrb5_import_name(thiz))
    vbkrb5_init_context(thiz);

#if defined(__WXMSW__) || defined(WIN32)
  if (!thiz->otoken.value) {
    printf("No token found, trying to import ms tokens\n");
    if (!vbkrb5_import_ms_tokens(thiz))
      if (!vbkrb5_import_name(thiz))
	vbkrb5_init_context(thiz);
  }
#endif

  if (!thiz->otoken.value) {
    printf("No token found, trying to get a new TGT\n");
    if (thiz->login && !vbkrb5_init(thiz))
      if (!vbkrb5_import_name(thiz))
	vbkrb5_init_context(thiz);
  }

   if (thiz->otoken.value) {
     thiz->err = VBKRB5_SUCCESS;
     return 1;
   }
   return 0;
}

const char *
vbkrb5_get_otoken_value(struct vb_krb5 *thiz)
{
   return (const char *)thiz->otoken.value;
}

unsigned
vbkrb5_get_otoken_len(struct vb_krb5 *thiz)
{
   return thiz->otoken.length;
}

const char *
vbkrb5_get_otoken_base64(struct vb_krb5 *thiz)
{
    char *p;
    size_t size = vbkrb5_get_otoken_len(thiz);
    size_t bytes;

    printf("Converting token to base64\n");
    if (!vbkrb5_get_otoken_value(thiz) || !vbkrb5_get_otoken_len(thiz))
	return NULL;

    bytes = (2 + size - ((size + 2) % 3)) * 4 / 3;
    p = (char *)malloc(bytes + 2);
    size = base64encode(p, vbkrb5_get_otoken_value(thiz), size);
    p[size] = '\0';
    return (const char *)p;
}

static krb5_error_code
get_new_tickets(struct vb_krb5 *thiz,
                krb5_context        context,
                krb5_principal      principal,
                krb5_ccache         ccache)
{
   krb5_error_code               ret;
   krb5_get_init_creds_opt       opt;
   krb5_creds                    cred;
   char *                        password = NULL;

   printf("Getting a new TGT\n");
   memset(&cred, 0, sizeof(cred));
   krb5_get_init_creds_opt_init (&opt);
   /*krb5_get_init_creds_opt_set_default_flags(context, "kinit",
                                             principal->realm, &opt);*/
   if (thiz->get_password)
      password = thiz->get_password(thiz->get_password_data);
   ret = krb5_get_init_creds_password(context,
                                      &cred,
                                      principal,
                                      password,
                                      krb5_prompter_posix,
                                      NULL,
                                      0,
                                      NULL,
                                      &opt);
   free(password);
   if (ret == KRB5_LIBOS_PWDINTR ||
       ret == KRB5KRB_AP_ERR_MODIFIED ||
       ret == KRB5KRB_AP_ERR_BAD_INTEGRITY) {
     thiz->err = KRB5_PASSWORD_INCORECT;
     return (1);
   }
   else if (ret) {
     thiz->err = KRB5_INITIALIZING_CREDS;
     return (2);
   }
   if (krb5_cc_initialize(context, ccache, cred.client)) {
     thiz->err = KRB5_INITIALIZING_CCACHE;
     return (3);
   }
   if (krb5_cc_store_cred(context, ccache, &cred)) {
     thiz->err = KRB5_COPYING_CCACHE;
     return (3);
   }
   //krb5_free_creds_contents(context, &cred);
   thiz->err = VBKRB5_SUCCESS;
   return (0);
}

int
vbkrb5_init(struct vb_krb5 *thiz)
{
   krb5_error_code               ret;
   krb5_context                  context;
   krb5_ccache                   ccache;
   krb5_principal                principal;

   printf("Initializing kerberos\n");
   if (krb5_init_context(&context)) {
     thiz->err = KRB5_INITIALIZING;
     return (1);
   }
#ifndef __WXMSW__
   /*   if (!thiz->login)
	krb5SetLogin(getlogin());*/
#endif
   if (!thiz->login ||
       (krb5_build_principal(context, &principal, strlen(thiz->realm),
			     thiz->realm, thiz->login, NULL))) {
     thiz->err = KRB5_GETTING_PRINCIPAL;
     return (1);
   }
   if (krb5_cc_default(context, &ccache)) {
     thiz->err = KRB5_INITIALIZING_CCACHE;
     return (1);
   }

   ret = get_new_tickets(thiz, context, principal, ccache);
   krb5_cc_close(context, ccache);
   krb5_free_principal(context, principal);
   krb5_free_context(context);
   return (ret);
}

int
vbkrb5_import_name(struct vb_krb5 *thiz)
{
   OM_uint32		min;
   OM_uint32		maj;
   gss_buffer_desc	buf;

   printf("Importing name: %s\n", thiz->service);
   if (thiz->gss_name != GSS_C_NO_NAME)
       gss_release_name(&min, &thiz->gss_name);

   buf.value = (unsigned char *) strdup(thiz->service);
   buf.length = strlen((const char*)buf.value) + 1;
   maj = gss_import_name(&min, &buf, GSS_C_NT_HOSTBASED_SERVICE, &thiz->gss_name);

   if (maj != GSS_S_COMPLETE) {
     thiz->err = GSS_IMPORTING_NAME;
     vbkrb5_display_status(thiz);
     return -1;
   }
   thiz->err = VBKRB5_SUCCESS;
   return 0;
}

void
vbkrb5_init_context(struct vb_krb5 *thiz)
{
   OM_uint32	 maj;
   gss_buffer_t	 itoken      = GSS_C_NO_BUFFER;
   /*   krb5_enctype  etypes[]    = { ENCTYPE_DES_CBC_MD5, ENCTYPE_NULL }; */
   /*   int           etype_count = sizeof(etypes) / sizeof(*etypes); */
   gss_cred_id_t credh;

   printf("Getting a service ticket\n");
   maj = gss_acquire_cred(&thiz->min, GSS_C_NO_NAME, GSS_C_INDEFINITE,
                          GSS_C_NO_OID_SET, GSS_C_INITIATE, &credh, NULL, NULL);
   if (maj != GSS_S_COMPLETE) {
     thiz->err = GSS_ACQUIRING_CREDS;
     vbkrb5_display_status(thiz);
     return;
   }
/*
   maj = gss_krb5_set_allowable_enctypes(&thiz->min, credh, etype_count, etypes);
   if (maj != GSS_S_COMPLETE) {
       vbkrb5_display_status(thiz);
       return;
   }
*/
   thiz->ctx = GSS_C_NO_CONTEXT;
   maj = gss_init_sec_context(&thiz->min,
                              credh,
                              &thiz->ctx,
                              thiz->gss_name,
                              GSS_C_NO_OID,
                              GSS_C_CONF_FLAG,
                              0,
                              GSS_C_NO_CHANNEL_BINDINGS,
                              itoken,
                              NULL,
                              &thiz->otoken,
                              NULL,
                              NULL);
   if (maj != GSS_S_COMPLETE) {
     thiz->err = GSS_INITIALIZING_CREDS;
     vbkrb5_display_status(thiz);
     return ;
   }
   thiz->err = VBKRB5_SUCCESS;
}

void
vbkrb5_display_status(struct vb_krb5 *thiz)
{
   OM_uint32		minor;
   OM_uint32		status;

   gss_display_status(&minor, thiz->min, GSS_C_GSS_CODE,
		      GSS_C_NO_OID, &status, &thiz->msg_gss);
   if (thiz->msg_gss.value)
     fprintf(stderr, "gss: %s\n", (const char *)thiz->msg_gss.value);
   gss_display_status(&minor, thiz->min, GSS_C_MECH_CODE,
		      GSS_C_NO_OID, &status, &thiz->msg_mech);
   if (thiz->msg_mech.value)
     fprintf(stderr, "mech: %s\n", (const char *)thiz->msg_mech.value);
}

const char *
vbkrb5_gss_error(struct vb_krb5 *thiz)
{
  return (const char *)thiz->msg_gss.value;
}

const char *
vbkrb5_mech_error(struct vb_krb5 *thiz)
{
  return (const char *)thiz->msg_mech.value;
}

const char *vbkrb5_error(int err)
{
  if (err >= (sizeof(errstr) / sizeof(errstr[0])))
    return errstr[VBKRB5_UNKNOWN];
  return errstr[err];
}

int vbkrb5_errno(struct vb_krb5 *thiz)
{
  return thiz->err;
}

void
vbkrb5_set_password(struct vb_krb5 *thiz,
                   get_password_f      get_password,
                   void *              data)
{
   thiz->get_password = get_password;
   thiz->get_password_data = data;
}

struct vb_krb5 *
vbkrb5_alloc(void)
{
    struct vb_krb5 *k = (struct vb_krb5 *)calloc(sizeof (struct vb_krb5), 1);

    k->gss_name = GSS_C_NO_NAME;
    k->ctx = GSS_C_NO_CONTEXT;
    return k;
}

void
vbkrb5_clear(struct vb_krb5 *thiz)
{
    OM_uint32 min;

    if (!thiz)
	return ;
    if (thiz->realm)
	free (thiz->realm);
    if (thiz->service)
	free (thiz->service);
    if (thiz->login)
	free (thiz->login);
    if (thiz->otoken.length)
	gss_release_buffer(&min, &thiz->otoken);
    if (thiz->gss_name != GSS_C_NO_NAME)
	gss_release_name(&min, &thiz->gss_name);
    if (thiz->ctx != GSS_C_NO_CONTEXT)
	gss_delete_sec_context(&min, &thiz->ctx, GSS_C_NO_BUFFER);
    free(thiz);
}

char * vbkrb5_simple_password_cb(void * data)
{
    return strdup((char *)data);
}

static const char cb64[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void encodeblock( unsigned char in[3], unsigned char out[4], int len )
{
    out[0] = cb64[ in[0] >> 2 ];
    out[1] = cb64[ ((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4) ];
    out[2] = (unsigned char) (len > 1 ? cb64[ ((in[1] & 0x0f) << 2) | ((in[2] & 0xc0) >> 6) ] : '=');
    out[3] = (unsigned char) (len > 2 ? cb64[ in[2] & 0x3f ] : '=');
}

static size_t base64encode(char *dst, const char *src, size_t size)
{
  unsigned char in[3], out[4];
  int i, len;
  size_t bytes;

  bytes = 0;
  size++;
  while (size) {
    len = 0;
    for (i = 0; i < 3; i++ ) {
      if (size) {
	size--;
	if (size)
	  in[i] = (unsigned char) *src++;
      }
      if (size)
	len++;
      else
	in[i] = 0;
    }
    if (len) {
      encodeblock(in, out, len);
      memcpy(dst, out, 4);
      dst += 4;
      bytes += 4;
    }
  }
  return bytes;
}
