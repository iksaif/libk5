/* This file is part of libk5
 *
 * Copyright (C) 2009-2010 commonIT
 *
 * Author: Corentin Chary <cchary@commonit.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

/*
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>

#include "k5_priv.h"

static void
k5_parse_ticket_flags(k5_ticket *ticket)
{
    krb5_creds *cred = ticket->creds;
    int i = 0;

    if (cred->ticket_flags & TKT_FLG_FORWARDABLE)
	ticket->flags[i++] = 'F';
    if (cred->ticket_flags & TKT_FLG_FORWARDED)
	ticket->flags[i++] = 'f';
    if (cred->ticket_flags & TKT_FLG_PROXIABLE)
	ticket->flags[i++] = 'P';
    if (cred->ticket_flags & TKT_FLG_PROXY)
	ticket->flags[i++] = 'p';
    if (cred->ticket_flags & TKT_FLG_MAY_POSTDATE)
	ticket->flags[i++] = 'D';
    if (cred->ticket_flags & TKT_FLG_POSTDATED)
	ticket->flags[i++] = 'd';
    if (cred->ticket_flags & TKT_FLG_INVALID)
	ticket->flags[i++] = 'i';
    if (cred->ticket_flags & TKT_FLG_RENEWABLE)
	ticket->flags[i++] = 'R';
    if (cred->ticket_flags & TKT_FLG_INITIAL)
	ticket->flags[i++] = 'I';
    if (cred->ticket_flags & TKT_FLG_HW_AUTH)
	ticket->flags[i++] = 'H';
    if (cred->ticket_flags & TKT_FLG_PRE_AUTH)
	ticket->flags[i++] = 'A';
    if (cred->ticket_flags & TKT_FLG_TRANSIT_POLICY_CHECKED)
	ticket->flags[i++] = 'T';
    if (cred->ticket_flags & TKT_FLG_OK_AS_DELEGATE)
	ticket->flags[i++] = 'O';		/* D/d are taken.  Use short strings?  */
    if (cred->ticket_flags & TKT_FLG_ANONYMOUS)
	ticket->flags[i++] = 'a';
    ticket->flags[i] = '\0';
}

static void
k5_parse_ticket_etypes(k5_ticket *ticket)
{
    krb5_enctype enctype;

    enctype = ticket->creds->keyblock.enctype;

    if (krb5_enctype_to_string(enctype, ticket->key_enc,
			       sizeof(ticket->key_enc)))
      sprintf(ticket->key_enc, "etype %d", enctype);

    enctype = ticket->ticket->enc_part.enctype;

    if (krb5_enctype_to_string(enctype, ticket->ticket_enc,
			       sizeof(ticket->ticket_enc)))
      sprintf(ticket->ticket_enc, "etype %d", enctype);
}

static krb5_error_code
k5_parse_ticket(k5_context k5, krb5_creds *creds,
		krb5_ticket *ticket, k5_ticket *t)
{
  krb5_error_code code;
  char *name, *sname;

  code = krb5_unparse_name(k5->ctx, creds->client, &name);
  if (code) {
    com_err("k5_parse_ticket", code, "while unparsing client name");
    return code;
  }
  code = krb5_unparse_name(k5->ctx, creds->server, &sname);
  if (code) {
    com_err("k5_parse_ticket", code, "while unparsing server name");
    krb5_free_unparsed_name(k5->ctx, name);
    return code;
  }
  if (!creds->times.starttime)
    creds->times.starttime = creds->times.authtime;

  memset(t, 0, sizeof (*t));

  t->client_name = strdup(name);
  t->server_name = strdup(sname);
  t->data = creds->ticket.data;
  t->data_size = creds->ticket.length;
  t->authtime = creds->times.authtime;
  t->starttime = creds->times.starttime;
  t->endtime = creds->times.endtime;
  t->renew_till = creds->times.renew_till;
  t->ticket = ticket;
  t->creds = creds;

  k5_parse_ticket_flags(t);
  k5_parse_ticket_etypes(t);

  krb5_free_unparsed_name(k5->ctx, name);
  krb5_free_unparsed_name(k5->ctx, sname);
  return 0;
}

/**
 * @fn krb5_error_code k5_init_context(k5_context *k5p, const char *cache)
 * @brief Initialize k5_context
 * @param k5p libk5 context
 * @param cache optional cache, set to NULL to use default
 * @return 0 on success; otherwise returns an error code
 * @sa k5_free_context
 */
krb5_error_code K5_EXPORT
k5_init_context(k5_context *k5p, const char *cache)
{
  krb5_error_code code = 0;
  k5_context k5;

  assert(k5p);

  *k5p = malloc(sizeof (struct _k5_context));
  k5 = *k5p;

  if (!k5)
    return ENOMEM;

  memset(k5, 0, sizeof (struct _k5_context));

  code = krb5_init_context(&k5->ctx);

  if (code)
    goto cleanup;

  if (cache) {
    if ((code = krb5_cc_resolve(k5->ctx, cache, &k5->cc))) {
      com_err("k5_init_context", code, "resolving ccache %s", cache);
      goto cleanup;
    }
  } else {
    if ((code = krb5_cc_default(k5->ctx, &k5->cc))) {
      com_err("k5_init_context", code, "while getting default ccache");
      goto cleanup;
    }
  }

  return 0;

 cleanup:
  if (k5->cc)
    krb5_cc_close(k5->ctx, k5->cc);
  if (k5->ctx)
    krb5_free_context(k5->ctx);
  free(k5);
  return code;
}

krb5_error_code
k5_free_context(k5_context k5)
{
  if (!k5)
    return 0;

  if (k5->cc)
    krb5_cc_close(k5->ctx, k5->cc);
  if (k5->ctx)
    krb5_free_context(k5->ctx);
  free(k5);
  return 0;
}

void K5_EXPORT
k5_set_verbose(k5_context k5, int enabled)
{
  assert(k5);

  k5->verbose = enabled;
}


krb5_error_code K5_EXPORT
k5_kinit(k5_context k5, k5_kinit_req *req, k5_ticket *k5_ticket)
{
  krb5_error_code code = 0;
  krb5_creds creds, *ccreds;
  krb5_ticket *ticket = NULL;
  krb5_get_init_creds_opt *options = NULL;
  krb5_principal me = NULL;
  char* name = NULL;

  /* Client creds.client field */
  memset(&creds, 0, sizeof(creds));

  assert(k5);

  if (k5->verbose) {
    fprintf(stderr, "kinit(principal: %s, service: %s)\n",
	    req->principal_name ? req->principal_name : "<default>",
	    req->service_name ? req->service_name : "<none>");
  }


  if (req->principal_name)
    {
      /* Use specified name */
      if ((code = krb5_parse_name(k5->ctx, req->principal_name, &me))) {
	com_err("k5_kinit", code, "when parsing name %s",
		req->principal_name);
	return code;
      }
    }
  else
    {
      /* Get default principal from cache if one exists */
      if ((code = krb5_cc_get_principal(k5->ctx, k5->cc, &me))) {
	com_err("k5_kinit", code, "when parsing name %s",
		req->principal_name);
	return code;
      }
    }

  code = krb5_unparse_name(k5->ctx, me, &name);
  if (code) {
    com_err("k5_kinit", code, "when unparsing name");
    return code;
  }

  code = krb5_get_init_creds_opt_alloc(k5->ctx, &options);
  if (code)
    goto cleanup;
  memset(&creds, 0, sizeof(creds));

  if (req->lifetime)
    krb5_get_init_creds_opt_set_tkt_life(options, req->lifetime);
  if (req->rlife)
    krb5_get_init_creds_opt_set_renew_life(options, req->rlife);
  if (req->forwardable)
    krb5_get_init_creds_opt_set_forwardable(options, 1);
  if (req->not_forwardable)
    krb5_get_init_creds_opt_set_forwardable(options, 0);
  if (req->proxiable)
    krb5_get_init_creds_opt_set_proxiable(options, 1);
  if (req->not_proxiable)
    krb5_get_init_creds_opt_set_proxiable(options, 0);

  switch (req->action) {
  case K5_KINIT_PW:
    code = krb5_get_init_creds_password(k5->ctx, &creds, me,
					0, req->prompter, 0,
					req->starttime,
					req->service_name,
					options);
    break;
  case K5_VALIDATE:
    code = krb5_get_validated_creds(k5->ctx, &creds, me, k5->cc,
				    req->service_name);
    break;
  case K5_RENEW:
    code = krb5_get_renewed_creds(k5->ctx, &creds, me, k5->cc,
				  req->service_name);
    break;
  }

  if (code) {
    char *doing = 0;

    switch (req->action) {
    case K5_KINIT_PW:
      doing = "getting initial credentials";
      break;
    case K5_VALIDATE:
      doing = "validating credentials";
      break;
    case K5_RENEW:
      doing = "renewing credentials";
      break;
    }

    if (code == KRB5KRB_AP_ERR_BAD_INTEGRITY)
      com_err("k5_kinit", EINVAL, "password incorrect while %s\n",
	      doing);
    else
      com_err("k5_kinit", code, "while %s", doing);
    goto cleanup;
  }

  code = krb5_cc_initialize(k5->ctx, k5->cc, me);
  if (code) {
    com_err("k5_kinit", code, "when initializing cache");
    goto cleanup;
  }

  code = krb5_cc_store_cred(k5->ctx, k5->cc, &creds);
  if (code) {
    com_err("k5_kinit", code, "while storing credentials");
    goto cleanup;
  }

  if (!k5_ticket)
    goto cleanup;

  if ((code = krb5_copy_creds(k5->ctx, &creds, &ccreds))) {
    com_err("k5_kinit", code, "while copying credentials");
    goto cleanup;
  }

  if ((code = krb5_decode_ticket(&creds.ticket, &ticket))) {
    krb5_free_creds(k5->ctx, ccreds);
    goto cleanup;
  }

  if ((code = k5_parse_ticket(k5, ccreds, ticket, k5_ticket))) {
    krb5_free_creds(k5->ctx, ccreds);
    krb5_free_ticket(k5->ctx, ticket);
    goto cleanup;
  }

 cleanup:
  if (options)
    krb5_get_init_creds_opt_free(k5->ctx, options);
  if (creds.client == me) {
    creds.client = 0;
  }
  krb5_free_cred_contents(k5->ctx, &creds);
  if (name)
    krb5_free_unparsed_name(k5->ctx, name);
  if (me)
    krb5_free_principal(k5->ctx, me);
  return code;
}

#if defined(_WIN32)
static gss_OID_desc gss_c_nt_hostbased_service =
    { 10, (void *) "\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x04" };
#define GSS_C_NT_HOSTBASED_SERVICE &gss_c_nt_hostbased_service
#endif

krb5_error_code K5_EXPORT
k5_get_service_ticket_gss(k5_context k5, const char *service,
			  const char *hostname,
			  k5_ticket *ticket)
{
  krb5_error_code code;
  OM_uint32 min;
  OM_uint32 maj;
  gss_buffer_desc buf, otoken;
  gss_buffer_t itoken;
  gss_name_t gss_name;
  gss_cred_id_t credh;
  char *name;
  gss_ctx_id_t ctx;

  assert(service);
  assert(ticket);

  if ((code = k5_get_service_ticket(k5, service, hostname, ticket)))
    return code;

  name = malloc(strlen(service) + strlen(hostname) + 2);
  if (!name) {
    code = -ENOMEM;
    goto cleanup;
  }

  strcpy(name, service);
  strcat(name, "@");
  strcat(name, hostname);

  buf.value = name;
  buf.length = strlen(name) + 1;
  maj = gss_import_name(&min, &buf, GSS_C_NT_HOSTBASED_SERVICE, &gss_name);

  if (maj != GSS_S_COMPLETE) {
    code = min;
    goto cleanup;
  }

  maj = gss_acquire_cred(&min, GSS_C_NO_NAME, GSS_C_INDEFINITE,
			 GSS_C_NO_OID_SET, GSS_C_INITIATE,
			 &credh, NULL, NULL);

  if (maj != GSS_S_COMPLETE) {
    code = min;
    goto cleanup;
  }

  itoken = GSS_C_NO_BUFFER;
  ctx = GSS_C_NO_CONTEXT;
  maj = gss_init_sec_context(&min,
			     credh,
			     &ctx,
			     gss_name,
			     GSS_C_NO_OID,
			     GSS_C_CONF_FLAG,
			     0,
			     GSS_C_NO_CHANNEL_BINDINGS,
			     itoken,
			     NULL,
			     &otoken,
			     NULL,
			     NULL);
  if (maj != GSS_S_COMPLETE) {
    code = min;
    goto cleanup;
  }

  ticket->gss_data_size = otoken.length;
  ticket->gss_data = malloc(otoken.length);

  if (!ticket->gss_data) {
    code = -ENOMEM;
    goto cleanup;
  }

  memcpy(ticket->gss_data, otoken.value, otoken.length);
  k5_b64enc_ticket(ticket);

 cleanup:
   if (code) {
     k5_clear_ticket(k5, ticket);
   }
   gss_release_cred(&min, &credh);
   gss_release_buffer(&min, &otoken);
   gss_release_name(&min, &gss_name);
   gss_delete_sec_context(&min, &ctx, GSS_C_NO_BUFFER);

   free(name);
   return code;
}

static krb5_error_code
k5_get_service_ticket_internal(k5_context k5, const char *service,
		      const char *hostname, k5_ticket *k5_ticket)
{
  krb5_error_code code = 0;
  krb5_principal me;
  krb5_creds in_creds, *out_creds = NULL;
  krb5_ticket *ticket = NULL;
  char *princ = NULL;

  assert(k5);
  assert(hostname);

  code = krb5_cc_get_principal(k5->ctx, k5->cc, &me);
  if (code) {
    com_err("k5_get_service_ticket", code, "while getting client principal name");
    return code;
  }

  memset(&in_creds, 0, sizeof(in_creds));
  in_creds.client = me;
  in_creds.keyblock.enctype = 0;

  if (service != NULL) {
    code = krb5_sname_to_principal(k5->ctx, hostname,
				   service, KRB5_NT_SRV_HST,
				   &in_creds.server);
  } else {
    code = krb5_parse_name(k5->ctx, hostname, &in_creds.server);
  }

  if (code) {
    com_err("k5_get_service_ticket", code, "while parsing principal name %s",
	    hostname);
    goto cleanup;
  }

  code = krb5_unparse_name(k5->ctx, in_creds.server, &princ);

  if (code) {
    com_err("k5_get_service_ticket", code,
	    "while formatting parsed principal name for '%s'",
	    hostname);
    goto cleanup;
  }

  code = krb5_get_credentials(k5->ctx, 0, k5->cc, &in_creds, &out_creds);

  if (code) {
    com_err("k5_get_service_ticket", code, "while getting credentials for %s",
	    princ);
    goto cleanup;
  }

  if (!k5_ticket)
    goto cleanup;

  if ((code = krb5_decode_ticket(&out_creds->ticket, &ticket)))
    goto cleanup;

  if ((code = k5_parse_ticket(k5, out_creds, ticket, k5_ticket)))
    goto cleanup;

  krb5_free_principal(k5->ctx, in_creds.server);
  krb5_free_unparsed_name(k5->ctx, princ);
  krb5_free_principal(k5->ctx, me);
  return code;

 cleanup:
  if (ticket)
    krb5_free_ticket(k5->ctx, ticket);
  if (out_creds)
    krb5_free_creds(k5->ctx, out_creds);
  if (in_creds.server)
    krb5_free_principal(k5->ctx, in_creds.server);
  if (princ)
    krb5_free_unparsed_name(k5->ctx, princ);
  if (me)
    krb5_free_principal(k5->ctx, me);

  return code;
}

krb5_error_code K5_EXPORT
k5_get_service_ticket(k5_context k5, const char *service,
		      const char *hostname,
		      k5_ticket *k5_ticket)
{
  krb5_error_code code;
  krb5_principal me = NULL;
  char *sname = NULL;
  size_t len;

  assert(k5);
  assert(hostname);

  /* First, try like the used asked us */
  code = k5_get_service_ticket_internal(k5, service, hostname, k5_ticket);
  if (!code)
    return code;

  /*
   * if it fails, try to append default principal's realm
   * this is really a hack, but seems to be needed on some
   * (misconfigured ?) AD
   */

   /*
   * only hostname was specified, use know what he is doing,
   * don't try to append realm
   */
  if (!service)
    return code;

  code = krb5_cc_get_principal(k5->ctx, k5->cc, &me);
  if (code) {
    com_err("k5_get_service_ticket", code, "while getting client principal name");
    return code;
  }

  /* Check that we can really try to append the realm */
  if (!krb5_princ_realm(k5->ctx, me)->length)
    return code;
  len = strlen(service) + strlen("/") + strlen(hostname) + strlen("@") +
        krb5_princ_realm(k5->ctx, me)->length + 1;
  sname = malloc(len);
  if (!sname)
    goto cleanup;

  memset(sname, 0, len);
  strcpy(sname, service);
  strcat(sname, "/");
  strcat(sname, hostname);
  strcat(sname, "@");
  strncat(sname, krb5_princ_realm(k5->ctx, me)->data,
          krb5_princ_realm(k5->ctx, me)->length);

  code = k5_get_service_ticket_internal(k5, NULL, sname, k5_ticket);
cleanup:
  if (me)
    krb5_free_principal(k5->ctx, me);
  free(sname);
  return code;
}

krb5_error_code K5_EXPORT
k5_klist(k5_context k5, k5_klist_entries *rep)
{
  krb5_cc_cursor cur;
  krb5_creds creds;
  krb5_principal princ = NULL;
  krb5_flags flags;
  krb5_error_code code;
  char *defname = NULL;

  assert(k5);
  assert(k5->ctx);
  assert(k5->cc);
  assert(rep);

  memset(rep, 0, sizeof (*rep));

  flags = 0;				/* turns off OPENCLOSE mode */
  if ((code = krb5_cc_set_flags(k5->ctx, k5->cc, flags))) {
    if (code == KRB5_FCC_NOFILE) {
      com_err("k5_klist", code, "(ticket cache %s:%s)",
	      krb5_cc_get_type(k5->ctx, k5->cc),
	      krb5_cc_get_name(k5->ctx, k5->cc));
    } else {
      com_err("k5_klist", code,
	      "while setting cache flags (ticket cache %s:%s)",
	      krb5_cc_get_type(k5->ctx, k5->cc),
	      krb5_cc_get_name(k5->ctx, k5->cc));
    }
    goto cleanup;
  }

  if ((code = krb5_cc_get_principal(k5->ctx, k5->cc, &princ))) {
    com_err("k5_klist", code, "while retrieving principal name");
    goto cleanup;
  }

  if ((code = krb5_unparse_name(k5->ctx, princ, &defname))) {
    com_err("k5_klist", code, "while unparsing principal name");
    goto cleanup;
  }

  if ((code = krb5_cc_start_seq_get(k5->ctx, k5->cc, &cur))) {
    com_err("k5_klist", code, "while starting to retrieve tickets");
    goto cleanup;
  }

  while (!(code = krb5_cc_next_cred(k5->ctx, k5->cc, &cur, &creds))) {
    krb5_creds *ccreds = NULL;
    krb5_ticket *ticket = NULL;

    rep->count++;
    rep->tickets = realloc(rep->tickets, sizeof (*rep->tickets) * rep->count);

    if ((code = krb5_copy_creds(k5->ctx, &creds, &ccreds))) {
      krb5_free_cred_contents(k5->ctx, &creds);
      com_err("k5_klist", code, "while copying creds");
      continue ;
    }

    if ((code = krb5_decode_ticket(&ccreds->ticket, &ticket))) {
      com_err("k5_klist", code, "while decoding ticket");
      krb5_free_creds(k5->ctx, ccreds);
      krb5_free_cred_contents(k5->ctx, &creds);
      continue ;
    }

    k5_parse_ticket(k5, ccreds, ticket, &rep->tickets[rep->count - 1]);

    krb5_free_cred_contents(k5->ctx, &creds);
  }

  if (code == KRB5_CC_END) {
    if ((code = krb5_cc_end_seq_get(k5->ctx, k5->cc, &cur))) {
      com_err("k5_klist", code, "while finishing ticket retrieval");
      goto cleanup;
    }
    flags = KRB5_TC_OPENCLOSE;	/* turns on OPENCLOSE mode */
    if ((code = krb5_cc_set_flags(k5->ctx, k5->cc, flags))) {
      com_err("k5_klist", code, "while closing ccache");
      goto cleanup;
    }
  } else {
    com_err("k5_klist", code, "while retrieving a ticket");
    goto cleanup;
  }

  rep->defname = strdup(defname);

 cleanup:
  if (defname)
    krb5_free_unparsed_name(k5->ctx, defname);
  if (princ)
    krb5_free_principal(k5->ctx, princ);

  if (code)
    k5_clear_klist(k5, rep);

  return code;
}

krb5_error_code K5_EXPORT
k5_kdestroy(k5_context k5)
{
  krb5_error_code code;

  assert(k5);
  assert(k5->ctx);
  assert(k5->cc);

  code = krb5_cc_destroy (k5->ctx, k5->cc);
  if (code != 0) {
    com_err ("k5_kdestroy", code, "while destroying cache");
    if (code != KRB5_FCC_NOFILE) {
      if (k5->verbose)
	fprintf(stderr, "Ticket cache NOT destroyed!\n");
    }
  }

  k5->cc = NULL;

  return code;
}

krb5_error_code K5_EXPORT
k5_clear_ticket(k5_context k5, k5_ticket *ticket)
{
  assert(k5);
  assert(k5->ctx);
  assert(k5->cc);

  if (!ticket)
    return 0;

  free(ticket->client_name);
  free(ticket->server_name);
  free(ticket->gss_data);
  free(ticket->gss_base64);

  krb5_free_creds(k5->ctx, ticket->creds);
  krb5_free_ticket(k5->ctx, ticket->ticket);

  memset(ticket, 0, sizeof (*ticket));
  return 0;
}

krb5_error_code K5_EXPORT
k5_clear_klist(k5_context k5, k5_klist_entries *klist)
{
  int i;

  assert(k5);
  assert(k5->ctx);
  assert(k5->cc);

  if (!klist)
    return 0;

  free(klist->defname);

  for (i = 0; i < klist->count; ++i)
    k5_clear_ticket(k5, &klist->tickets[i]);
  free(klist->tickets);

  memset(klist, 0, sizeof (*klist));
  return 0;
}
