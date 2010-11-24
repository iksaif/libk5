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

#ifndef K5_H_
# define K5_H_

#ifdef WIN32
#  ifdef K5_MAKEDLL
#    define K5_EXPORT __declspec(dllexport)
#  else
#    define K5_EXPORT __declspec(dllimport)
#  endif
#else
#  define K5_EXPORT
#endif

#if defined(__MINGW32__)
/*
 * win-mac.h:92: error: expected '=', ',', ';', 'asm'
 *  or '__attribute__' before 'int'
 */
# include <unistd.h>
# define SSIZE_T_DEFINED
#endif


#include <krb5/krb5.h>

struct _k5_context {
  krb5_context ctx;
  krb5_ccache cc;
  int verbose;
};

typedef struct _k5_ticket {
  char *client_name;
  char *server_name;
  time_t authtime;
  time_t starttime;
  time_t endtime;
  time_t renew_till;
  krb5_ticket *ticket;
  krb5_creds *creds;
  char flags[32];
  char ticket_enc[100];
  char key_enc[100];
  char *data;
  size_t data_size;
  /* GSS */
  char *gss_data;
  size_t gss_data_size;
  char *gss_base64;
  size_t gss_base64_size;
} k5_ticket;

typedef struct _k5_klist_entries {
  char *defname;
  int count;
  k5_ticket *tickets;
} k5_klist_entries;


enum k5_kinit_action {
  K5_KINIT_PW,
  K5_VALIDATE,
  K5_RENEW,
};

typedef struct _k5_kinit_req {
  int action;
  int lifetime;
  int rlife;
  int starttime;
  int forwardable;
  int proxiable;
  int not_forwardable;
  int not_proxiable;
  char *principal_name;
  char *service_name;
  krb5_prompter_fct prompter;
} k5_kinit_req;

typedef struct _k5_context * k5_context;

krb5_error_code K5_EXPORT
k5_init_context(k5_context *k5, const char *cache);

krb5_error_code K5_EXPORT
k5_free_context(k5_context k5);

void K5_EXPORT
k5_set_verbose(k5_context k5, int enabled);

krb5_error_code K5_EXPORT
k5_kinit(k5_context k5, k5_kinit_req *req, k5_ticket *ticket);

krb5_error_code K5_EXPORT
k5_get_service_ticket(k5_context k5, const char *service,
		      const char *hostname,
		      k5_ticket *ticket);

krb5_error_code K5_EXPORT
k5_get_service_ticket_gss(k5_context k5, const char *service,
			  const char *hostname,
			  k5_ticket *ticket);

krb5_error_code K5_EXPORT
k5_klist(k5_context k5, k5_klist_entries *rep);

krb5_error_code K5_EXPORT
k5_kdestroy(k5_context k5);

krb5_error_code K5_EXPORT
k5_free_ticket(k5_context k5, k5_ticket *ticket);

krb5_error_code K5_EXPORT
k5_clear_ticket(k5_context k5, k5_ticket *ticket);

krb5_error_code K5_EXPORT
k5_free_klist(k5_context k5, k5_klist_entries *klist);

krb5_error_code K5_EXPORT
k5_clear_klist(k5_context k5, k5_klist_entries *klist);

#if defined(_WIN32)
int K5_EXPORT k5_mslsa_check_registry();
int K5_EXPORT k5_mslsa_set_registry(int enable);

krb5_error_code K5_EXPORT k5_ms2mit(k5_context k5);
#endif

#endif /* K5_H_ */
