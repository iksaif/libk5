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

/**
 * @file k5.h
 * @brief libk5 header
 */

struct _k5_context;
typedef struct _k5_context * k5_context;

/**
 * @brief Kerberos ticket structure
 */
typedef struct _k5_ticket {
  /**
   * Client Name
   */
  char *client_name;
  /**
   * Server Name
   */
  char *server_name;
  /**
   * Auth time
   */
  time_t authtime;
  /**
   * Start time
   */
  time_t starttime;
  /**
   * End time
   */
  time_t endtime;
  /**
   * Renew untill time
   */
  time_t renew_till;
  /**
   * Raw krb5_ticket structure
   */
  krb5_ticket *ticket;
  /**
   * Raw krb5_cred structure
   */
  krb5_creds *creds;
  /**
   * Humanly readable ticket flags
   */
  char flags[32];
  /**
   * Humanly readable ticket encryptions
   */
  char ticket_enc[100];
  /**
   * Humanly readable key encryptions
   */
  char key_enc[100];
  /**
   * Raw ticket data
   */
  char *data;
  /**
   * Raw ticket data size
   */
  size_t data_size;
  /**
   * Raw gss ticket data, only set after
   * k5_get_service_ticket_gss() call
   */
  char *gss_data;
  /**
   * Raw gss ticket data size, only set after
   * k5_get_service_ticket_gss() call
   */
  size_t gss_data_size;
  /**
   * gss ticket, base64 encoded, only set after
   * k5_get_service_ticket_gss() call
   */
  char *gss_base64;
  /**
   * gss ticket size (base64 encoded), only set after
   * k5_get_service_ticket_gss() call
   */
  size_t gss_base64_size;
} k5_ticket;

/**
 * @brief Klist entries
 */
typedef struct _k5_klist_entries {
  /**
   * Default principal name
   */
  char *defname;
  /**
   * Number of ticket
   */
  int count;
  /**
   * Tickets found in cache
   */
  k5_ticket *tickets;
} k5_klist_entries;


/**
 * @brief enum used for k5_kinit() calls
 */
enum k5_kinit_action {
  K5_KINIT_PW, /**< Init with password */
  K5_VALIDATE, /**< Validate */
  K5_RENEW,    /**> Renew */
};

/**
 * @brief kinit request
 */
typedef struct _k5_kinit_req {
  /**
   * Requested action
   */
  enum k5_kinit_action action;
  /**
   * Requested lifetime, 0 for default value
   */
  int lifetime;
  /**
   * Requested rlife, 0 for default value
   */
  int rlife;
  /**
   * Requested starttime, 0 for default value
   */
  int starttime;
  /**
   * Set to 1 to get a forwardable ticket
   */
  int forwardable;
  /**
   * Set to 1 to get a proxiable ticket
   */
  int proxiable;
  /**
   * Set to 1 to get a non-forwardable ticket
   */
  int not_forwardable;
  /**
   * Set to 1 to get a non-proxiable ticket
   */
  int not_proxiable;
  /**
   * Principal name ([service/]host&#64REALM)
   */
  char *principal_name;
  /**
   * Optional service name (service/host)
   * Set to NULL to get a TGT
   */
  char *service_name;
  /**
   * Optional password prompter
   * Set to NULL to use default prompter
   */
  krb5_prompter_fct prompter;
} k5_kinit_req;

krb5_error_code K5_EXPORT
k5_init_context(k5_context *k5, const char *cache);

/**
 * @brief Free k5_context
 * @param k5 libk5 context
 * @return 0 on success; otherwise returns an error code
 * @sa k5_init_context
 */
krb5_error_code K5_EXPORT
k5_free_context(k5_context k5);

/**
 * @brief Set libk5 verbosity
 * @param k5 libk5 context
 * @param enabled enable verbose mode
 */
void K5_EXPORT
k5_set_verbose(k5_context k5, int enabled);

/**
 * @brief Request a ticket
 * @param k5 libk5 context
 * @param req kinit request
 * @param ticket requested ticket, can be NULL
 * @return 0 on success; otherwise returns an error code
 */
krb5_error_code K5_EXPORT
k5_kinit(k5_context k5, k5_kinit_req *req, k5_ticket *ticket);

/**
 * @brief Request a service ticket
 * @param k5 libk5 context
 * @param service service name (can be NULL if hostname is a full principal name)
 * @param hostname hostname, can also be a full principal name (service/hostname&#64REALM) is service is NULL
 * @param ticket requested ticket, can be NULL
 * @return 0 on success; otherwise returns an error code
 * @sa k5_get_service_ticket_gss
 */
krb5_error_code K5_EXPORT
k5_get_service_ticket(k5_context k5, const char *service,
		      const char *hostname,
		      k5_ticket *ticket);

/**
 * @brief Request a gss service ticket (can be used for gssapi auth)
 * @param k5 libk5 context
 * @param service service name
 * @param hostname
 * @param ticket requested ticket, can be NULL
 * @return 0 on success; otherwise returns an error code
 * @sa k5_get_service_ticket
 */
krb5_error_code K5_EXPORT
k5_get_service_ticket_gss(k5_context k5, const char *service,
			  const char *hostname,
			  k5_ticket *ticket);

/**
 * @brief Request ticket list for current cache
 * @param k5 libk5 context
 * @param rep ticket list
 * @return 0 on success; otherwise returns an error code
 */
krb5_error_code K5_EXPORT
k5_klist(k5_context k5, k5_klist_entries *rep);

/**
 * @brief Destroy all tickets
 * @param k5 libk5 context
 * @return 0 on success; otherwise returns an error code
 * @sa k5_kinit
 */
krb5_error_code K5_EXPORT
k5_kdestroy(k5_context k5);

/**
 * @brief Free internal ticket structure. You still need to call free()
 * on ticket if needed)
 * @param k5 libk5 context
 * @param ticket ticket
 * @return 0 on success; otherwise returns an error code
 */
krb5_error_code K5_EXPORT
k5_clear_ticket(k5_context k5, k5_ticket *ticket);

/**
 * @brief Free internal klist structure. You still need to call free()
 * on klist if needed)
 * @param k5 libk5 context
 * @param klist ticket list
 * @return 0 on success; otherwise returns an error code
 */
krb5_error_code K5_EXPORT
k5_clear_klist(k5_context k5, k5_klist_entries *klist);

#if defined(_WIN32)
/**
 * @brief Check MSLSA related registry keys
 * @return 0 on success; otherwise returns an error code
 * @sa k5_mslsa_set_registry
 */
int K5_EXPORT k5_mslsa_check_registry();

/**
 * @brief Set MSLSA related registry keys
 * @enable 1 to enable, 0 to disable
 * @return 0 on success; otherwise returns an error code
 * @sa k5_mslsa_get_registry
 */
int K5_EXPORT k5_mslsa_set_registry(int enable);

/**
 * @brief Import MSLSA cache
 * @param k5 libk5 context
 * @return 0 on success; otherwise returns an error code
 * @sa k5_mslsa_set_registry
 * @sa k5_mslsa_get_registry
 */
krb5_error_code K5_EXPORT k5_ms2mit(k5_context k5);
#endif

#endif /* K5_H_ */
