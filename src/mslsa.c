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

#include <stdio.h>
#include <errno.h>

#include "k5_priv.h"

#define MSLSA_PATH_1 "SYSTEM\\CurrentControlSet\\Control\\Lsa\\Kerberos"
#define MSLSA_PATH_2 "SYSTEM\\CurrentControlSet\\Control\\Lsa\\Kerberos\\Parameters"
#define MSLSA_KEY    "AllowTGTSessionKey"

#ifndef _WIN32

/* Only on win32 */

int K5_EXPORT
k5_mslsa_check_registry()
{
  return -1;
}

int K5_EXPORT
k5_mslsa_set_registry(int enable)
{
  return -1;
}

krb5_error_code
K5_EXPORT k5_ms2mit(k5_context k5)
{
  return -1;
}

#else
static int
read_registry_key(const char *path, const char *key)
{
  HKEY hKey;
  DWORD dwLen = sizeof(DWORD);
  DWORD dwKeyEn = 0;

  if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
    fprintf(stderr, "Couldn't open LSA registry key %s, error %d\n", path, (int) GetLastError());
    return -1;
  }

  if (RegQueryValueEx(hKey, key, NULL, NULL, (LPBYTE)&dwKeyEn, &dwLen) != ERROR_SUCCESS) {
    fprintf(stderr,"Couldn't read LSA registry key, error %d\n", (int) GetLastError());
    RegCloseKey(hKey);
    return -1;
  }
    
  RegCloseKey(hKey);
  return dwKeyEn;
}

static int
write_registry_key(const char *path, const char *key, int value)
{
  HKEY hKey;
  DWORD dwLen = sizeof(DWORD);
  DWORD dwKeyEn = 0;
  DWORD dwType;

  if (RegCreateKey(HKEY_LOCAL_MACHINE, path, &hKey) != ERROR_SUCCESS) {
    fprintf(stderr, "Couldn't create LSA registry key %s, error %d\n", path, (int) GetLastError());
    return -1;
  }

  if (RegQueryValueEx(hKey, key, NULL, NULL, (LPBYTE)&dwKeyEn, &dwLen) == ERROR_SUCCESS) {
    if (dwKeyEn)
      goto exit;
  }

  dwLen = sizeof(DWORD);
  dwKeyEn = 1;
  dwType = REG_DWORD;

  if (RegSetValueEx(hKey, key, 0, dwType, (LPBYTE)&dwKeyEn, dwLen) != ERROR_SUCCESS) {
    fprintf(stderr,"Couldn't write LSA registry key, error %d\n", (int) GetLastError());
    goto error;
  }

exit:
  RegCloseKey(hKey);
  return 0;
error:
  RegCloseKey(hKey);
  return -1;
}

int K5_EXPORT
k5_mslsa_check_registry()
{
  int ret, k1 = 0, k2 = 0;
  
  if ((ret = read_registry_key(MSLSA_PATH_1, MSLSA_KEY)) < 0) {
    fprintf(stderr, "%s: error while reading value of %s\\%s\n",
            "k5_mslsa_check_registry", MSLSA_PATH_1, MSLSA_KEY);
    return ret;
  } else {
    fprintf(stderr, "%s\\%s = %x\n", MSLSA_PATH_1, MSLSA_KEY, ret);
    k1 = ret;
  }
		
  if ((ret = read_registry_key(MSLSA_PATH_2, MSLSA_KEY)) < 0) {
    fprintf(stderr, "%s: error while reading value of %s\\%s\n",
            "k5_mslsa_check_registry", MSLSA_PATH_2, MSLSA_KEY);
    return ret;
  } else {
    fprintf(stderr, "%s\\%s = %x\n", MSLSA_PATH_2, MSLSA_KEY, ret);
    k2 = ret;
  }

  return !(k1 && k2);
}

int K5_EXPORT
k5_mslsa_set_registry(int enable)
{
  return write_registry_key(MSLSA_PATH_1, MSLSA_KEY, 1) ||
	 write_registry_key(MSLSA_PATH_2, MSLSA_KEY, 1);
}

krb5_error_code
K5_EXPORT k5_ms2mit(k5_context k5)
{
  krb5_error_code code;
  krb5_ccache mslsa_ccache = NULL;
  krb5_cc_cursor cursor;
  krb5_creds creds;
  krb5_principal princ = NULL;
  int initial_ticket = 0;
    
  if ((code = krb5_cc_resolve(k5->ctx, "MSLSA:", &mslsa_ccache))) {
    com_err("k5_ms2mit", code, "while opening MS LSA ccache");
    goto cleanup;
  }

  if ((code = krb5_cc_set_flags(k5->ctx, mslsa_ccache, KRB5_TC_NOTICKET))) {
    com_err("k5_ms2mit", code, "while setting KRB5_TC_NOTICKET flag");
    goto cleanup;
  }

  /* Enumerate tickets from cache looking for an initial ticket */
  if ((code = krb5_cc_start_seq_get(k5->ctx, mslsa_ccache, &cursor))) {
    com_err("k5_ms2mit", code, "while initiating the cred sequence of MS LSA ccache");
    goto cleanup;
  }

  while (!(code = krb5_cc_next_cred(k5->ctx, mslsa_ccache, &cursor, &creds))) 
  {
    if ( creds.ticket_flags & TKT_FLG_INITIAL ) {
      krb5_free_cred_contents(k5->ctx, &creds);
      initial_ticket = 1;
      break;
    }
    krb5_free_cred_contents(k5->ctx, &creds);
  }
  krb5_cc_end_seq_get(k5->ctx, mslsa_ccache, &cursor);

  if ((code = krb5_cc_set_flags(k5->ctx, mslsa_ccache, 0))) {
    com_err("k5_ms2mit", code, "while clearing flags");
    goto cleanup;
  }

  if (!initial_ticket) {
    if (k5->verbose)
      fprintf(stderr, "%s: Initial Ticket Getting Tickets are not available from the MS LSA\n",
              "k5_ms2mit");
    goto cleanup;
  }

  if ((code = krb5_cc_get_principal(k5->ctx, mslsa_ccache, &princ))) {
    com_err("k5_ms2mit", code, "while obtaining MS LSA principal");
    goto cleanup;
  }

  if ((code = krb5_cc_initialize(k5->ctx, k5->cc, princ))) {
    com_err ("k5_ms2mit", code, "when initializing ccache");
    goto cleanup;
  }

  if ((code = krb5_cc_copy_creds(k5->ctx, mslsa_ccache, k5->cc))) {
    com_err ("k5_ms2mit", code, "while copying MS LSA ccache to default ccache");
    goto cleanup;
  }

cleanup:
  krb5_free_principal(k5->ctx, princ);
  if (mslsa_ccache)
    krb5_cc_close(k5->ctx, mslsa_ccache);
  return code;
}
#endif
