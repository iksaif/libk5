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

#include <errno.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "k5.h"

static const char cb64[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void
encodeblock( unsigned char in[3], unsigned char out[4], int len )
{
    out[0] = cb64[ in[0] >> 2 ];
    out[1] = cb64[ ((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4) ];
    out[2] = (unsigned char) (len > 1 ? cb64[ ((in[1] & 0x0f) << 2) | ((in[2] & 0xc0) >> 6) ] : '=');
    out[3] = (unsigned char) (len > 2 ? cb64[ in[2] & 0x3f ] : '=');
}

static size_t
base64encode(char *dst, const char *src, size_t size)
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

int
k5_b64enc_ticket(k5_ticket *ticket)
{
  size_t bytes, size;

  assert(ticket);
  assert(ticket->gss_data);

  if (ticket->gss_base64)
    return EINVAL;

  size = ticket->gss_data_size;
  /* http://en.wikipedia.org/wiki/Base64 */
  bytes = ((2 + size - ((size + 2) % 3)) * 4 / 3) + 2;

  ticket->gss_base64 = (char *)malloc(bytes);

  if (!ticket->gss_base64)
    return ENOMEM;

  size = base64encode((char *)ticket->gss_base64, ticket->gss_data, size);
  ((char *)ticket->gss_base64)[size] = '\0';
  ticket->gss_base64_size = size;
  return 0;
}
