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

#include "k5_priv.h"

int K5_EXPORT
k5_mslsa_check_registry()
{
  return 0;
}

int K5_EXPORT
k5_mslsa_set_registry(int enable)
{
  return 0;
}

krb5_error_code
K5_EXPORT k5_ms2mit(k5_context k5)
{
  return 0;
}
