/*
 * https://github.com/linuxunderground/eid-mw-sdk-c
 * Copyright (C) 2016-2020 Vincent Hardy <vincent.hardy@linuxunderground.be>
 *
 * This complete example shows how to read identity data from the card.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version
 * 3.0 as published by the Free Software Foundation.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, see
 * http://www.gnu.org/licenses/.
 */

#ifndef __base64_h__
#define __base64_h__

int b64_encode(const unsigned char* in, int in_len, char *out, int out_len);
int dumpcert(const void* derdata, int len, char *pemdata, int pem_maxlen);

#endif
