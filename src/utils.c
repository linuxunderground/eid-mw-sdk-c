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

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>


int b64_encode(const unsigned char *in, int in_len, char *out, int out_len)
{
    int ret = 0;
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bio = BIO_new(BIO_s_mem());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, bio);

    ret = BIO_write(b64, in, in_len);
    BIO_flush(b64);
    if (ret > 0) ret = BIO_read(bio, out, out_len);

    BIO_free(b64);
    return ret;
}

/* see also ./plugins_tools/eid-viewer/certhelpers.c in eid-mw tree */
int dumpcert(const void* derdata, int len, char *pemdata, int pem_maxlen)
{
    int retVal=0;
    BIO *bio = BIO_new(BIO_s_mem());
    X509 *aX509 = d2i_X509(NULL, (const unsigned char**)&derdata, len);
    if (aX509 != NULL)
    {
        retVal = PEM_write_bio_X509(bio, aX509);  /* 1=OK 0=error */
        BIO_flush(bio);
        if (retVal > 0)
            /*return data length in pemdata */
            retVal = BIO_read(bio, pemdata, pem_maxlen);
    }
    BIO_free(bio);
    return retVal;
}
