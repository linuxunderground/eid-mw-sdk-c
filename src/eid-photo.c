/*
 * https://github.com/linuxunderground/eid-mw-sdk-c
 *
 * Copyright (C) 2014 FedICT.
 * Copyright (C) 2016-2020 Vincent Hardy <vincent.hardy@linuxunderground.be>
 *
 * This complete example shows how to decode identity photo from the card.
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

#define PKCS11_LIB "libbeidpkcs11.so.0"

#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <dlfcn.h>
#include <string.h>
#include <limits.h>
#include <rsaref220/unix.h>
#include <rsaref220/pkcs11.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#if HAVE_JPEGLIB
#include <jpeglib.h>
#endif


CK_ULONG Beidsdk_Decode_Photo(CK_FUNCTION_LIST_PTR pFunctions, CK_SESSION_HANDLE session_handle);
void save_photo(char* data, CK_ULONG length);
#if HAVE_JPEGLIB
void jpegdump(char* data, CK_ULONG length);
#else
void hex_dump(char* data, CK_ULONG length);
#endif
CK_ULONG beidsdk_GetData(void);


int main()
{
    CK_ULONG retval = CKR_OK;
    retval = beidsdk_GetData();
}

CK_ULONG beidsdk_GetData()
{
    void *pkcs11Handle;                 /* handle to the pkcs11 library */
    CK_FUNCTION_LIST_PTR pFunctions;    /* list of the pkcs11 function pointers */
    CK_C_GetFunctionList pC_GetFunctionList;
    CK_SLOT_ID_PTR slotIds;
    CK_ULONG slot_count;
    CK_ULONG slotIdx;
    CK_SESSION_HANDLE session_handle;
    CK_RV retVal = CKR_OK;

    /* open the pkcs11 library */
    pkcs11Handle = dlopen(PKCS11_LIB, RTLD_LAZY);
    if (pkcs11Handle != NULL)
    {
        /* get function pointer to C_GetFunctionList */
        pC_GetFunctionList = (CK_C_GetFunctionList)dlsym(pkcs11Handle, "C_GetFunctionList");
        if (pC_GetFunctionList != NULL)
        {
            /* invoke C_GetFunctionList to get the list of pkcs11 function pointers */
            retVal = (*pC_GetFunctionList)(&pFunctions);
            if (retVal == CKR_OK)
            {
                /* initialize Cryptoki */
                retVal = (pFunctions->C_Initialize)(NULL);
                if (retVal == CKR_OK)
                {
                    /* retrieve the number of slots (cardreaders) found
                     * set first parameter to CK_FALSE if you also want to find the slots without a card inserted
                     */
                    retVal = (pFunctions->C_GetSlotList)(CK_TRUE, 0, &slot_count);
                    if ((retVal == CKR_OK) && (slot_count > 0))
                    {
                        slotIds = (CK_SLOT_ID_PTR)malloc(slot_count * sizeof(CK_SLOT_ID));
                        if (slotIds != NULL)
                        {
                            /* Now retrieve the list of slots (cardreaders)
                             *
                             * Note: this should ideally be done in a loop, since the
                             * number of slots reported by C_GetSlotList might increase if
                             * the user inserts a card (or card reader) at exactly the right
                             * moment. See PKCS#11 (pkcs-11v2-11r1.pdf) for details.
                             */
                            retVal = (pFunctions->C_GetSlotList)(CK_TRUE, slotIds, &slot_count);
                            if (retVal == CKR_OK)
                            {
                                /* Loop over the reported slots and read data from any eID card found */
                                for (slotIdx = 0; slotIdx < slot_count; slotIdx++)
                                {
                                    /* open a session */
                                    retVal = (pFunctions->C_OpenSession)(slotIds[slotIdx], CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &session_handle);
                                    if (retVal == CKR_OK)
                                    {
                                        retVal = Beidsdk_Decode_Photo(pFunctions, session_handle);

                                        /* close the session */
                                        if (retVal == CKR_OK)
                                            retVal = (pFunctions->C_CloseSession)(session_handle);
                                        else
                                            (pFunctions->C_CloseSession)(session_handle);
                                    }
                                }
                            }
                            free(slotIds);
                        }
                        else /* malloc slotIds failed */
                        {
                            printf("malloc failed\n");
                            retVal = CKR_GENERAL_ERROR;
                        }
                    }
                    else
                    {
                        printf("no slots found\n");
                    }

                    if (retVal == CKR_OK)
                        retVal = (pFunctions->C_Finalize)(NULL_PTR);
                    else
                        (pFunctions->C_Finalize)(NULL_PTR);
                }
            }
        }
        else retVal = CKR_GENERAL_ERROR; /* dlsym failed */
        dlclose(pkcs11Handle);
    }
    else /* dlopen failed */
    {
        printf("%s not found\n",PKCS11_LIB);
#ifdef WIN32
        DWORD err;
        err = GetLastError();
        printf("err is 0x%.8x\n",err);
        //14001 is "MSVCR80.DLL not found"
#else
        printf("err is %s", dlerror());
#endif
        retVal = CKR_GENERAL_ERROR;
    }
    return retVal;
}

CK_ULONG Beidsdk_Decode_Photo(CK_FUNCTION_LIST_PTR pFunctions, CK_SESSION_HANDLE session_handle)
{
    CK_ULONG type = CKO_DATA;
    CK_ATTRIBUTE searchtemplate[2];
    CK_OBJECT_HANDLE Object;
    CK_ULONG ObjectCount;
    char *label_str;
    char *value_str;
    char *objid_str;
    CK_ATTRIBUTE data[3] = {
        {CKA_LABEL, NULL_PTR, 0},
        {CKA_VALUE, NULL_PTR, 0},
        {CKA_OBJECT_ID, NULL_PTR, 0},
    };
    CK_RV retVal = CKR_OK;


    searchtemplate[0].type = CKA_CLASS;
    searchtemplate[0].pValue = &type;
    searchtemplate[0].ulValueLen = sizeof(CK_ULONG);

    searchtemplate[1].type = CKA_LABEL;
    searchtemplate[1].pValue = (void*)("PHOTO_FILE");
    searchtemplate[1].ulValueLen = strlen("PHOTO_FILE");

    /* initialize the search for the objects "PHOTO_FILE" */
    retVal = (pFunctions->C_FindObjectsInit)(session_handle, searchtemplate, 2);
    if (retVal == CKR_OK)
    {
        /* find the first object with label "PHOTO_FILE" */
        retVal = (pFunctions->C_FindObjects)(session_handle, &Object, 1, &ObjectCount);
        if (ObjectCount == 1)
        {
            /* retrieve the length of the data from the object */
            retVal = (pFunctions->C_GetAttributeValue)(session_handle, Object, data, 3);
            if (retVal == CKR_OK &&
                (CK_LONG)(data[0].ulValueLen) >= 0 &&
                (CK_LONG)(data[1].ulValueLen) >= 0 &&
                (CK_LONG)(data[2].ulValueLen) >= 0)
            {
                label_str = malloc(data[0].ulValueLen + 1);
                data[0].pValue = label_str;

                value_str = malloc(data[1].ulValueLen + 1);
                data[1].pValue = value_str;

                objid_str = malloc(data[2].ulValueLen + 1);
                data[2].pValue = objid_str;

                if ((label_str != NULL) && (value_str != NULL) && (objid_str != NULL))
                {
                    /* now run C_GetAttributeValue a second time to actually retrieve the
                     * data from the object
                     */
                    retVal = (pFunctions->C_GetAttributeValue)(session_handle, Object, data, 3);

                    label_str[data[0].ulValueLen] = '\0';
                    value_str[data[1].ulValueLen] = '\0';
                    objid_str[data[2].ulValueLen] = '\0';

                    save_photo(value_str,data[1].ulValueLen);
#if HAVE_JPEGLIB
                    printf("Data object with object ID: %s; label: %s; length: %lu\nContents(ASCII art representation):\n",
                        objid_str, label_str, data[1].ulValueLen);
                    jpegdump(value_str, data[1].ulValueLen);
#else
                    printf("Data object with object ID: %s; label: %s; length: %lu\nContents(hexdump):\n",
                        objid_str, label_str, data[1].ulValueLen);
                    hex_dump(value_str, data[1].ulValueLen);
#endif
                }
                if (label_str != NULL) free(label_str);
                if (value_str != NULL) free(value_str);
                if (objid_str != NULL) free(objid_str);
            }
        }
        /* finalize the search */
        retVal = (pFunctions->C_FindObjectsFinal)(session_handle);
    }
    return retVal;
}

void save_photo(char* data, CK_ULONG length)
{
    char *hd;
    FILE* f;
    char filename[PATH_MAX];

#ifdef WIN32
    hd = getenv("USERDATA");
    if (hd==NULL) hd = getenv("USERPROFILE");
#else
    hd = getenv("HOME");
#endif
    if (hd != NULL)
    {
        strncpy(filename,hd,PATH_MAX-15);
        strncat(filename,"/eid-photo.jpg",14);
        f = fopen(filename, "wb+");
        if (f)
        {
            fwrite(data, 1, length, f);
            fclose(f);
        }
    }
}

#if HAVE_JPEGLIB
enum weights
{
    TOPLEFT,
    TOPCENTER,
    TOPRIGHT,
    CENTLEFT,
    CENTER,
    CENTRIGHT,
    BOTLEFT,
    BOTCENTER,
    BOTRIGHT,
    SLASH,
    BACKSLASH,
};

enum duty
{
    NONE,
    LIGHT,
    MED,
    HEAVY,
};

static int orientations[16] = {
               /*br bl tr tl */
    CENTER,    /* 0  0  0  0 */
    TOPLEFT,   /* 0  0  0  1 */
    TOPRIGHT,  /* 0  0  1  0 */
    TOPCENTER, /* 0  0  1  1 */
    BOTLEFT,   /* 0  1  0  0 */
    CENTLEFT,  /* 0  1  0  1 */
    SLASH,     /* 0  1  1  0 */
    TOPLEFT,   /* 0  1  1  1 */
    BOTRIGHT,  /* 1  0  0  0 */
    BACKSLASH, /* 1  0  0  1 */
    CENTRIGHT, /* 1  0  1  0 */
    TOPRIGHT,  /* 1  0  1  1 */
    BOTCENTER, /* 1  1  0  0 */
    BOTLEFT,   /* 1  1  0  1 */
    BOTRIGHT,  /* 1  1  1  0 */
    CENTER,    /* 1  1  1  1 */
};

static char translate[4][11] = {
    { ' ',  ' ',  ' ',  ' ',  ' ',  ' ',  ' ',  ' ',  ' ', ' ', ' ', },
    { 0x60,'\'', 0x27,  '>',  '-',  '<',  ',',  '_',  '.', '/', '\\', },
    { '"',  '?',  '"',  '[',  '*',  ']',  'b',  'o',  'd', '/', '\\', },
    { 'F',  'V',  '$',  '#',  '@',  '#',  '&',  'W',  'Q', '/', '\\' },
};

void jpegdump(char* data, CK_ULONG length)
{
    struct jpeg_decompress_struct cinfo;
    struct jpeg_error_mgr jerr;
    JSAMPARRAY imgbuf;
    JDIMENSION size = 0;
    int rlen, i, j;

    /* initialize JPEG decompression */
    cinfo.err = jpeg_std_error(&jerr);

    jpeg_create_decompress(&cinfo);
    jpeg_mem_src(&cinfo, (unsigned char*)data, length);

    if (jpeg_read_header(&cinfo, TRUE) != JPEG_HEADER_OK)
    {
        printf("Could not read JPEG header\n");
        return;
    }

    if (!jpeg_start_decompress(&cinfo))
    {
        printf("Could not decompress JPEG data\n");
        return;
    }

    printf("image has %d byte(s) per pixel\n", cinfo.output_components);
    rlen = cinfo.output_width * cinfo.output_components;
    imgbuf = (*cinfo.mem->alloc_sarray)((j_common_ptr)&cinfo, JPOOL_IMAGE, rlen, cinfo.output_height);
    while (size != cinfo.output_height)
    {
        size += jpeg_read_scanlines(&cinfo, &(imgbuf[size]), cinfo.output_height - size);
    }

    printf("Read %u scanlines\n", size);

    for (i=0; i<cinfo.output_height; i+=2)
    {
        for (j=0; j<rlen; j+=2)
        {
            int p[4];     /* pixel */
            int d[4], dt; /* duty  */
            int k, m, or;
            p[0] = 255 - (imgbuf[i][j]);
            p[1] = 255 - (imgbuf[i][j+1]);
            p[2] = 255 - (imgbuf[i+1][j]);
            p[3] = 255 - (imgbuf[i+1][j+1]);
            or = 0;
            for(k=0, m=0; k<4; k++)
            {
                d[k] = p[k] >> 6;
                if (d[k] > m)
                {
                    m = d[k];
                    or = 1 << k;
                }
                else
                if (d[k] == m)
                {
                    or |= 1 << k;
                }
            }
            dt = (p[0] + p[1] + p[2] + p[3]) >> 8;
            or = orientations[or];
            printf("%c", translate[dt][or]);
        }
        printf("\n");
    }
}
#else
void hex_dump(char* data, CK_ULONG length)
{
    CK_ULONG i;
    int j;

    for (i=0, j=0; i<length; i++)
    {
        int8_t d = (int8_t)(data[i]);
        printf("%02hhx ", d);
        j+=3;
        if (!((i + 1) % 5))
        {
            printf(" ");
            j += 1;
        }
        if (j >= 80)
        {
            printf("\n");
            j = 0;
        }
    }
    if (j)
    {
        printf("\n");
    }
}
#endif
