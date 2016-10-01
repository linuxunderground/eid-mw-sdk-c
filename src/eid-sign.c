/*
 * https://github.com/linuxunderground/eid-mw-sdk-c
 * Copyright (C) 2016 Vincent Hardy <vincent.hardy.be@gmail.com>
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
#include <malloc.h>
#include <dlfcn.h>
#include <string.h>
#include <unix.h>
#include <pkcs11.h>

#include "utils.h"

CK_ULONG beidsdk_sign(CK_CHAR_PTR textToSign);

int main()
{
    CK_ULONG retval = CKR_OK;
    CK_CHAR_PTR copyrightText = 
        "* eID Middleware Project.                                            \
         * Copyright (C) 2009-2010 FedICT.                                    \
         *                                                                    \
         * This is free software; you can redistribute it and/or modify it    \
         * under the terms of the GNU Lesser General Public License version   \
         * 3.0 as published by the Free Software Foundation.                  \
         *                                                                    \
         * This software is distributed in the hope that it will be useful,   \
         * but WITHOUT ANY WARRANTY; without even the implied warranty of     \
         * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU   \
         * Lesser General Public License for more details.                    \
         *                                                                    \
         * You should have received a copy of the GNU Lesser General Public   \
         * License along with this software; if not, see                      \
         * http://www.gnu.org/licenses/.";

    retval = beidsdk_sign( copyrightText );
    getchar();
}

CK_ULONG beidsdk_sign(CK_CHAR_PTR textToSign) 
{
    void *pkcs11Handle;                 /* handle to the pkcs11 library */
    CK_FUNCTION_LIST_PTR pFunctions;    /* list of the pkcs11 function pointers */
    CK_C_GetFunctionList pC_GetFunctionList;
    CK_SLOT_ID_PTR slotIds;
    CK_ULONG slot_count;
    CK_ULONG slotIdx;
    CK_SESSION_HANDLE session_handle;
    CK_ULONG private_key = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE attributes[2];
    CK_ULONG ulMaxObjectCount;
    CK_ULONG ulObjectCount;
    CK_OBJECT_HANDLE hKey;
    unsigned long counter;
    CK_RV retVal = CKR_OK;

    /* use the CKM_SHA1_RSA_PKCS mechanism for signing */
    CK_MECHANISM mechanism = {CKM_SHA1_RSA_PKCS, NULL_PTR, 0};
    CK_BYTE signature[128];
    CK_ULONG signLength = 128;
    /**/
    char buffer[255];


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
                                        /* prepare the findobjects function to find all objects with attributes
                                         * CKA_CLASS set to CKO_PRIVATE_KEY and with CKA_LABEL set to Signature
                                         */
                                        attributes[0].type = CKA_CLASS;
                                        attributes[0].pValue = &private_key;
                                        attributes[0].ulValueLen = sizeof(CK_ULONG);

                                        attributes[1].type = CKA_LABEL;
                                        attributes[1].pValue = "Signature";
                                        attributes[1].ulValueLen = strlen("Signature");

                                        retVal = (pFunctions->C_FindObjectsInit)(session_handle, attributes, 2); 
                                        if (retVal == CKR_OK)
                                        {
                                            ulMaxObjectCount = 1; /* we want max one object returned */
                                            /* retrieve the private key with label "signature" */
                                            retVal = (pFunctions->C_FindObjects)(session_handle, &hKey, ulMaxObjectCount, &ulObjectCount); 
                                            if (retVal == CKR_OK)
                                            {
                                                /* terminate the search */
                                                retVal = (pFunctions->C_FindObjectsFinal)(session_handle);
                                                if (retVal == CKR_OK)
                                                {
                                                    /* initialize the signature operation */
                                                    retVal = (pFunctions->C_SignInit)(session_handle, &mechanism, hKey); 
                                                    if (retVal == CKR_OK)
                                                    {
                                                        retVal = (pFunctions->C_Sign)(session_handle,textToSign,(CK_ULONG) strlen(textToSign),signature,&signLength);
                                                        if (retVal == CKR_OK)
                                                        {
                                                            counter = 0;
                                                            printf("The Signature (base64):\n");
                                                            b64_encode(signature,signLength,buffer,255);
                                                            printf("%s\n",buffer);
                                                        }
                                                    }
                                                }
                                            }
                                            if (retVal == CKR_OK)
                                                retVal = (pFunctions->C_FindObjectsFinal)(session_handle);
                                            else
                                                (pFunctions->C_FindObjectsFinal)(session_handle);
                                        }
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
