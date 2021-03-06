/*
 * https://github.com/linuxunderground/eid-mw-sdk-c
 *
 * Copyright (C) 2009-2010 FedICT.
 * Copyright (C) 2016-2020 Vincent Hardy <vincent.hardy@linuxunderground.be>
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
#include <rsaref220/unix.h>
#include <rsaref220/pkcs11.h>


CK_ULONG beidsdk_waitcard(void);

int main()
{
    CK_ULONG retval = CKR_OK;

    retval = beidsdk_waitcard();
    getchar();
}

CK_ULONG beidsdk_waitcard() 
{
    void *pkcs11Handle;                 /* handle to the pkcs11 library */
    CK_FUNCTION_LIST_PTR pFunctions;    /* list of the pkcs11 function pointers */
    CK_C_GetFunctionList pC_GetFunctionList;
    CK_SLOT_ID_PTR slotIds;
    CK_ULONG slot_count;
    CK_ULONG slotIdx;
    CK_SESSION_HANDLE session_handle;
    CK_BBOOL cardInserted = CK_FALSE;
    CK_SLOT_INFO slotinfo;
    CK_TOKEN_INFO tokeninfo;
    CK_UTF8CHAR slotDescription[65];
    CK_UTF8CHAR manufacturerID[33];
    CK_UTF8CHAR label[33];
    CK_UTF8CHAR serialnumber[17];
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
                    /* retrieve the number of slots (cardreaders)
                     * to find also the slots without tokens inserted, set the first parameter to CK_FALSE
                     */
                    retVal = (pFunctions->C_GetSlotList)(CK_FALSE, 0, &slot_count);
                    if ((retVal == CKR_OK) && (slot_count > 0))
                    {
                        slotIds = (CK_SLOT_ID_PTR)malloc(slot_count * sizeof(CK_SLOT_INFO));
                        if (slotIds != NULL)
                        {
                            /* retrieve the list of slots (cardreaders) */
                            retVal = (pFunctions->C_GetSlotList)(CK_FALSE, slotIds, &slot_count);
                            if (retVal == CKR_OK)
                            {
                                /* check if a card is already present in one of the readers */
                                for (slotIdx = 0; slotIdx < slot_count; slotIdx++)
                                {
                                    retVal = (pFunctions->C_GetSlotInfo)(slotIds[slotIdx], &slotinfo);
                                    if ((retVal == CKR_OK) && (slotinfo.flags & CKF_TOKEN_PRESENT))
                                    {
                                        memcpy(slotDescription, slotinfo.slotDescription, 64);
                                        slotDescription[64] = '\0'; /* make the string null terminated */
                                        printf("Card found in reader %s \n\n",slotDescription);

                                        /* a card is found in the slot */
                                        cardInserted = CK_TRUE;
                                        retVal = (pFunctions->C_GetTokenInfo)(slotIds[slotIdx], &tokeninfo);
                                        if (retVal == CKR_OK)
                                        {
                                            memcpy(manufacturerID,tokeninfo.manufacturerID, 32);
                                            manufacturerID[32] = '\0'; /* make the string null terminated */
                                            printf("ManufacturerID : %s \n",manufacturerID);

                                            memcpy(label,tokeninfo.label, 32);
                                            label[32] = '\0';          /* make the string null terminated */
                                            printf("Label          : %s \n",label);

                                            memcpy(serialnumber,tokeninfo.serialNumber, 16);
                                            serialnumber[16] = '\0';   /* make the string null terminated */
                                            printf("Serial number  : %s \n",serialnumber);

                                            switch(tokeninfo.firmwareVersion.major) {
                                            case 0x17 : printf("Applet version : 1.7\n"); break;
                                            case 0x18 : printf("Applet version : 1.8\n"); break;
                                            default : printf("Unsupported applet version!\n");
                                            }

                                            printf("\n");
                                        }

                                    }
                                }

                                if (cardInserted == CK_FALSE)
                                {
                                    CK_FLAGS flags = 0;  /* use CKF_DONT_BLOCK if you don't want C_WaitForSlotEvent to block */
                                    CK_SLOT_ID slotId;   /* will receive the ID of the slot that the event occurred in */

                                    printf("Please insert a beid card\n");
                                    retVal = (pFunctions->C_WaitForSlotEvent)(flags, &slotId, NULL_PTR);
                                    if (retVal == CKR_OK)
                                    {
                                        printf("Card inserted \n");
                                        for (slotIdx = 0; slotIdx < slot_count; slotIdx++) 
                                        {
                                            if (slotId == slotIds[slotIdx])
                                            {
                                                retVal = (pFunctions->C_GetSlotInfo)(slotId, &slotinfo);
                                                if (retVal == CKR_OK)
                                                {
                                                    memcpy(slotDescription,slotinfo.slotDescription,64);
                                                    slotDescription[64] = '\0'; /* make the string null terminated */
                                                    printf("into reader %s \n",slotDescription);
                                                }
                                            }
                                        }
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
                    else if (slot_count == 0)  /* no slots found */
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
	dlclose(pkcs11Handle);
    }
    return retVal;
}
