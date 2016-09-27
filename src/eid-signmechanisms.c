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

#include "unix.h"
#include "pkcs11.h"

#include <stdio.h>
#include <malloc.h>
#include <dlfcn.h>
#include <string.h>


CK_ULONG beidsdk_getsignmechanisms(void);

int main()
{
    CK_ULONG retval = CKR_OK;

    retval = beidsdk_getsignmechanisms();
    getchar();
}

CK_ULONG beidsdk_getsignmechanisms() 
{
    void *pkcs11Handle;                 /* handle to the pkcs11 library */
    CK_FUNCTION_LIST_PTR pFunctions;    /* list of the pkcs11 function pointers */
    CK_C_GetFunctionList pC_GetFunctionList;
    CK_SLOT_ID_PTR slotIds;
    CK_ULONG slot_count;
    CK_ULONG slotIdx;
    CK_ULONG ulMechCount;
    CK_MECHANISM_TYPE_PTR pMechanismList;
    CK_MECHANISM_INFO mechanismInfo;
    CK_ULONG ulCount;
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
                        slotIds = (CK_SLOT_ID_PTR)malloc(slot_count * sizeof(CK_SLOT_INFO));
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
                                    pMechanismList = NULL;
                                    retVal = (pFunctions->C_GetMechanismList)(slotIds[slotIdx], NULL_PTR, &ulMechCount);
		                    if ((retVal == CKR_OK) && (ulMechCount > 0))
                                    {
                                        pMechanismList = (CK_MECHANISM_TYPE_PTR)malloc(ulMechCount * sizeof(CK_MECHANISM_TYPE));
                                        if (pMechanismList != NULL)
                                        {
                                            retVal = (pFunctions->C_GetMechanismList)(slotIds[slotIdx], pMechanismList, &ulMechCount);
                                            if (retVal == CKR_OK)
                                            {
                                               printf("Card Mechanisms found :\n");
                                               for (ulCount = 0; ulCount < ulMechCount; ulCount++)
                                               {
                                                    retVal = (pFunctions->C_GetMechanismInfo)(slotIds[slotIdx], pMechanismList[ulCount], &mechanismInfo);
                                                    if (retVal == CKR_OK)
                                                    {
                                                        if (mechanismInfo.flags & CKF_SIGN)
                                                            printf("Mechanism 0x%.8x, which supports signing\n",pMechanismList[ulCount]);
                                                        else
                                                            printf("Mechanism 0x%.8x, which doesn't support signing\n",pMechanismList[ulCount]);
                                                    }
                                                }
                                            }
                                        }
                                        else //malloc pMechanismList failed
                                        {
                                            printf("malloc pMechanismList failed\n");
                                            retVal = CKR_GENERAL_ERROR;
                                        }
                                    }
                                }//end of for loop
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