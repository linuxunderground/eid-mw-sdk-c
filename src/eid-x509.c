/*
 * https://github.com/linuxunderground/eid-mw-sdk-c
 *
 * Copyright (C) 2017 Vincent Hardy <vincent.hardy.be@gmail.com>
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
#include <malloc.h>
#include <dlfcn.h>
#include <string.h>
#include <unix.h>
#include <pkcs11.h>
#include <openssl/x509.h>
#include <openssl/crypto.h>


CK_ULONG beid_X509(void);
CK_ULONG beid_GetX509Cert(CK_FUNCTION_LIST_PTR pFunctions, CK_SESSION_HANDLE session_handle, CK_CHAR_PTR pName, CK_VOID_PTR *ppValue, CK_ULONG_PTR pvalueLen);
void X509Info(CK_BYTE_PTR pValue, CK_ULONG valueLen);
void beid_PrintValue_PEM(CK_BYTE_PTR pValue, CK_ULONG valueLen);


int main()
{
    CK_ULONG retval = CKR_OK;
    retval = beid_X509();
}

CK_ULONG beid_X509()
{
    void *pkcs11Handle;                 /* handle to the pkcs11 library */
    CK_FUNCTION_LIST_PTR pFunctions;    /* list of the pkcs11 function pointers */
    CK_C_GetFunctionList pC_GetFunctionList;
    CK_SLOT_ID_PTR slotIds;
    CK_ULONG slot_count;
    CK_ULONG slotIdx;
    CK_SESSION_HANDLE session_handle;
    CK_VOID_PTR pCertValue = NULL;
    CK_ULONG CertValueLen = 0;
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
                                        /* Old Belgium Root CA2 certificate
                                         * Expires on 15/12/2021 but probably already useless now.
                                         */
                                        retVal = beid_GetX509Cert(pFunctions, session_handle, "Root", &pCertValue, &CertValueLen);
                                        X509Info(pCertValue, CertValueLen);
                                        beid_PrintValue_PEM(pCertValue, CertValueLen);
                                        if (pCertValue != NULL) free(pCertValue);
                                        CertValueLen = 0;

                                        /* Citizen CA or Foreigner CA certificate */
                                        retVal = beid_GetX509Cert(pFunctions, session_handle, "CA", &pCertValue, &CertValueLen);
                                        X509Info(pCertValue, CertValueLen);
                                        beid_PrintValue_PEM(pCertValue, CertValueLen);
                                        if (pCertValue != NULL) free(pCertValue);
                                        CertValueLen = 0;

                                        /* Authentication certificate of eID owner */
                                        retVal = beid_GetX509Cert(pFunctions, session_handle, "Authentication", &pCertValue, &CertValueLen);
                                        X509Info(pCertValue, CertValueLen);
                                        beid_PrintValue_PEM(pCertValue, CertValueLen);
                                        if (pCertValue != NULL) free(pCertValue);
                                        CertValueLen = 0;

                                        /* Signature certificate of eID owner */
                                        retVal = beid_GetX509Cert(pFunctions, session_handle, "Signature", &pCertValue, &CertValueLen);
                                        X509Info(pCertValue, CertValueLen);
                                        beid_PrintValue_PEM(pCertValue, CertValueLen);
                                        if (pCertValue != NULL) free(pCertValue);
                                        CertValueLen = 0;

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


CK_ULONG beid_GetX509Cert(CK_FUNCTION_LIST_PTR pFunctions, CK_SESSION_HANDLE session_handle, CK_CHAR_PTR pName, CK_VOID_PTR *ppValue, CK_ULONG_PTR pvalueLen)
{
    CK_ATTRIBUTE searchtemplate[2];
    CK_ULONG classtype = CKO_CERTIFICATE;
    CK_OBJECT_HANDLE hObject;
    CK_ULONG ulObjectCount;
    CK_ATTRIBUTE attr_templ[1];
    CK_RV retVal = CKR_OK;

    searchtemplate[0].type = CKA_CLASS;
    searchtemplate[0].pValue = &classtype;
    searchtemplate[0].ulValueLen = sizeof(CK_ULONG);

    searchtemplate[1].type = CKA_LABEL;
    searchtemplate[1].pValue = (CK_VOID_PTR)pName;
    searchtemplate[1].ulValueLen = strlen(pName);

    /* initialize the search for the objects with label <certname> */
    retVal = (pFunctions->C_FindObjectsInit)(session_handle, searchtemplate, 2);
    if (retVal == CKR_OK)
    {
        /* find the first object with class CKO_CERTIFICATE and with label <certname> */
        retVal = (pFunctions->C_FindObjects)(session_handle, &hObject, 1, &ulObjectCount);
        if (ulObjectCount == 1)
        {
            /* NULL_PTR as second argument, so the length of value is filled in to retValueLen */
            attr_templ[0].type = CKA_VALUE;
            attr_templ[0].pValue = NULL;
            attr_templ[0].ulValueLen = 0;
            /* retrieve the length of the data from the object */
            retVal = (pFunctions->C_GetAttributeValue)(session_handle, hObject, attr_templ, 1);
            if (retVal == CKR_OK && (CK_LONG)(attr_templ[0].ulValueLen) > 0)
            {
                *ppValue = malloc(attr_templ[0].ulValueLen);
                if (*ppValue != NULL)
                {
                    attr_templ[0].pValue = *ppValue;
                    /* retrieve the data from the object */
                    retVal = (pFunctions->C_GetAttributeValue)(session_handle, hObject, attr_templ, 1);
                    *pvalueLen = attr_templ[0].ulValueLen;
                }
                else
                    retVal = CKR_GENERAL_ERROR;
            }
        }
        else
            retVal = CKR_GENERAL_ERROR;
        /* finalize the search */
        retVal = (pFunctions->C_FindObjectsFinal)(session_handle);
    }
    return retVal;
}

void X509Info(CK_BYTE_PTR pValue, CK_ULONG valueLen)
{
    X509 *aX509;
    X509_NAME *aX509Name;
    char LOneLine[2048];
    ASN1_INTEGER *Serial;
    BIGNUM *bn;
    char *buffer;

    if (pValue != NULL)
    {
        aX509 = d2i_X509(NULL, (const unsigned char**)&pValue, valueLen);
        if (aX509 != NULL)
        {
            aX509Name = X509_get_issuer_name(aX509);
            if (aX509Name != NULL)
            {
                X509_NAME_oneline(aX509Name, LOneLine, sizeof(LOneLine));
                printf("IssuerName: %s\n",LOneLine);
            }
            else
                printf("Unable to find issuer_name\n");

            Serial = X509_get_serialNumber(aX509);
            bn = ASN1_INTEGER_to_BN(Serial, NULL);
            if (bn != NULL)
            {
                buffer = BN_bn2dec(bn);
                if (buffer != NULL)
                {
                    printf("SerialNumber: %s\n",buffer),
                    OPENSSL_free(buffer);
                }
                else
                    printf("Unable to convert ASN1INTEGER to BN\n");
                BN_free(bn);
            }
            X509_free(aX509);
        }
    }
}

#define X509_MAX_LENGTH 2048

void beid_PrintValue_PEM(CK_BYTE_PTR pValue, CK_ULONG valueLen)
{
    unsigned long counter = 0;
    char buffer[X509_MAX_LENGTH+1];

    if (pValue != NULL)
    {
        counter = dumpcert(pValue, valueLen, buffer, X509_MAX_LENGTH);
        buffer[counter]='\0';
        printf("%s\n",buffer);
    }
}
