/*
 * Crypto.c
 *
 *  Created on: Apr 15, 2025
 *      Author: Ahmed Gamal
 */

// CryptoSW.c

//static const uint8_t SoftwareKeyTable[][16] = {
//    { 0x00, 0x01, 0x02, ..., 0x0F },  // Key index 0
//    { 0x10, 0x11, 0x12, ..., 0x1F },  // Key index 1
//};

//Std_ReturnType CryptoSW_PerformAesEncrypt(uint8 KeyIndex, const uint8* PlainText, uint8* CipherText)
//{
//    const uint8_t* key = SoftwareKeyTable[KeyIndex];
//
//
//}


#include "Crypto.h"
    #include "Crypto_GeneralTypes.h"
#include "Std_Types.h"

/* Function for Crypto Initialization API */
void Crypto_Init (const Crypto_ConfigType* configPtr);

/* Function for Crypto Get Version Info API */
#if (CRYPTO_VERSION_INFO_API == STD_ON)
void Crypto_GetVersionInfo (Std_VersionInfoType* versioninfo);
#endif

/* Function for Cancel Processing of jobs in Crypto stack */
Std_ReturnType Crypto_CancelJob (uint32 objectId,Crypto_JobType* job);

/* Function for Process jobs in Crypto stack */
Std_ReturnType Crypto_ProcessJob(uint32 objectId, Crypto_JobType* job) {
    CryptoDriverObject* driverObject;
    Std_ReturnType retVal = E_NOT_OK;

    /* [SWS_Crypto_00057] Check initialization */
    if (!Crypto_ModuleInitialized) {//this parameter will be a bool var and i will initialize then check it
        Crypto_ReportError(CRYPTO_PROCESSJOB_API_ID, CRYPTO_E_UNINIT);
        return E_NOT_OK;
    }

    SchM_Enter_Crypto_CRYPTO_EXCLUSIVE_AREA();//i will make it as soon as possible

    /* [SWS_Crypto_00059] Null pointer check */
    if (job == NULL_PTR) {
        Crypto_ReportError(CRYPTO_PROCESSJOB_API_ID, CRYPTO_E_PARAM_POINTER);
        SchM_Exit_Crypto_CRYPTO_EXCLUSIVE_AREA();//i will make it as soon as possible
        return E_NOT_OK;
    }

    /* [SWS_Crypto_00058] Validate objectId range */
    driverObject = Crypto_GetDriverObject(objectId);//will be implemented
    if (driverObject == NULL_PTR) {
        Crypto_ReportError(CRYPTO_PROCESSJOB_API_ID, CRYPTO_E_PARAM_HANDLE);
        SchM_Exit_Crypto_CRYPTO_EXCLUSIVE_AREA();//i will make it as soon as possible
        return E_NOT_OK;
    }

    /* [SWS_Crypto_00064] Validate supported service */
    if (!Crypto_IsServiceSupported(driverObject, job->jobPrimitiveInfo->primitiveInfo->service)) {//this function will be implemented
        Crypto_ReportError(CRYPTO_PROCESSJOB_API_ID, CRYPTO_E_PARAM_HANDLE);
        SchM_Exit_Crypto_CRYPTO_EXCLUSIVE_AREA();//i will make it as soon as possible
        return E_NOT_OK;
    }

    /* [SWS_Crypto_00202] Key derivation validation */
    if (job->jobPrimitiveInfo->primitiveInfo->service == CRYPTO_KEYDERIVE) {
        if (!Crypto_IsKeyIdValid(job->targetCryptoKeyId)) {
            Crypto_ReportError(CRYPTO_PROCESSJOB_API_ID, CRYPTO_E_PARAM_HANDLE);
            SchM_Exit_Crypto_CRYPTO_EXCLUSIVE_AREA();//i will make it as soon as possible
            return E_NOT_OK;
        }
    }

    /* [SWS_Crypto_00067] Algorithm validation */
    if (!Crypto_CheckAlgorithmSupport(driverObject, job->jobPrimitiveInfo->primitiveInfo->algorithm)) {//this function will be implemented
        Crypto_ReportError(CRYPTO_PROCESSJOB_API_ID, CRYPTO_E_PARAM_HANDLE);
        SchM_Exit_Crypto_CRYPTO_EXCLUSIVE_AREA();//i will make it as soon as possible
        return E_NOT_OK;
    }

    /* [SWS_Crypto_00070] Buffer pointer validation */
    if (!Crypto_ValidateRequiredPointers(job)) {//this function will be implemented
        Crypto_ReportError(CRYPTO_PROCESSJOB_API_ID, CRYPTO_E_PARAM_POINTER);
        SchM_Exit_Crypto_CRYPTO_EXCLUSIVE_AREA();//i will make it as soon as possible
        return E_NOT_OK;
    }

    /* [SWS_Crypto_00142] Length validation */
    if (!Crypto_ValidateLengths(job)) {//this function will be implemented
        Crypto_ReportError(CRYPTO_PROCESSJOB_API_ID, CRYPTO_E_PARAM_VALUE);
        SchM_Exit_Crypto_CRYPTO_EXCLUSIVE_AREA();//i will make it as soon as possible
        return E_NOT_OK;
    }

    /* Context handling [SWS_Crypto_00228-00231] */
    if (job->jobPrimitiveInputOutput->mode == CRYPTO_OPERATIONMODE_SAVE_CONTEXT ||
        job->jobPrimitiveInputOutput->mode == CRYPTO_OPERATIONMODE_RESTORE_CONTEXT) {

        if (!driverObject->config.supportContext) {//i will see it later
            SchM_Exit_Crypto_CRYPTO_EXCLUSIVE_AREA();//i will make it as soon as possible
            return E_NOT_OK;
        }

        if (job->jobPrimitiveInputOutput->mode == CRYPTO_OPERATIONMODE_SAVE_CONTEXT) {
            /* [SWS_Crypto_00229] Save context validation */
            if (job->jobPrimitiveInputOutput->outputLengthPtr < driverObject->contextSize) {
                SchM_Exit_Crypto_CRYPTO_EXCLUSIVE_AREA();//i will make it as soon as possible
                return E_NOT_OK;
            }

            /* [SWS_Crypto_00230] Save context implementation */
            retVal = Crypto_SaveContext(driverObject, job);//i will see it later
        }
        else {
            /* [SWS_Crypto_00231] Restore context validation */
            if (job->jobPrimitiveInputOutput->inputLength < driverObject->contextSize) {
                SchM_Exit_Crypto_CRYPTO_EXCLUSIVE_AREA();//i will make it as soon as possible
                return E_NOT_OK;
            }

            retVal = Crypto_RestoreContext(driverObject, job);//i will see it later
        }

        SchM_Exit_Crypto_CRYPTO_EXCLUSIVE_AREA();//i will make it as soon as possible
        return retVal;
    }

    /* Handle standard processing */
    //we will stress here later
    switch(job->jobPrimitiveInfo->primitiveInfo->service) {
        case CRYPTO_HASH:
        case CRYPTO_MACGENERATE:
            /* [SWS_Crypto_00065] Truncate output if needed */
            retVal = Crypto_HandleHmacHash(job, driverObject);
            break;

        case CRYPTO_RANDOMGENERATE:
            /* [SWS_Crypto_00252] Random generation handling */
            retVal = Crypto_HandleRandomGeneration(job, driverObject);
            break;

        default:
            /* Standard processing */
            if (driverObject->config.executionMode == CRYPTO_EXECUTION_SYNC) {
                retVal = Crypto_ProcessJobSync(driverObject, job);
            } else {
                retVal = Crypto_QueueJob(driverObject, job);
            }
            break;
    }

    SchM_Exit_Crypto_CRYPTO_EXCLUSIVE_AREA();
    return retVal;
}


