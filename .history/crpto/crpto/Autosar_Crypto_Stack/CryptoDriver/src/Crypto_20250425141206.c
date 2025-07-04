/*
 * Crypto.c
 *
 *  Created on: Apr 15, 2025
 *      Author: Ahmed Gamal
 */
#include "../include/Crypto.h"
#include "../include/Crypto_Cfg.h"
#include "../include/Crypto_GeneralTypes.h"
#include "../include/Std_Types.h"
#include "stdbool.h"
#include "stdio.h"

bool Crypto_ModuleInitialized= FALSE;
Crypto_JobStateType ObjectsStatus[10] ={CRYPTO_JOBSTATE_IDLE}; //Accessed by object id
Crypto_JobType* CurrentJobs[10];


void Crypto_ReportError(uint8 ApiId, uint8 ErrorId)
{
    printf("Crypto Error - API ID: 0x%02X, Error ID: 0x%02X\n",
           (unsigned)ApiId,
           (unsigned)ErrorId);
}


/* Global pointer to the active configuration */
static const Crypto_ConfigType* Crypto_GlobalConfigPtr = NULL_PTR;

/* Tracks each key’s validity (0 = valid, 1 = invalid) */
static uint8 Crypto_KeyState[CRYPTO_MAX_KEYS];



/**
 * @brief   Initialize the Crypto driver.
 * @param   configPtr  Pointer to the post-build configuration (e.g. &Crypto_PBConfig)
 *                    SHALL always be non-NULL
 * @sws     SWS_Crypto_00045  Report CRYPTO_E_INIT_FAILED on any init failure
 * @sws     SWS_Crypto_00198  Mark any key missing in config as invalid
 */
void Crypto_Init(const Crypto_ConfigType* configPtr)
{
    printf("11111Hello, World!\n");

    boolean initFailed = FALSE;

    /* 1) Validate the passed-in configPtr */
    if (configPtr == NULL_PTR) {
        initFailed = TRUE;
    } else {
        Crypto_GlobalConfigPtr = configPtr;
    }

    /* 2) Initialize Driver Objects */
    if (Crypto_GlobalConfigPtr != NULL_PTR) {
        for (uint32 i = 0; i < Crypto_GlobalConfigPtr->NumDriverObjects; ++i) {
            if (Crypto_GlobalConfigPtr->DriverObjectRefs[i] == NULL_PTR) {
                initFailed = TRUE;
            }
        }
    }

    /* 3) Initialize Keys (no NVM: just check presence) */
    if (Crypto_GlobalConfigPtr != NULL_PTR) {
        for (uint32 i = 0; i < Crypto_GlobalConfigPtr->NumKeys; ++i) {
            if (Crypto_GlobalConfigPtr->KeyRefs[i] == NULL_PTR) {
                Crypto_KeyState[i] = KEY_STATE_INVALID;
                initFailed = TRUE;
            } else {
                Crypto_KeyState[i] = KEY_STATE_VALID;
            }
        }
    }

    /* 4) Report overall init failure if any sub-step failed */
    if (initFailed) {
        Crypto_ReportError(CRYPTO_INIT_API_ID, CRYPTO_E_INIT_FAILED);

    }
 Crypto_ModuleInitialized= TRUE;

}


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
    bool canProcessJob = FALSE;
    bool needsReset = FALSE; //Will be used when Start or Finish happens
    
    // /* [SWS_Crypto_00057] Check initialization */
    // if (!Crypto_ModuleInitialized) {//this parameter will be a bool var and i will initialize then check it
    //     Crypto_ReportError(CRYPTO_PROCESSJOB_API_ID, CRYPTO_E_UNINIT);
    //     return E_NOT_OK;
    // }

    // SchM_Enter_Crypto_CRYPTO_EXCLUSIVE_AREA();//i will make it as soon as possible

    // /* [SWS_Crypto_00059] Null pointer check */
    // if (job == NULL_PTR) {
    //     Crypto_ReportError(CRYPTO_PROCESSJOB_API_ID, CRYPTO_E_PARAM_POINTER);
    //     SchM_Exit_Crypto_CRYPTO_EXCLUSIVE_AREA();//i will make it as soon as possible
    //     return E_NOT_OK;
    // }

    // /* [SWS_Crypto_00058] Validate objectId range */
    // driverObject = Crypto_GetDriverObject(objectId);//will be implemented
    // if (driverObject == NULL_PTR) {
    //     Crypto_ReportError(CRYPTO_PROCESSJOB_API_ID, CRYPTO_E_PARAM_HANDLE);
    //     SchM_Exit_Crypto_CRYPTO_EXCLUSIVE_AREA();//i will make it as soon as possible
    //     return E_NOT_OK;
    // }

    // /* [SWS_Crypto_00064] Validate supported service */
    // if (!Crypto_IsServiceSupported(driverObject, job->jobPrimitiveInfo->primitiveInfo->service)) {//this function will be implemented
    //     Crypto_ReportError(CRYPTO_PROCESSJOB_API_ID, CRYPTO_E_PARAM_HANDLE);
    //     SchM_Exit_Crypto_CRYPTO_EXCLUSIVE_AREA();//i will make it as soon as possible
    //     return E_NOT_OK;
    // }

    // /* [SWS_Crypto_00202] Key derivation validation */
    // if (job->jobPrimitiveInfo->primitiveInfo->service == CRYPTO_KEYDERIVE) {
    //     if (!Crypto_IsKeyIdValid(job->targetCryptoKeyId)) {
    //         Crypto_ReportError(CRYPTO_PROCESSJOB_API_ID, CRYPTO_E_PARAM_HANDLE);
    //         SchM_Exit_Crypto_CRYPTO_EXCLUSIVE_AREA();//i will make it as soon as possible
    //         return E_NOT_OK;
    //     }
    // }

    // /* [SWS_Crypto_00067] Algorithm validation */
    // if (!Crypto_CheckAlgorithmSupport(driverObject, job->jobPrimitiveInfo->primitiveInfo->algorithm)) {//this function will be implemented
    //     Crypto_ReportError(CRYPTO_PROCESSJOB_API_ID, CRYPTO_E_PARAM_HANDLE);
    //     SchM_Exit_Crypto_CRYPTO_EXCLUSIVE_AREA();//i will make it as soon as possible
    //     return E_NOT_OK;
    // }

    // /* [SWS_Crypto_00070] Buffer pointer validation */
    // if (!Crypto_ValidateRequiredPointers(job)) {//this function will be implemented
    //     Crypto_ReportError(CRYPTO_PROCESSJOB_API_ID, CRYPTO_E_PARAM_POINTER);
    //     SchM_Exit_Crypto_CRYPTO_EXCLUSIVE_AREA();//i will make it as soon as possible
    //     return E_NOT_OK;
    // }

    // /* [SWS_Crypto_00142] Length validation */
    // if (!Crypto_ValidateLengths(job)) {//this function will be implemented
    //     Crypto_ReportError(CRYPTO_PROCESSJOB_API_ID, CRYPTO_E_PARAM_VALUE);
    //     SchM_Exit_Crypto_CRYPTO_EXCLUSIVE_AREA();//i will make it as soon as possible
    //     return E_NOT_OK;
    // }

    // /* Context handling [SWS_Crypto_00228-00231] */
    // if (job->jobPrimitiveInputOutput->mode == CRYPTO_OPERATIONMODE_SAVE_CONTEXT ||
    //     job->jobPrimitiveInputOutput->mode == CRYPTO_OPERATIONMODE_RESTORE_CONTEXT) {

    //     if (!driverObject->config.supportContext) {//i will see it later
    //         SchM_Exit_Crypto_CRYPTO_EXCLUSIVE_AREA();//i will make it as soon as possible
    //         return E_NOT_OK;
    //     }

    //     if (job->jobPrimitiveInputOutput->mode == CRYPTO_OPERATIONMODE_SAVE_CONTEXT) {
    //         /* [SWS_Crypto_00229] Save context validation */
    //         if (job->jobPrimitiveInputOutput->outputLengthPtr < driverObject->contextSize) {
    //             SchM_Exit_Crypto_CRYPTO_EXCLUSIVE_AREA();//i will make it as soon as possible
    //             return E_NOT_OK;
    //         }

    //         /* [SWS_Crypto_00230] Save context implementation */
    //         retVal = Crypto_SaveContext(driverObject, job);//i will see it later
    //     }
    //     else {
    //         /* [SWS_Crypto_00231] Restore context validation */
    //         if (job->jobPrimitiveInputOutput->inputLength < driverObject->contextSize) {
    //             SchM_Exit_Crypto_CRYPTO_EXCLUSIVE_AREA();//i will make it as soon as possible
    //             return E_NOT_OK;
    //         }

    //         retVal = Crypto_RestoreContext(driverObject, job);//i will see it later
    //     }

    //     SchM_Exit_Crypto_CRYPTO_EXCLUSIVE_AREA();//i will make it as soon as possible
    //     return retVal;
    // }

    if (ObjectsStatus[objectId] == CRYPTO_JOBSTATE_ACTIVE)
    {
        if (job == CurrentJobs[objectId])
        {
            if (job->jobPrimitiveInputOutput.mode == CRYPTO_OPERATIONMODE_START)//#define CRYPTO_OPERATIONMODE_START 0x01
            {
                // Reset buffers and restart current job
                canProcessJob = true;
                needsReset = true;
            }
            else //Update Or Finish(Don't forget to go to idle state and reset buffers)0x02 Error, 0x03 
            {
                canProcessJob = true;
                needsReset = false;
            }
        }
        else // job != currentJob
        {
            if (job->jobPrimitiveInputOutput.mode == CRYPTO_OPERATIONMODE_START)
            {
                // Cancel currentJob and start new job
                CurrentJobs[objectId] = job;
                canProcessJob = true;
                needsReset = true;
                // Reset buffers, enter ACTIVE state
            }
            else
            {
                canProcessJob = false;
                retVal = CRYPTO_E_BUSY;
            }
        }
    }
    else if (ObjectsStatus[objectId] == CRYPTO_JOBSTATE_IDLE)// DriverState == IDLE
    {
        if (job->jobPrimitiveInputOutput.mode == CRYPTO_OPERATIONMODE_START)
        {
            // Initialize job context, move to ACTIVE
            canProcessJob = true;
            //needsReset = true; we don't need that here as IDLE = Reseted
            CurrentJobs[objectId] = job;
            ObjectsStatus[objectId] = CRYPTO_JOBSTATE_ACTIVE;
        }
        else
        {
            // No active job to update/finish — reject
            canProcessJob = false;
            retVal = CRYPTO_E_NOT_OK;
        }
    }

    if (needsReset) {
        Crypto_ResetBuffers(driverObject);//Needs to be implemented
    }
    
    if(canProcessJob)
    {
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
    }
    SchM_Exit_Crypto_CRYPTO_EXCLUSIVE_AREA();
    return retVal;
}

