/*
 * Crypto.c
 *
 */

#include "Crypto.h"
#include "Crypto_Cfg.h"
#include "Crypto_GeneralTypes.h"
#include "Std_Types.h"
#include "stdbool.h"
#include "stdio.h"
#include "mbedtls/gcm.h"

// CryptoObject Instantation
CryptoPrimitive MacVerify_Primitive = {
    .CryptoPrimitiveAlgorithmFamily = {CRYPTO_ALGOFAM_AES},    
    .CryptoPrimitiveAlgorithmMode = {CRYPTO_ALGOMODE_GCM},   
    .CryptoPrimitiveAlgorithmSecondaryFamily = {CRYPTO_ALGOFAM_AES},
    .CryptoPrimitiveService = CRYPTO_MACVERIFY,
    .CryptoPrimitiveSupportContext = false,
    .CryptoPrimitiveAlgorithmFamilyCustomRef= {NULL_PTR},
    .CryptoPrimitiveAlgorithmModeCustomRef = {NULL_PTR},                
    .CryptoPrimitiveAlgorithmSecondaryFamilyCustomRef = {NULL_PTR}      
};

CryptoPrimitive MacGenerate_Primitive = {
    .CryptoPrimitiveAlgorithmFamily = {CRYPTO_ALGOFAM_AES},  
    .CryptoPrimitiveAlgorithmMode = {CRYPTO_ALGOMODE_GCM},    
    .CryptoPrimitiveAlgorithmSecondaryFamily = {CRYPTO_ALGOFAM_AES},
    .CryptoPrimitiveService = CRYPTO_MACGENERATE,
    .CryptoPrimitiveSupportContext = false,
    .CryptoPrimitiveAlgorithmFamilyCustomRef= {NULL_PTR},
    .CryptoPrimitiveAlgorithmModeCustomRef = {NULL_PTR},               
    .CryptoPrimitiveAlgorithmSecondaryFamilyCustomRef = {NULL_PTR}     
};


CryptoDriverObject CryptoObject_MAC = {
    .CryptoDriverObjectId = 0,
    .CryptoQueueSize = 0,  // We aren't supporting Crypto Queues
    .CryptoDefaultRandomKeyRef = NULL_PTR,  // not needed for MAC operations
    .CryptoDefaultRandomPrimitiveRef = NULL_PTR,  // also not needed for MAC
    .CryptoPrimitiveRef = {
        &MacGenerate_Primitive,
        &MacVerify_Primitive
    }
};

CryptoKeyElement GCM_KeyElement = {
    .CryptoKeyElementId=0,
    .CryptoKeyElementAllowPartialAccess = false,
    .CryptoKeyElementFormat = CRYPTO_KE_FORMAT_BIN_OCTET,
    .CryptoKeyElementInitValue = "AA",
    .CryptoKeyElementPersist = false,
    .CryptoKeyElementReadAccess = CRYPTO_RA_DENIED,
    .CryptoKeyElementSize = 16,
    .CryptoKeyElementWriteAccess =  CRYPTO_WA_DENIED  
};

CryptoKeyType GCM_KeyType = {
    .CryptoKeyElementRef = { &GCM_KeyElement }
};

CryptoKey CryptoKey1 = {
    .CryptoKeyId = 0,
    .CryptoKeyNvBlockRef=NULL_PTR,
    .CryptoKeyTypeRef = &GCM_KeyType
};


/* PB structure used with Crypto_Init API */
const Crypto_ConfigType Crypto_PBConfig = {
  .NumPrimitives     = CRYPTO_MAX_PRIMITIVES,
  .PrimitiveRefs     = {
    &MacGenerate_Primitive,
    &MacVerify_Primitive
  },

  .NumDriverObjects  = CRYPTO_MAX_DRIVER_OBJECTS,
  .DriverObjectRefs  = {
    &CryptoObject_MAC
  },

  .NumKeys           = CRYPTO_MAX_KEYS,
  .KeyRefs           = {
    &CryptoKey1
  }
};


void Crypto_ReportError(uint8 ApiId, uint8 ErrorId)
{
    printf("Crypto Error - API ID: 0x%02X, Error ID: 0x%02X\n",
           (unsigned)ApiId,
           (unsigned)ErrorId);
}
mbedtls_gcm_context gcm;

/* Global pointer to the active configuration */
static const Crypto_ConfigType* Crypto_GlobalConfigPtr = NULL_PTR;

/* Tracks each key’s validity (0 = valid, 1 = invalid) */
static uint8 Crypto_KeyState[CRYPTO_MAX_KEYS];

driveobject_type Driverobjects[CRYPTO_MAX_DRIVER_OBJECTS] ;

/**
 * @brief   Initialize the Crypto driver.
 * @param   configPtr  Pointer to the post-build configuration (e.g. &Crypto_PBConfig)
 *                    SHALL always be non-NULL
 * @sws     SWS_Crypto_00045  Report CRYPTO_E_INIT_FAILED on any init failure
 * @sws     SWS_Crypto_00198  Mark any key missing in config as invalid
 */
void Crypto_Init(const Crypto_ConfigType* configPtr)
{
    // printf("11111Hello, World!\n");

    boolean initFailed = FALSE;

    /* 1) Validate the passed-in configPtr */
    if (configPtr == NULL_PTR) {
        initFailed = TRUE;
    } else {
        Crypto_GlobalConfigPtr = configPtr;
    }
    // printf("10\n");
   
    /* 2) Initialize Driver Objects */
    if (Crypto_GlobalConfigPtr != NULL_PTR) {
        for (uint32 i = 0; i < Crypto_GlobalConfigPtr->NumDriverObjects; ++i) {//2
            // printf("%d\n", Crypto_GlobalConfigPtr->NumDriverObjects);
            if (Crypto_GlobalConfigPtr->DriverObjectRefs[i] == NULL_PTR) {
                // printf("%d\n", Crypto_GlobalConfigPtr->NumDriverObjects);
                initFailed = TRUE;
                // printf("11\n");
            }
            // printf("12\n");
            Driverobjects[i].DriverObjectId = Crypto_GlobalConfigPtr->DriverObjectRefs[i]->CryptoDriverObjectId;
            // printf("13\n");
            Driverobjects[i].status=CRYPTO_JOBSTATE_IDLE;
            // printf("14\n"); 
        }
    }
    // printf("15\n");
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

    {
        /* code */
    }
    
    /* 4) Report overall init failure if any sub-step failed */
    if (initFailed) {
        Crypto_ReportError(CRYPTO_INIT_API_ID, CRYPTO_E_INIT_FAILED);

    }
}




static Std_ReturnType AesGcm_Start(driveobject_type* drv, const Crypto_JobType* job) {
    // printf("Start");
    mbedtls_gcm_init(&gcm);
    printf("Start");
    // [!] Get key from driveobject_type's CryptoKey
    const CryptoKey* key = &drv->Key;
    if (key->CryptoKeyTypeRef == NULL ||
        key->CryptoKeyTypeRef->CryptoKeyElementRef == NULL) {
        return E_NOT_OK; // Key not configured
    }

    // [!] Access the first CryptoKeyElement
    const CryptoKeyElement* keyElement = key->CryptoKeyTypeRef->CryptoKeyElementRef;
    const uint8* keyData = keyElement->CryptoKeyElementInitValue;
    size_t keyLength = keyElement->CryptoKeyElementSize;

    // [!] Validate key length (e.g., 16, 24, 32 bytes for AES)
    if (keyLength != 16 && keyLength != 24 && keyLength != 32) {
        return E_NOT_OK; // Invalid AES key size
    }

    // [!] Determine mode (Encrypt for Generate, Decrypt for Verify)
    int mode = (job->jobPrimitiveInfo->primitiveInfo->service == CRYPTO_MACGENERATE) ?
                MBEDTLS_GCM_ENCRYPT : MBEDTLS_GCM_DECRYPT;

    // [!] Set key from CryptoKeyElementInitValue
    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES,
                                keyData, keyLength * 8);
    if (ret != 0) return E_NOT_OK;

    // [!] Initialize with IV
    uint8 iv[12] = { 0x00, 0x11, 0x22, 0x33, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0xFF, 0xFF };
    size_t iv_len = 12;
    ret = mbedtls_gcm_starts(&gcm, mode, iv, iv_len);
    return (ret == 0) ? E_OK : E_NOT_OK;
}


static Std_ReturnType AesGcm_Update(driveobject_type* drv, const Crypto_JobType* job) {
    const uint8* input = job->jobPrimitiveInputOutput.inputPtr;
    size_t input_len = job->jobPrimitiveInputOutput.inputLength;
    uint8* output = job->jobPrimitiveInputOutput.outputPtr;
    printf("Update");
    size_t output_len;
    int ret = mbedtls_gcm_update(&gcm, input, input_len,
                                output, sizeof(output), &output_len);
    printf("%d\n",ret);

    return (ret == 0) ? E_OK : E_OK;
}
//
static Std_ReturnType AesGcm_Finish(driveobject_type* drv, Crypto_JobType* job) {
    printf("Hamada 1");
    uint8* tag = job->jobPrimitiveInputOutput.inputPtr;
    size_t tag_len = job->jobPrimitiveInputOutput.inputLength;
    uint8* output = job->jobPrimitiveInputOutput.outputPtr;
    size_t output_length = *(job->jobPrimitiveInputOutput.outputLengthPtr);
    int ret; 
    printf("Hamada 2");
    // [!] Finalize and handle Generate/Verify logic
    if (job->jobPrimitiveInfo->primitiveInfo->service == CRYPTO_MACGENERATE) {
        // Generate MAC tag
        ret = mbedtls_gcm_finish(&gcm,output,sizeof(output),&output_length, tag, tag_len);
       
    } else {
//        // Verify MAC tag
        printf("Hamada");
        ret = mbedtls_gcm_finish(&gcm,output,sizeof(output),&output_length, tag, tag_len);
        printf("Finish");
        if (ret == MBEDTLS_ERR_GCM_AUTH_FAILED) {
            *(job->jobPrimitiveInputOutput.verifyPtr) = CRYPTO_E_VER_NOT_OK;
            ret = 0; // Override error to indicate completion
            printf("not done");
        } else if (ret == 0) {
            job->jobPrimitiveInputOutput.verifyPtr = CRYPTO_E_VER_OK;
            printf("done");
        }
    }

    return (ret == 0) ? E_OK : E_NOT_OK;
}

static void AesGcm_Reset(driveobject_type* drv) {
    
    mbedtls_gcm_free(&gcm);
}





//static const CryptoServiceHandler AesGcmHandler = {
//    .Start  = AesGcm_Start,
//    .Update = AesGcm_Update,
//    .Finish = AesGcm_Finish,
//    .Reset  = AesGcm_Reset
//};
//
//static const CryptoServiceHandler* GetHandlerForService(Crypto_ServiceType service) {
//    switch (service) {
//        case CRYPTO_MACGENERATE:
//        case CRYPTO_MACVERIFY:
//            return &AesGcmHandler;
//        // Add other handlers (SHA, RNG, etc.)
//        default:
//            return NULL;
//    }
//}


/* Main processing per AUTOSAR SWS requirements */
Std_ReturnType Crypto_ProcessJob(uint32 objectId, Crypto_JobType* job)
{
    /* Parameter validation and [SWS_Crypto_00118] */
    if (job == NULL || objectId >= CRYPTO_MAX_DRIVER_OBJECTS) {
        return E_NOT_OK;
    }
    printf("1\n");
    const CryptoDriverObject* const* drv = &Crypto_GlobalConfigPtr->DriverObjectRefs[objectId];
    driveobject_type*            obj   =  &Driverobjects[objectId];                            // our driver object that holds the status
  
//    Crypto_JobStateType          state = ObjectsStatus[objectId];
    uint8  mode  = job->jobPrimitiveInputOutput.mode;
    bool start  = (mode & CRYPTO_OPERATIONMODE_START)  != 0;
    bool update = (mode & CRYPTO_OPERATIONMODE_UPDATE) != 0;
    bool finish = (mode & CRYPTO_OPERATIONMODE_FINISH) != 0;
    bool single = (mode & CRYPTO_OPERATIONMODE_SINGLECALL) == CRYPTO_OPERATIONMODE_SINGLECALL;
    printf("%d\n",single);
    Std_ReturnType retVal = E_NOT_OK;
    printf("2\n");
    if (*drv == &CryptoObject_MAC) {
        printf("3\n");
        /* START handling per [SWS_Crypto_00020] and note */
        if (obj->status == CRYPTO_JOBSTATE_IDLE) {
            if (!start) { //The only legal operation when you’re in Idle is to start a new job.
                
                return E_NOT_OK;
            }
            /* Initialize new job */
            obj->jobId   = job->jobId;
            obj->status = CRYPTO_JOBSTATE_ACTIVE;
            job->jobState           = CRYPTO_JOBSTATE_ACTIVE;
            printf("4\n");
            AesGcm_Reset(obj);
            printf("5\n");
            AesGcm_Start(obj, job);
            printf("6\n");
            
            
        } else {
            /* ACTIVE state */
            if (start) {
                /* Cancel previous only if not actively being processed */
                
                /* Initialize new job */
                obj->jobId   = job->jobId;
                obj->status = CRYPTO_JOBSTATE_ACTIVE;
                job->jobState = CRYPTO_JOBSTATE_ACTIVE;
                AesGcm_Reset(obj);
                AesGcm_Start(obj, job);

            } else if (obj->jobId   != job->jobId) { //lw galy update aw finish mn job tanya fa da error
                /* UPDATE/FINISH on wrong job */
                return CRYPTO_E_BUSY;
            }
        }

        /* Single-call must perform START, UPDATE, FINISH in order [SWS_Crypto_00017] */
        if (single) {
            update = true;
            finish = true;
        }

        /* UPDATE: feed streaming chunks [SWS_Crypto_00118 note] */
        if (update) {
            retVal = AesGcm_Update(obj, job);
            if (retVal != E_OK) {
                printf("E_NOT_OK");
                /* Cleanup on streaming error [SWS_Crypto_00025] */
                //ObjectsStats[objectId] = CRYPTO_JOBSTATE_IDLE;
                obj->status = CRYPTO_JOBSTATE_IDLE;
                job->jobState = CRYPTO_JOBSTATE_IDLE;
                return retVal;

                }
            }
        }

        /* FINISH: finalize, output, and go to Idle [SWS_Crypto_00023] */
        if (finish) {
            
            retVal =  AesGcm_Finish(obj, job);
            if (retVal == E_OK) {
                //ObjectsStatus[objectId] = CRYPTO_JOBSTATE_IDLE;
                obj->status = CRYPTO_JOBSTATE_IDLE;
                job->jobState = CRYPTO_JOBSTATE_IDLE;
                // Crypto_ResetBuffers(obj);//////////////problem not defined
                AesGcm_Reset(obj);
            } else {
                /* Cleanup on finalization error [SWS_Crypto_00025/00119] */
                //ObjectsStatus[objectId] = CRYPTO_JOBSTATE_IDLE;
                obj->status = CRYPTO_JOBSTATE_IDLE;
                job->jobState           = CRYPTO_JOBSTATE_IDLE;
                // Crypto_ResetBuffers(drv);/////////////////problem not defined
                AesGcm_Reset(obj);
                
            }
            return retVal;
        }

       
    }
    


int main()
{
    // printf("1\n");
    Crypto_JobType macVerifyJob;
    macVerifyJob.jobState = CRYPTO_JOBSTATE_IDLE;

    // Initialize your data, MAC, and result variables (example values)
    uint8 data[] = {0x01, 0x02, 0x03}; // Your actual data
    uint32 dataLength = sizeof(data);
    uint8 mac[] = {0xA1, 0xB2, 0xC3}; // Your actual MAC value
    uint32 macLength = sizeof(mac);
    Crypto_VerifyResultType verifyResult;

    // Assign pointers to your data and MAC
    const uint8* dataPtr = data;
    const uint8* macPtr = mac;
    Crypto_VerifyResultType* verifyPtr = &verifyResult;
    
    // Configure Input/Output parameters
    macVerifyJob.jobPrimitiveInputOutput.inputPtr = dataPtr;
    macVerifyJob.jobPrimitiveInputOutput.inputLength = dataLength;

    macVerifyJob.jobPrimitiveInputOutput.secondaryInputPtr = macPtr;
    macVerifyJob.jobPrimitiveInputOutput.secondaryInputLength = macLength;

    macVerifyJob.jobPrimitiveInputOutput.verifyPtr = verifyPtr;

    macVerifyJob.jobPrimitiveInfo->primitiveInfo->service = CRYPTO_MACVERIFY;
    macVerifyJob.jobPrimitiveInputOutput.mode=CRYPTO_OPERATIONMODE_SINGLECALL;
    // Initialize Crypto module with configuration
    // printf("3\n");
    Crypto_Init(&Crypto_PBConfig);
    // printf("4\n");
    // Configure Primitive Information (algorithm details)
    // macVerifyJob.jobPrimitiveInfo.primitiveInfo.service = CRYPTO_MACVERIFY;
    // macVerifyJob.jobPrimitiveInfo.primitiveInfo.algorithm.family = CRYPTO_ALGOFAMILY_CMAC; // Example: CMAC
    // macVerifyJob.jobPrimitiveInfo.primitiveInfo.algorithm.keyLength = 128; // Key length in bits
    // macVerifyJob.jobPrimitiveInfo.primitiveInfo.algorithm.mode = CRYPTO_ALGOMODE_CBC; // Example mode

    // Set cryptographic key ID (example value)
    macVerifyJob.cryptoKeyId = 0; // Use your actual key ID

    // Configure job parameters
    // macVerifyJob.jobPriority = CRYPTO_JOB_PRIORITY_MEDIUM; // Example priority
    // macVerifyJob.PrimitiveInfo.processingType = CRYPTO_PROCESSING_SYNCHRONOUS; // Sync processing
    macVerifyJob.jobState = CRYPTO_JOBSTATE_ACTIVE;

    // Process the job
    Crypto_ProcessJob(0, &macVerifyJob);

    // Check verification result
    if(*verifyPtr == 0x00) {
        printf("MAC verification succeeded - Message is authentic\n");
    } else {
        printf("MAC verification failed - Potential tampering detected!\n");
        // You might also want to handle the error here
    }
    while (1);
    return 0;
}

































// #include "../include/Crypto.h"
// #include "../include/Crypto_Cfg.h"
// #include "../include/Crypto_GeneralTypes.h"
// #include "../include/Std_Types.h"
// #include "stdbool.h"
// #include "stdio.h"

// bool Crypto_ModuleInitialized= FALSE;
// Crypto_JobStateType ObjectsStatus[10] ={CRYPTO_JOBSTATE_IDLE}; //Accessed by object id
// Crypto_JobType* CurrentJobs[10];


// void Crypto_ReportError(uint8 ApiId, uint8 ErrorId)
// {
//     printf("Crypto Error - API ID: 0x%02X, Error ID: 0x%02X\n",
//            (unsigned)ApiId,
//            (unsigned)ErrorId);
// }


// /* Global pointer to the active configuration */
// static const Crypto_ConfigType* Crypto_GlobalConfigPtr = NULL_PTR;

// /* Tracks each key’s validity (0 = valid, 1 = invalid) */
// static uint8 Crypto_KeyState[CRYPTO_MAX_KEYS];



// /**
//  * @brief   Initialize the Crypto driver.
//  * @param   configPtr  Pointer to the post-build configuration (e.g. &Crypto_PBConfig)
//  *                    SHALL always be non-NULL
//  * @sws     SWS_Crypto_00045  Report CRYPTO_E_INIT_FAILED on any init failure
//  * @sws     SWS_Crypto_00198  Mark any key missing in config as invalid
//  */
// void Crypto_Init(const Crypto_ConfigType* configPtr)
// {
//     printf("11111Hello, World!\n");

//     boolean initFailed = FALSE;

//     /* 1) Validate the passed-in configPtr */
//     if (configPtr == NULL_PTR) {
//         initFailed = TRUE;
//     } else {
//         Crypto_GlobalConfigPtr = configPtr;
//     }

//     /* 2) Initialize Driver Objects */
//     if (Crypto_GlobalConfigPtr != NULL_PTR) {
//         for (uint32 i = 0; i < Crypto_GlobalConfigPtr->NumDriverObjects; ++i) {
//             if (Crypto_GlobalConfigPtr->DriverObjectRefs[i] == NULL_PTR) {
//                 initFailed = TRUE;
//             }
//         }
//     }

//     /* 3) Initialize Keys (no NVM: just check presence) */
//     if (Crypto_GlobalConfigPtr != NULL_PTR) {
//         for (uint32 i = 0; i < Crypto_GlobalConfigPtr->NumKeys; ++i) {
//             if (Crypto_GlobalConfigPtr->KeyRefs[i] == NULL_PTR) {
//                 Crypto_KeyState[i] = KEY_STATE_INVALID;
//                 initFailed = TRUE;
//             } else {
//                 Crypto_KeyState[i] = KEY_STATE_VALID;
//             }
//         }
//     }

//     /* 4) Report overall init failure if any sub-step failed */
//     if (initFailed) {
//         Crypto_ReportError(CRYPTO_INIT_API_ID, CRYPTO_E_INIT_FAILED);

//     }
//  Crypto_ModuleInitialized= TRUE;

// }


// /* Function for Crypto Get Version Info API */
// #if (CRYPTO_VERSION_INFO_API == STD_ON)
// void Crypto_GetVersionInfo (Std_VersionInfoType* versioninfo);
// #endif

// /* Function for Cancel Processing of jobs in Crypto stack */
// Std_ReturnType Crypto_CancelJob (uint32 objectId,Crypto_JobType* job);

// /* Function for Process jobs in Crypto stack */
// Std_ReturnType Crypto_ProcessJob(uint32 objectId, Crypto_JobType* job) {
//     CryptoDriverObject* driverObject;
//     Std_ReturnType retVal = E_NOT_OK;
//     bool canProcessJob = FALSE;
//     // bool needsReset = FALSE; //Will be used when Start or Finish happens
    
//     // /* [SWS_Crypto_00057] Check initialization */
//     // if (!Crypto_ModuleInitialized) {//this parameter will be a bool var and i will initialize then check it
//     //     Crypto_ReportError(CRYPTO_PROCESSJOB_API_ID, CRYPTO_E_UNINIT);
//     //     return E_NOT_OK;
//     // }

//     // SchM_Enter_Crypto_CRYPTO_EXCLUSIVE_AREA();//i will make it as soon as possible

//     // /* [SWS_Crypto_00059] Null pointer check */
//     // if (job == NULL_PTR) {
//     //     Crypto_ReportError(CRYPTO_PROCESSJOB_API_ID, CRYPTO_E_PARAM_POINTER);
//     //     SchM_Exit_Crypto_CRYPTO_EXCLUSIVE_AREA();//i will make it as soon as possible
//     //     return E_NOT_OK;
//     // }

//     // /* [SWS_Crypto_00058] Validate objectId range */
//     // driverObject = Crypto_GetDriverObject(objectId);//will be implemented
//     // if (driverObject == NULL_PTR) {
//     //     Crypto_ReportError(CRYPTO_PROCESSJOB_API_ID, CRYPTO_E_PARAM_HANDLE);
//     //     SchM_Exit_Crypto_CRYPTO_EXCLUSIVE_AREA();//i will make it as soon as possible
//     //     return E_NOT_OK;
//     // }

//     // /* [SWS_Crypto_00064] Validate supported service */
//     // if (!Crypto_IsServiceSupported(driverObject, job->jobPrimitiveInfo->primitiveInfo->service)) {//this function will be implemented
//     //     Crypto_ReportError(CRYPTO_PROCESSJOB_API_ID, CRYPTO_E_PARAM_HANDLE);
//     //     SchM_Exit_Crypto_CRYPTO_EXCLUSIVE_AREA();//i will make it as soon as possible
//     //     return E_NOT_OK;
//     // }

//     // /* [SWS_Crypto_00202] Key derivation validation */
//     // if (job->jobPrimitiveInfo->primitiveInfo->service == CRYPTO_KEYDERIVE) {
//     //     if (!Crypto_IsKeyIdValid(job->targetCryptoKeyId)) {
//     //         Crypto_ReportError(CRYPTO_PROCESSJOB_API_ID, CRYPTO_E_PARAM_HANDLE);
//     //         SchM_Exit_Crypto_CRYPTO_EXCLUSIVE_AREA();//i will make it as soon as possible
//     //         return E_NOT_OK;
//     //     }
//     // }

//     // /* [SWS_Crypto_00067] Algorithm validation */
//     // if (!Crypto_CheckAlgorithmSupport(driverObject, job->jobPrimitiveInfo->primitiveInfo->algorithm)) {//this function will be implemented
//     //     Crypto_ReportError(CRYPTO_PROCESSJOB_API_ID, CRYPTO_E_PARAM_HANDLE);
//     //     SchM_Exit_Crypto_CRYPTO_EXCLUSIVE_AREA();//i will make it as soon as possible
//     //     return E_NOT_OK;
//     // }

//     // /* [SWS_Crypto_00070] Buffer pointer validation */
//     // if (!Crypto_ValidateRequiredPointers(job)) {//this function will be implemented
//     //     Crypto_ReportError(CRYPTO_PROCESSJOB_API_ID, CRYPTO_E_PARAM_POINTER);
//     //     SchM_Exit_Crypto_CRYPTO_EXCLUSIVE_AREA();//i will make it as soon as possible
//     //     return E_NOT_OK;
//     // }

//     // /* [SWS_Crypto_00142] Length validation */
//     // if (!Crypto_ValidateLengths(job)) {//this function will be implemented
//     //     Crypto_ReportError(CRYPTO_PROCESSJOB_API_ID, CRYPTO_E_PARAM_VALUE);
//     //     SchM_Exit_Crypto_CRYPTO_EXCLUSIVE_AREA();//i will make it as soon as possible
//     //     return E_NOT_OK;
//     // }

//     // /* Context handling [SWS_Crypto_00228-00231] */
//     // if (job->jobPrimitiveInputOutput->mode == CRYPTO_OPERATIONMODE_SAVE_CONTEXT ||
//     //     job->jobPrimitiveInputOutput->mode == CRYPTO_OPERATIONMODE_RESTORE_CONTEXT) {

//     //     if (!driverObject->config.supportContext) {//i will see it later
//     //         SchM_Exit_Crypto_CRYPTO_EXCLUSIVE_AREA();//i will make it as soon as possible
//     //         return E_NOT_OK;
//     //     }

//     //     if (job->jobPrimitiveInputOutput->mode == CRYPTO_OPERATIONMODE_SAVE_CONTEXT) {
//     //         /* [SWS_Crypto_00229] Save context validation */
//     //         if (job->jobPrimitiveInputOutput->outputLengthPtr < driverObject->contextSize) {
//     //             SchM_Exit_Crypto_CRYPTO_EXCLUSIVE_AREA();//i will make it as soon as possible
//     //             return E_NOT_OK;
//     //         }

//     //         /* [SWS_Crypto_00230] Save context implementation */
//     //         retVal = Crypto_SaveContext(driverObject, job);//i will see it later
//     //     }
//     //     else {
//     //         /* [SWS_Crypto_00231] Restore context validation */
//     //         if (job->jobPrimitiveInputOutput->inputLength < driverObject->contextSize) {
//     //             SchM_Exit_Crypto_CRYPTO_EXCLUSIVE_AREA();//i will make it as soon as possible
//     //             return E_NOT_OK;
//     //         }

//     //         retVal = Crypto_RestoreContext(driverObject, job);//i will see it later
//     //     }

//     //     SchM_Exit_Crypto_CRYPTO_EXCLUSIVE_AREA();//i will make it as soon as possible
//     //     return retVal;
//     // }
// /*
//     mac_gen(job1,data,start)
//     mac_gen(job1,data1,update)
//     mac_gen(job2,data,start)
// */
//     if (ObjectsStatus[objectId] == CRYPTO_JOBSTATE_ACTIVE)
//     {
//         if (job == CurrentJobs[objectId])
//         {
//             if (job->jobPrimitiveInputOutput.mode == CRYPTO_OPERATIONMODE_START)//#define CRYPTO_OPERATIONMODE_START 0x01
//             {
//                 // Reset buffers and restart current job
//                 canProcessJob = true;
//                 // needsReset = true;
//             }
//             else //Update Or Finish(Don't forget to go to idle state and reset buffers)0x02 Error, 0x03 
//             {
//                 canProcessJob = true;
//                 // needsReset = false;
//             }
//         }
//         else // job != currentJob
//         {
//             if (job->jobPrimitiveInputOutput.mode == CRYPTO_OPERATIONMODE_START)
//             {
//                 // Cancel currentJob and start new job
//                 CurrentJobs[objectId] = job;
//                 // input = *CurrentJobs[objectId]->jobPrimitiveInputOutput->inputptr;
//                 // output = *CurrentJobs[objectId]->jobPrimitiveInputOutput->outputptr;
//                 canProcessJob = true;
//                 // needsReset = true;
//                 // Reset buffers, enter ACTIVE state
//             }
//             else
//             {
//                 canProcessJob = false;
//                 retVal = CRYPTO_E_BUSY;
//             }
//         }
//     }
//     else if (ObjectsStatus[objectId] == CRYPTO_JOBSTATE_IDLE)// DriverState == IDLE
//     {
//         if (job->jobPrimitiveInputOutput.mode == CRYPTO_OPERATIONMODE_START)
//         {
//             // Initialize job context, move to ACTIVE
//             canProcessJob = true;
//             // needsReset = false; //we don't need that here as IDLE = Reseted
//             CurrentJobs[objectId] = job;
//             ObjectsStatus[objectId] = CRYPTO_JOBSTATE_ACTIVE;
//             job->jobState = CRYPTO_JOBSTATE_ACTIVE;
//         }
//         else
//         {
//             // No active job to update/finish — reject
//             canProcessJob = false;
//             // needsReset=false;
//             retVal = E_NOT_OK;
//         }
//     }

//     // if (needsReset) {
//     //     Crypto_ResetBuffers(driverObject);//Needs to be implemented
//     // }
    
//     if(canProcessJob)
//     {
//         /* Handle standard processing */
//         //we will stress here later
//         switch(job->jobPrimitiveInfo->primitiveInfo->service) {
//             case CRYPTO_HASH:
//             case CRYPTO_MACGENERATE:
//                 /* [SWS_Crypto_00065] Truncate output if needed */
//                 retVal = Crypto_HandleHmacHash(job, driverObject);
//                 break;

//             case CRYPTO_RANDOMGENERATE:
//                 /* [SWS_Crypto_00252] Random generation handling */
//                 retVal = Crypto_HandleRandomGeneration(job, driverObject);
//                 break;

//             default:
//                 // /* Standard processing */
//                 // if (driverObject->config.executionMode == CRYPTO_EXECUTION_SYNC) {
//                 //     retVal = Crypto_ProcessJobSync(driverObject, job);
//                 // } else {
//                 //     retVal = Crypto_QueueJob(driverObject, job);
//                 // }
//                 // break;
//         }
//     }
//     SchM_Exit_Crypto_CRYPTO_EXCLUSIVE_AREA();
//     return retVal;
// }

// int main()
// {
//     Crypto_JobType macVerifyJob;
//     macVerifyJob.jobState =  CRYPTO_JOBSTATE_IDLE;
//     const uint8* dataPtr=;
//     uint32 dataLength=;
//     const uint8* macPtr=;
//     uint32 macLength=;
//     Crypto_VerifyResultType* verifyPtr=;
//     macVerifyJob.jobPrimitiveInputOutput.inputPtr = dataPtr;
//     macVerifyJob.jobPrimitiveInputOutput.inputLength = dataLength;
    
//     macVerifyJob.jobPrimitiveInputOutput.secondaryInputPtr = macPtr;
//     macVerifyJob.jobPrimitiveInputOutput.secondaryInputLength = macLength;

//     macVerifyJob.jobPrimitiveInputOutput.verifyPtr = verifyPtr;
    
//     Crypto_Init(&Crypto_PBConfig);
//     Crypto_ProcessJob(0,&macVerifyJob);

//     return 0;
// }

