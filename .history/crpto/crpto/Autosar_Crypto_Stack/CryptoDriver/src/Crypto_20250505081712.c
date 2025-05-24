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
        for (uint32 i = 0; i < Crypto_GlobalConfigPtr->NumDriverObjects; ++i) {//2
            if (Crypto_GlobalConfigPtr->DriverObjectRefs[i] == NULL_PTR) {
                initFailed = TRUE;
            }
            Driverobjects[i].DriverObjectId = Crypto_GlobalConfigPtr->DriverObjectRefs[i]->CryptoDriverObjectId;
            
            Driverobjects[i].status=CRYPTO_JOBSTATE_IDLE;
            
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
    
    if (initFailed) {
        Crypto_ReportError(CRYPTO_INIT_API_ID, CRYPTO_E_INIT_FAILED);

    }
}




static Std_ReturnType AesGcm_Start(driveobject_type* drv, const Crypto_JobType* job) {
    mbedtls_gcm_init(&gcm);
    printf("Start\n");
    printf("55\n");
    // [!] Get key from driveobject_type's CryptoKey
    const CryptoKey* key = &drv->Key;
    if (key->CryptoKeyTypeRef == NULL ||
        key->CryptoKeyTypeRef->CryptoKeyElementRef == NULL) {
        return E_NOT_OK; // Key not configured
    }
    printf("5\n");
    // [!] Access the first CryptoKeyElement
    const CryptoKeyElement* keyElement = key->CryptoKeyTypeRef->CryptoKeyElementRef;
    const uint8* keyData = keyElement->CryptoKeyElementInitValue;
    size_t keyLength = keyElement->CryptoKeyElementSize;

    // [!] Validate key length (e.g., 16, 24, 32 bytes for AES)
    if (keyLength != 16 && keyLength != 24 && keyLength != 32) {
        return E_NOT_OK; // Invalid AES key size
    }
    printf("4\n");
    // [!] Determine mode (Encrypt for Generate, Decrypt for Verify)
    int mode;
    if(job->jobPrimitiveInfo->primitiveInfo->service == CRYPTO_MACGENERATE 
       || job->jobPrimitiveInfo->primitiveInfo->service == CRYPTO_MACVERIFY
       || job->jobPrimitiveInfo->primitiveInfo->service == CRYPTO_ENCRYPT)
        {
            mode =MBEDTLS_GCM_ENCRYPT;
        }
    else if(job->jobPrimitiveInfo->primitiveInfo->service == CRYPTO_DECRYPT)
        {
            mode =MBEDTLS_GCM_DECRYPT;
        }
    printf("%d Service\n",job->jobPrimitiveInfo->primitiveInfo->service);
    printf("3\n");
    // [!] Set key from CryptoKeyElementInitValue
    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES,
                                keyData, keyLength * 8);
    if (ret != 0) return E_NOT_OK;

    // [!] Initialize with IV
    uint8 iv[12] = { 0x00, 0x11, 0x22, 0x33, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0xFF, 0xFF };
    size_t iv_len = 12;
    ret = mbedtls_gcm_starts(&gcm, mode, iv, iv_len);
    printf("Start : %d/n",ret);
    return (ret == 0) ? E_OK : E_NOT_OK;
}


static Std_ReturnType AesGcm_Update(driveobject_type* drv, const Crypto_JobType* job) {
    const uint8* input = job->jobPrimitiveInputOutput.inputPtr;
    size_t input_len = job->jobPrimitiveInputOutput.inputLength;
    printf("%d\n",input_len);
    uint8* output = job->jobPrimitiveInputOutput.outputPtr;
    printf("Update");
    size_t output_len = *(job->jobPrimitiveInputOutput.outputLengthPtr);
    printf("10\n");
    int ret = mbedtls_gcm_update(&gcm, input, input_len,
                                output, 16, &output_len);//data --> mac
    printf("11\n");
    printf("%d\n",ret);

    return (ret == 0) ? E_OK : E_NOT_OK;
}

static Std_ReturnType AesGcm_Finish(driveobject_type* drv, Crypto_JobType* job) {
    size_t tag_len=16;
    uint8 tag[tag_len];
    
    uint8* output = job->jobPrimitiveInputOutput.outputPtr;
    size_t output_length = *(job->jobPrimitiveInputOutput.outputLengthPtr);
    int ret; 
    // [!] Finalize and handle Generate/Verify logic
    if (job->jobPrimitiveInfo->primitiveInfo->service == CRYPTO_MACGENERATE) {
        ret = mbedtls_gcm_finish(&gcm,output,sizeof(output),&output_length, tag, tag_len); 

        
        // printf("Finish :");
        // for (size_t i = 0; i < 16; i++) {
        //     printf("%02x ", output[i]);
        // }
        // printf("\nTag :");
        // for (size_t i = 0; i < sizeof(tag)/sizeof(tag[0]); i++) {
        //     printf("%02x ", tag[i]);
        // }  
        for(int i =0 ;i<tag_len;i++)
        {
            job->jobPrimitiveInputOutput.outputPtr[i] = tag[i];
        }
        *(job->jobPrimitiveInputOutput.outputLengthPtr) = (uint32)tag_len;
    } 
    else if (job->jobPrimitiveInfo->primitiveInfo->service == CRYPTO_MACVERIFY)
    {
        // Verify MAC tag
        uint8* expected_tag = job->jobPrimitiveInputOutput.secondaryInputPtr;
        ret = mbedtls_gcm_finish(&gcm,output,sizeof(output),&output_length, tag, tag_len);
        // for (size_t i = 0; i < tag_len; i++) {
        //     printf("%02x ", output[i]);
        // }
        // printf("\nTag :");
        // for (size_t i = 0; i < tag_len; i++) {
        //     printf("%02x ", tag[i]);
        // }

        if (ret == 0 ) {
            *(job->jobPrimitiveInputOutput.verifyPtr) = CRYPTO_E_VER_OK;
            for(int i = 0;i<tag_len;i++)
            {
                if(expected_tag[i] != tag[i])
                {
                    *(job->jobPrimitiveInputOutput.verifyPtr) = CRYPTO_E_VER_NOT_OK;
                }
            }
            printf("done");
        } else{
            printf("not done");

        }
    }
    else if (job->jobPrimitiveInfo->primitiveInfo->service == CRYPTO_ENCRYPT)
    {
        ret = mbedtls_gcm_finish(&gcm,output,sizeof(output),&output_length, tag, tag_len); 
        for(int i =0 ;i<tag_len;i++)
        {
            job->jobPrimitiveInputOutput.outputPtr[i] = output[i];
        }
        // *(job->jobPrimitiveInputOutput.outputLengthPtr) = (uint32)output_length;
        // printf("%d\n",*(job->jobPrimitiveInputOutput.outputLengthPtr));
        // printf("%d\n",output_length);
        // printf("Finish :");
        // for (size_t i = 0; i < 16; i++) {
        //     printf("%02x ", output[i]);
        // }
        // printf("\nTag :");
        // for (size_t i = 0; i < sizeof(tag)/sizeof(tag[0]); i++) {
        //     printf("%02x ", tag[i]);
        // }  
    }
else if (job->jobPrimitiveInfo->primitiveInfo->service == CRYPTO_DECRYPT)
    {
        ret = mbedtls_gcm_finish(&gcm,output,sizeof(output),&output_length, tag, tag_len); 
        for(int i =0 ;i<tag_len;i++)
        {
            job->jobPrimitiveInputOutput.outputPtr[i] = output[i];
        }
        // printf("Finish :");
        // for (size_t i = 0; i < 16; i++) {
        //     printf("%02x ", output[i]);
        // }
        // printf("\nTag :");
        // for (size_t i = 0; i < sizeof(tag)/sizeof(tag[0]); i++) {
        //     printf("%02x ", tag[i]);
        // }  
    }

    return (ret == 0) ? E_OK : E_NOT_OK;
}

static void AesGcm_Reset(driveobject_type* drv) {
    
    mbedtls_gcm_free(&gcm);
}



/* Main processing per AUTOSAR SWS requirements */
Std_ReturnType Crypto_ProcessJob(uint32 objectId, Crypto_JobType* job)
{
    /* Parameter validation and [SWS_Crypto_00118] */
    if (job == NULL || objectId >= CRYPTO_MAX_DRIVER_OBJECTS) {
        return E_NOT_OK;
    }
    const CryptoDriverObject* const* drv = &Crypto_GlobalConfigPtr->DriverObjectRefs[objectId];
    driveobject_type*            obj   =  &Driverobjects[objectId];                            // our driver object that holds the status

    uint8  mode  = job->jobPrimitiveInputOutput.mode;
    bool start  = (mode & CRYPTO_OPERATIONMODE_START)  != 0;
    bool update = (mode & CRYPTO_OPERATIONMODE_UPDATE) != 0;
    bool finish = (mode & CRYPTO_OPERATIONMODE_FINISH) != 0;
    bool single = (mode & CRYPTO_OPERATIONMODE_SINGLECALL) == CRYPTO_OPERATIONMODE_SINGLECALL;
    printf("%d\n",single);
    Std_ReturnType retVal = E_NOT_OK;
    printf("2\n");
    obj->Key=CryptoKey1;
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
            AesGcm_Reset(obj);
            AesGcm_Start(obj, job);
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
                obj->status = CRYPTO_JOBSTATE_IDLE;
                job->jobState = CRYPTO_JOBSTATE_IDLE;
                return retVal;

                }
            }
        }

        
        if (finish) {
            
            retVal =  AesGcm_Finish(obj, job);
            if (retVal == E_OK) 
            {    
                obj->status = CRYPTO_JOBSTATE_IDLE;
                job->jobState = CRYPTO_JOBSTATE_IDLE;
                
                AesGcm_Reset(obj);
            } 
            else 
            {
                obj->status = CRYPTO_JOBSTATE_IDLE;
                job->jobState           = CRYPTO_JOBSTATE_IDLE;
                AesGcm_Reset(obj);
                
            }
            return retVal;
        }    
}   

//main code
int main()
{
    Crypto_JobType macVerifyJob;
    macVerifyJob.jobState = CRYPTO_JOBSTATE_IDLE;
    // uint8_t data[] = {
    //     0xbc, 0x4f, 0x08, // Original data
    //     0xed, 0x58, 0x36, 0x67, 0xf3, 0x0e, 0x08, 0xc9, 0xa9, 0xe6, 0x7f, 0x7c, 0x77
    // };
    // Initialize your data, MAC, and result variables (example values)
    uint8_t data[] = {
        0x01, 0x02, 0x03, // Original data
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    uint32 dataLength = sizeof(data);
    printf("%d",dataLength);
    // MAC array (16 bytes)
    uint8_t mac[] = {
        0xb8, 0xfb , 0x4b , 0x0f , 0x2a , 0xd0 , 0x25 , 0xbc , 0xe4 , 0x6b , 0x67 , 0x62 , 0x9f , 0x1b , 0xed , 0x9f 
    }; 
    // Your actual MAC value
    uint32 macLength = sizeof(mac);
    Crypto_VerifyResultType verifyResult;
    
    // Assign pointers to your data and MAC
    const uint8* dataPtr = data;
    const uint8* macPtr = mac;
    uint32 outputLenght = 16;
    uint8 output[16] ;
    
    macVerifyJob.jobPrimitiveInputOutput.inputPtr = dataPtr;
    macVerifyJob.jobPrimitiveInputOutput.inputLength = dataLength;
    
    macVerifyJob.jobPrimitiveInputOutput.secondaryInputPtr = macPtr;
    macVerifyJob.jobPrimitiveInputOutput.secondaryInputLength = macLength;

    macVerifyJob.jobPrimitiveInputOutput.outputPtr = output;
    macVerifyJob.jobPrimitiveInputOutput.outputLengthPtr = &outputLenght;

    macVerifyJob.jobPrimitiveInputOutput.verifyPtr = &verifyResult;
    
    
    macVerifyJob.jobPrimitiveInfo = &verifyJob ;
   
    macVerifyJob.jobPrimitiveInputOutput.mode=CRYPTO_OPERATIONMODE_SINGLECALL;
    // Initialize Crypto module with configuration
    Crypto_Init(&Crypto_PBConfig);
    macVerifyJob.cryptoKeyId = 0; // Use your actual key ID
    macVerifyJob.jobState = CRYPTO_JOBSTATE_ACTIVE;

    // Process the job
    Crypto_ProcessJob(0, &macVerifyJob);
    uint8* output1 = macVerifyJob.jobPrimitiveInputOutput.outputPtr;
    // Check verification result
    
    // if(macVerifyJob.jobPrimitiveInfo->primitiveInfo->service == CRYPTO_MACGENERATE)
    // {
    printf("\nOutput:");
    for (int i = 0; i < *(macVerifyJob.jobPrimitiveInputOutput.outputLengthPtr); i++) {
        printf("%02x ", output1[i]);
    }

    if(macVerifyJob.jobPrimitiveInfo->primitiveInfo->service == CRYPTO_MACVERIFY)
    {
        if(*(macVerifyJob.jobPrimitiveInputOutput.verifyPtr) == 0x00) {
            printf("\nMAC verification succeeded - Message is authentic\n");
        } else {
            printf("\nMAC verification failed - Potential tampering detected!\n");
        }
    }

    while (1);
    return 0;
}
