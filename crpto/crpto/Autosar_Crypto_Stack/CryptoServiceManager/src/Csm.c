#include "Csm.h"
#include "Csm_Cfg.h"
#include "Crypto.h"
#include "Crypto_Cfg.h"
#include "Crypto_GeneralTypes.h"
#include "Std_Types.h"
#include "stdbool.h"
#include "stdio.h"
#include "mbedtls/gcm.h"

uint32_t jobtypeID_Counter = 0;
Std_ReturnType Csm_MacGenerate(
    uint32 jobId,
    Crypto_OperationModeType mode,
    const uint8* dataPtr,
    uint32 dataLength,
    const uint8* macPtr,
    uint32* macLengthPtr,
   )
   {
   if (dataPtr == NULL || macPtr == NULL || macLengthPtr == NULL || jobId >= NUM_CSM_JOBS) {
       return E_NOT_OK;
   }
//    if (macLength % 8 != 0) {
//        return E_NOT_OK; // OR Error handling
//    }

   Std_ReturnType returnVal;
   Crypto_JobType macGenerateJob ={
    .jobPriority = JobList[jobId].CsmJobPriority,
   };



   CsmKey CsmKey = CsmKeys[JobList[jobId].CsmJobKeyRef->CsmKeyId]; // Getting the the required CsmKey from the CsmJob
   macGenerateJob.jobId = jobId; // Make an algorithm for id assignments
   
   // Set the input data and MAC pointers along with their lengths
   macGenerateJob.jobPrimitiveInputOutput.inputPtr = dataPtr;
   macGenerateJob.jobPrimitiveInputOutput.inputLength = dataLength;

   // Set the output data and MAC pointers along with their lengths
   macGenerateJob.jobPrimitiveInputOutput.outputPtr = macPtr ;      				
   macGenerateJob.jobPrimitiveInputOutput.outputLengthPtr = macLengthPtr;				
   
   macGenerateJob.jobPrimitiveInputOutput.mode = mode ;
   

   macGenerateJob.jobPrimitiveInputOutput.cryIfKeyId = CsmKey.CsmKeyRef->CryifKeyId; //Fetch the cryIfKeyId from the referenced CsmKey

   
   Crypto_JobPrimitiveInfoType Crypto_JobPrimitiveInfoInstance;

   
   Crypto_PrimitiveInfoType primitiveInfoInstance ={
    .service= CRYPTO_MACGENERATE,   // Set the crypto service type to MAC generation

    /* Configure algorithm parameters for the MAC operation*/
    .algorithm = {
        .family= JobList[jobId].CsmJobPrimitiveRef.CsmMacGenerate.CsmMacGenerateConfig.CsmMacGenerateAlgorithmFamily,
        .keyLength = JobList[jobId].CsmJobPrimitiveRef.CsmMacGenerate.CsmMacGenerateConfig.CsmMacGenerateAlgorithmKeyLength,
        .mode =JobList[jobId].CsmJobPrimitiveRef.CsmMacGenerate.CsmMacGenerateConfig.CsmMacGenerateAlgorithmMode,
    }
   };
   macGenerateJob.jobPrimitiveInfo= &Crypto_JobPrimitiveInfoInstance;
   macGenerateJob.jobPrimitiveInfo->primitiveInfo= &primitiveInfoInstance;
   macGenerateJob.jobPrimitiveInfo->processingType = JobList[jobId].CsmProcessingMode;
   macGenerateJob.jobPrimitiveInfo->crylfKeyId =  CsmKey.CsmKeyRef->CryifKeyId;
   macGenerateJob.jobState = CRYPTO_JOBSTATE_ACTIVE;
   
   returnVal = CryIf_ProcessJob(channelId, &macGenerateJob);
   switch (returnVal) {
           case E_OK:
           case CRYPTO_E_BUSY:
           case CRYPTO_E_KEY_NOT_VALID:
           case CRYPTO_E_KEY_SIZE_MISMATCH:
           case CRYPTO_E_KEY_EMPTY:
               return returnVal;
   
           default:
               // All other CryIf-specific errors are not in CSM's return spec.
               return E_NOT_OK;
   }
   }
   
   



Std_ReturnType Csm_MacVerify(
 uint32 jobId,
 Crypto_OperationModeType mode,
 const uint8* dataPtr,
 uint32 dataLength,
 const uint8* macPtr,
 uint32 macLength,
 Crypto_VerifyResultType* verifyPtr
)
{
if (dataPtr == NULL || macPtr == NULL || verifyPtr == NULL || jobId >= NUM_CSM_JOBS) {
    return E_NOT_OK;
}
if (macLength % 8 != 0) {
    return E_NOT_OK; // OR Error handling
}
Std_ReturnType returnVal;
Crypto_JobType macVerifyJob ={
    .jobPriority = JobList[jobId].CsmJobPriority,
};

CsmKey_Type CsmKey = CsmKeys[JobList[jobId].CsmJobKeyRef->CsmKeyId]; // Getting the the required CsmKey from the CsmJob
macVerifyJob.jobId = jobId; // Make an algorithm for id assignments

// Set the input data and MAC pointers along with their lengths
macVerifyJob.jobPrimitiveInputOutput.inputPtr = dataPtr;
macVerifyJob.jobPrimitiveInputOutput.inputLength = dataLength;

macVerifyJob.jobPrimitiveInputOutput.secondaryInputPtr = macPtr;
//maclength is in BITS so it had to be casted to BYTES
macVerifyJob.jobPrimitiveInputOutput.secondaryInputLength = macLength / 8; 

macVerifyJob.jobPrimitiveInputOutput.verifyPtr = verifyPtr;
macVerifyJob.jobPrimitiveInputOutput.mode = mode; 
macVerifyJob.jobPrimitiveInputOutput.cryIfKeyId = CsmKey.CsmKeyRef->CryifKeyId; //Getting the cryifKeyid from the CsmKey
//macVerifyJob.cryptokeyid = cryifkey[cryIfKeyId].keyref->id //Cryif -> Cryptokey in CRYIF layer



//macVerifyJob.PrimitiveInfo.primitiveInfo.callbackId = ; 			//todo : for Asynchronous

Crypto_JobPrimitiveInfoType Crypto_JobPrimitiveInfoInstance;


Crypto_PrimitiveInfoType primitiveInfoInstance ={
    .service= CRYPTO_MACVERIFY,   // Set the crypto service type to MAC Verify

    /* Configure algorithm parameters for the MAC operation*/
    .algorithm = {
        .family= JobList[jobId].CsmJobPrimitiveRef.CsmMacVerify.CsmMacVerifyConfig.CsmMacVerifyAlgorithmFamily,
        .keyLength = JobList[jobId].CsmJobPrimitiveRef.CsmMacVerify.CsmMacVerifyConfig.CsmMacVerifyAlgorithmKeyLength,
        .mode =JobList[jobId].CsmJobPrimitiveRef.CsmMacVerify.CsmMacVerifyConfig.CsmMacVerifyAlgorithmMode,
    }
   };


macVerifyJob.jobPrimitiveInfo = &Crypto_JobPrimitiveInfoInstance;

macVerifyJob.jobPrimitiveInfo->primitiveInfo= & primitiveInfoInstance;

macVerifyJob.jobPrimitiveInfo->processingType = JobList[jobId].CsmProcessingMode;
macVerifyJob.jobPrimitiveInfo->crylfKeyId = CsmKey.CsmKeyRef->CryifKeyId; 

macVerifyJob.jobState = CRYPTO_JOBSTATE_ACTIVE;

returnVal = CryIf_ProcessJob(channelId, &macVerifyJob);
switch (returnVal) {
        case E_OK:
        case CRYPTO_E_BUSY:
        case CRYPTO_E_KEY_NOT_VALID:
        case CRYPTO_E_KEY_SIZE_MISMATCH:
        case CRYPTO_E_KEY_EMPTY:
            return returnVal;

        default:
            // All other CryIf-specific errors are not in CSM's return spec.
            return E_NOT_OK;
}
}

