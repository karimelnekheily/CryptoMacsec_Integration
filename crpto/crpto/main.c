//
//  main.c
//  crpto
//
//  Created by Ahmed Khalifa on 4/6/25.
//

#include <stdio.h>

int main(int argc, const char * argv[]) {
    // insert code here...
    printf("Hello, World!\n");
    return 0;
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
   if(dataPtr == NULL  macPtr == NULL  verifyPtr == NULL){
   return E_NOT_OK;     //return failure on invalid input
   }
   
   Crypto_JobType macVerifyJob;
   
   //macVerifyJob.jobId = jobId; // Make an algorithm for id assignments
   
   if ( macVerifyJob.jobState ==  CRYPTO_JOBSTATE_ACTIVE ){
       //return CryIf_ProcessJob(channelId, &macVerifyJob) //Process the job if it's active
   }
   else{
      macVerifyJob.jobState =  CRYPTO_JOBSTATE_ACTIVE; //activate the job state
   }
   // Set the input data and MAC pointers along with their lengths
   macVerifyJob.jobPrimitiveInputOutput.inputPtr = dataPtr;
   macVerifyJob.jobPrimitiveInputOutput.inputLength = dataLength;
   
   macVerifyJob.jobPrimitiveInputOutput.secondaryInputPtr = macPtr;
   macVerifyJob.jobPrimitiveInputOutput.secondaryInputLength = macLength;
   
   //macVerifyJob.jobPrimitiveInputOutput.outputPtr = ;
   //macVerifyJob.jobPrimitiveInputOutput.outputLengthPtr = ;
   
   macVerifyJob.jobPrimitiveInputOutput.verifyPtr = verifyPtr;
   //macVerifyJob.jobPrimitiveInputOutput.mode = mode; ??????????????????????
   
   
   
   
   //macVerifyJob.PrimitiveInfo.primitiveInfo.callbackId = ; //todo : for Asynchronous
   macVerifyJob.PrimitiveInfo->primitiveInfo->service = CRYPTO_MACVERIFY;
   macVerifyJob.PrimitiveInfo.primitiveInfo.algorithm.family = JobList[jobid].csmjobprimitiveref.csmMacVerify.csmmacverifyconfig.CsmMacVerifyAlgorithmFamily ;
   macVerifyJob.PrimitiveInfo.primitiveInfo.algorithm.keyLength = JobList[jobid].csmjobprimitiveref.csmMacVerify.csmmacverifyconfig.CsmMacVerifyAlgorithmKeyLength;
   macVerifyJob.PrimitiveInfo.primitiveInfo.algorithm.mode =JobList[jobid].csmjobprimitiveref.csmMacVerify.csmmacverifyconfig.CsmMacVerifyAlgorithmMode ;
   
   //macVerifyJob.cryptoKeyId =;
   //macVerifyJob.targetCryptoKeyId =;
   macVerifyJob.jobPriority = JobList[jobid].CsmJobPriority;
   //macVerifyJob.PrimitiveInfo.cryIfKeyId = JobList[jobid].CsmJobKeyRef; //as2lllll GPT
   macVerifyJob.PrimitiveInfo.processingType = JobList[jobid].CsmProcessingMode;
   macVerifyJob.jobState = CRYPTO_JOBSTATE_ACTIVE;
   
   //Std_ReturnType ret= return CryIf_ProcessJob(channelId, &macVerifyJob);
   
   if(ret != E_OK){
   return E_NOT_OK;
   }
   
   if(*verifyPtr != CRYPTO_E_VER_OK ){
   return E_NOT_OK;
   } 
   return E_OK;
   
   
   
   } 