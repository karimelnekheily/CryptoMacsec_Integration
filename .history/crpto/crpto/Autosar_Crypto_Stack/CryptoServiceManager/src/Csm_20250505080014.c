uint32_t jobtypeID_Counter = 0;
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
Crypto_JobType macVerifyJob;
//JOBID-->Job-->         CSMKEYID-->CSMKEY-->REF -----> CRYIFKEYID
CsmKey_Type CsmKey = JobList[jobid].CsmJobKeyRef; // Getting the the required CsmKey from the CsmJob

macVerifyJob.jobId = jobId; // Make an algorithm for id assignments

// Set the input data and MAC pointers along with their lengths
macVerifyJob.jobPrimitiveInputOutput.inputPtr = dataPtr;
macVerifyJob.jobPrimitiveInputOutput.inputLength = dataLength;

macVerifyJob.jobPrimitiveInputOutput.secondaryInputPtr = macPtr;
//maclength is in BITS so it had to be casted to BYTES
macVerifyJob.jobPrimitiveInputOutput.secondaryInputLength = macLength / 8; 

//macVerifyJob.jobPrimitiveInputOutput.outputPtr = ;      				//Not Needed
//macVerifyJob.jobPrimitiveInputOutput.outputLengthPtr = ;				//Not Needed

macVerifyJob.jobPrimitiveInputOutput.verifyPtr = verifyPtr;
macVerifyJob.jobPrimitiveInputOutput.mode = mode; 




//macVerifyJob.PrimitiveInfo.primitiveInfo.callbackId = ; 				//todo : for Asynchronous
macVerifyJob.PrimitiveInfo->primitiveInfo->service = CRYPTO_MACVERIFY;
macVerifyJob.PrimitiveInfo.primitiveInfo.algorithm.family = JobList[jobid].csmjobprimitiveref.csmMacVerify.csmmacverifyconfig.CsmMacVerifyAlgorithmFamily ;
macVerifyJob.PrimitiveInfo.primitiveInfo.algorithm.keyLength = JobList[jobid].csmjobprimitiveref.csmMacVerify.csmmacverifyconfig.CsmMacVerifyAlgorithmKeyLength;
macVerifyJob.PrimitiveInfo.primitiveInfo.algorithm.mode =JobList[jobid].csmjobprimitiveref.csmMacVerify.csmmacverifyconfig.CsmMacVerifyAlgorithmMode ;

macVerifyJob.jobPriority = JobList[jobid].CsmJobPriority;
macVerifyJob.PrimitiveInfo.cryIfKeyId = CsmKey.CsmKeyRef->CryifKeyId; //Getting the cryifKeyid from the CsmKey
//macVerifyJob.cryptokeyid = cryifkey[cryIfKeyId].keyref->id //Cryif -> Cryptokey in CRYIF layer
macVerifyJob.PrimitiveInfo.processingType = JobList[jobid].CsmProcessingMode;
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