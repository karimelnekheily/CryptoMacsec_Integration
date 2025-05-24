/*
 * CryIf.c
 *
 *  Created on: Apr 8, 2025
 *      Author: Ahmed Gamal
 */

 #include "Crypto.h"
 #include "Crypto_Cfg.h"
 #include "Crypto_GeneralTypes.h"
 #include "Std_Types.h"
 #include "stdbool.h"
 #include "stdio.h"
 #include "mbedtls/gcm.h"


void CryIf_Init(void)
{
    CryIf_Initialized = TRUE;

    for (uint8 i = 0; i < CRYIF_NUM_CHANNELS; i++)
    {
        CryIf_JobQueues[i].head = 0;
        CryIf_JobQueues[i].tail = 0;
        CryIf_JobQueues[i].count = 0;
    }
}

Std_ReturnType CryIf_ProcessJob(uint32 channelId, Crypto_JobType* job)
{

    if (!CryIf_Initialized)
        return E_NOT_OK;

    if (job == NULL)
        return E_NOT_OK;

    if(job->jobPrimitiveInfo->primitiveInfo->service == CRYPTO_KEYSETVALID ||
        job->jobPrimitiveInfo->primitiveInfo->service == CRYPTO_KEYSETINVALID ||
        job->jobPrimitiveInfo->primitiveInfo->service ==  CRYPTO_RANDOMSEED ||
        job->jobPrimitiveInfo->primitiveInfo->service == CRYPTO_KEYGENERATE ||
        job->jobPrimitiveInfo->primitiveInfo->service == CRYPTO_KEYDERIVE ||
        job->jobPrimitiveInfo->primitiveInfo->service == CRYPTO_KEYEXCHANGE_CALCPUBVAL ||
        job->jobPrimitiveInfo->primitiveInfo->service == CRYPTO_KEYEXCHANGECALCSECRET ){

          if(job->jobPrimitiveInputOutput.cryIfKeyId  <= 10) {

          }
          else return CRYIF_E_PARAM_HANDLE;
          if(job->jobPrimitiveInputOutput.targetCryIfKeyId  <= 10 ){
    
          }
          else return CRYIF_E_PARAM_HANDLE
        }

    // Find channel config
    const CryIf_ChannelConfigType* config = NULL;
    for (uint8 i = 0; i < CRYIF_NUM_CHANNELS; i++)
    {
        if (CryIf_ChannelConfig[i].channelId == channelId)
        {
            config = &CryIf_ChannelConfig[i];
            break;
        }
    }

    if (config == NULL)
        return E_NOT_OK;  // Invalid channel

    if (config->isAsync)
    {
        // Queue the job
        CryIf_JobQueueType* queue = &CryIf_JobQueues[channelId];
        if (queue->count >= CRYIF_MAX_JOB_QUEUE_LENGTH)
            return CRYPTO_E_BUSY;

        queue->jobQueue[queue->tail] = job;
        queue->tail = (queue->tail + 1) % CRYIF_MAX_JOB_QUEUE_LENGTH;
        queue->count++;

        return E_OK;  // Job queued
    }
    else
    {
        // Route directly to backend
        if (config->backendId == CRYIF_BACKEND_CSM)
        {
            return Csm_ProcessJob(channelId, job);
        }
        else if (config->backendId == CRYIF_BACKEND_DRIVER)
        {
            return Driver_ProcessJob(channelId, job);  // You must implement this
        }
    }

    return E_NOT_OK;
}


Std_ReturnType CryIf_CancelJob(uint32 channelId, Crypto_JobType* job)
{
    if(job == NULL_PTR  ){
        return CRYIF_E_PARAM_HANDLE;
    }
    Std_ReturnType retval = Crypto_CancelJob(1, job);
    return retval;
}



//should be handeled in csm
void CryIf_MainFunction(void)
{
    for (uint8 ch = 0; ch < CRYIF_NUM_CHANNELS; ch++)
    {
        const CryIf_ChannelConfigType* config = &CryIf_ChannelConfig[ch];
        if (!config->isAsync)
            continue;

        CryIf_JobQueueType* queue = &CryIf_JobQueues[ch];

        if (queue->count > 0)
        {
            Crypto_JobType* job = queue->jobQueue[queue->head];
            Std_ReturnType result;

            if (config->backendId == CRYIF_BACKEND_CSM)
                result =+ Csm_ProcessJob(config->channelId, job);
            else
                result = Driver_ProcessJob(config->channelId, job); // implement this

            if (result == E_OK)
            {
                // Remove job from queue
                queue->head = (queue->head + 1) % CRYIF_MAX_JOB_QUEUE_LENGTH;
                queue->count--;
            }
            // else keep job in queue and try later
        }
    }
}

