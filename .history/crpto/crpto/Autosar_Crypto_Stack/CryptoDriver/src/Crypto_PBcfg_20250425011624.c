/*
 * Crypto_PBcfg.c
 *
 *  Created on: Apr 16, 2025
 *      Author: Ahmed Gamal
 */
#include "Crypto.h"
#include "../include/Crypto_Cfg.h"
#include <stdbool.h>
/* PB structure used with Crypto_Init API */
const Crypto_ConfigType Crypto_Configuration = {
//                                             DioConf_LED1_PORT_NUM,DioConf_LED1_CHANNEL_NUM,
//                                             DioConf_SW1_PORT_NUM,DioConf_SW1_CHANNEL_NUM
                                         };

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


extern CryptoDriverObject CryptoObject_MAC = {
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
    .CryptoKeyElementAllowPartialAccess = false,
    .CryptoKeyElementFormat = CRYPTO_KE_FORMAT_BIN_OCTET,
    .CryptoKeyElementInitValue = "AA",
    .CryptoKeyElementPersist = false,
    .CryptoKeyElementReadAccess = CRYPTO_RA_DENIED,
    .CryptoKeyElementSize = 16,
    .CryptoKeyElementWriteAccess =  CRYPTO_WA_DENIED  
};

CryptoKeyType GCM_KeyType = {
    .CryptoKeyElementArray = { &GCM_KeyElement }
};

CryptoKey CryptoKey1 = {
    .CryptoKeyId = 0,
    .CryptoKeyNvBlockRef={NULL_PTR},
    .CryptoKeyTypeRef = {&GCM_KeyElement}
};