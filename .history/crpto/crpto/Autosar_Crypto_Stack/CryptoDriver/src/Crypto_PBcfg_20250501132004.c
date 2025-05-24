/*
 * Crypto_PBcfg.c
 *
 *  Created on: Apr 16, 2025
 *      Author: Ahmed Gamal
 
 updated :Ahmed Khalifa
 */
#include "Crypto.h"
#include "../include/Crypto_Cfg.h"
#include <stdbool.h>



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
