/*
 * Crypto_PBcfg.c
 *
 *  Created on: Apr 16, 2025
 *      Author: Ahmed Gamal
 
 updated :Ahmed Khalifa
 */
// #include "Crypto.h"
#include "../include/Crypto_GeneralTypes.h"
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

CryptoPrimitive Encrypt_Primitive = {
  .CryptoPrimitiveAlgorithmFamily = {CRYPTO_ALGOFAM_AES},  
  .CryptoPrimitiveAlgorithmMode = {CRYPTO_ALGOMODE_GCM},    
  .CryptoPrimitiveAlgorithmSecondaryFamily = {CRYPTO_ALGOFAM_AES},
  .CryptoPrimitiveService = CRYPTO_ENCRYPT,
  .CryptoPrimitiveSupportContext = false,
  .CryptoPrimitiveAlgorithmFamilyCustomRef= {NULL_PTR},
  .CryptoPrimitiveAlgorithmModeCustomRef = {NULL_PTR},               
  .CryptoPrimitiveAlgorithmSecondaryFamilyCustomRef = {NULL_PTR}     
};

CryptoPrimitive Decrypt_Primitive = {
  .CryptoPrimitiveAlgorithmFamily = {CRYPTO_ALGOFAM_AES},  
  .CryptoPrimitiveAlgorithmMode = {CRYPTO_ALGOMODE_GCM},    
  .CryptoPrimitiveAlgorithmSecondaryFamily = {CRYPTO_ALGOFAM_AES},
  .CryptoPrimitiveService = CRYPTO_DECRYPT,
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
      &MacVerify_Primitive,
      &Encrypt_Primitive,
      &Decrypt_Primitive
  }
};



//Crpto_job
const Crypto_AlgorithmInfoType aesGCM = {
  .family = CRYPTO_ALGOFAM_AES,
  .secondaryFamily = CRYPTO_ALGOFAM_AES,  // e.g., if hashing is involved with encryption
  .keyLength = 128,                        // AES-128
  .mode = CRYPTO_ALGOMODE_GCM
};
// Primitive info definitions
const Crypto_PrimitiveInfoType verifyPrimitive = {
  .service = CRYPTO_MACVERIFY,
  .algorithm = aesGCM
};

const Crypto_PrimitiveInfoType macGeneratePrimitive = {
  .service = CRYPTO_MACGENERATE,
  .algorithm = aesGCM
};

const Crypto_PrimitiveInfoType encryptPrimitive = {
  .service = CRYPTO_ENCRYPT,
  .algorithm = aesGCM
};

const Crypto_PrimitiveInfoType decryptPrimitive = {
  .service = CRYPTO_DECRYPT,
  .algorithm = aesGCM
};

// Job definitions
Crypto_JobPrimitiveInfoType verifyJob = {
  .callbackId = 1,                              // Assume 1 maps to MAC verify callback
  .primitiveInfo = &verifyPrimitive,
  .crylfKeyId = 10,                             // Example key ID
  .processingType = CRYPTO_PROCESSING_SYNC
};

Crypto_JobPrimitiveInfoType macGenerateJob = {
  .callbackId = 2,                              // Assume 2 maps to MAC generate callback
  .primitiveInfo = &macGeneratePrimitive,
  .crylfKeyId = 11,
  .processingType = CRYPTO_PROCESSING_SYNC
};

Crypto_JobPrimitiveInfoType encryptJob = {
  .callbackId = 3,                              // Assume 3 maps to encryption callback
  .primitiveInfo = &encryptPrimitive,
  .crylfKeyId = 12,
  .processingType = CRYPTO_PROCESSING_SYNC
};

Crypto_JobPrimitiveInfoType decryptJob = {
  .callbackId = 4,                              // Assume 4 maps to decryption callback
  .primitiveInfo = &decryptPrimitive,
  .crylfKeyId = 13,
  .processingType = CRYPTO_PROCESSING_SYNC
};


const char AES_KEY_DATA[AES_KEY_SIZE] = {
  0x00, 0x11, 0x22, 0x33,
  0x44, 0x55, 0x66, 0x77,
  0x88, 0x99, 0xaa, 0xbb,
  0xcc, 0xdd, 0xee, 0xff
};

CryptoKeyElement GCM_KeyElement = {
  .CryptoKeyElementId=0,
  .CryptoKeyElementAllowPartialAccess = false,
  .CryptoKeyElementFormat = CRYPTO_KE_FORMAT_BIN_OCTET,
  .CryptoKeyElementInitValue = AES_KEY_DATA,
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
  &MacVerify_Primitive,
  &Encrypt_Primitive,
  &Decrypt_Primitive
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