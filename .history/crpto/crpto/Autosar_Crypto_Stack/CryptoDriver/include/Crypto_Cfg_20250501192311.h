#ifndef CRYPTO_CFG_H
#define CRYPTO_CFG_H

/*
 *  Crypto_Cfg.h
 *  AUTOSAR Crypto Stack - General Types Header File
 *
 *  This file contains common type definitions for use by all layers of the AUTOSAR Crypto Stack.
 */

#ifdef __cplusplus
extern "C" {
#endif

/* ===================[INCLUDES]============================================= */
#include "Std_Types.h"

/* ===================[VERSION INFORMATION]================================== */
#define CRYPTO_GENERALTYPES_AR_RELEASE_MAJOR_VERSION    (4U)
#define CRYPTO_GENERALTYPES_AR_RELEASE_MINOR_VERSION    (4U)
#define CRYPTO_GENERALTYPES_AR_RELEASE_REVISION_VERSION (0U)


#define CRYPTO_VERSION_INFO_API     STD_ON
#define CRYPTO_NUM_PARTITION_REFS   0
#define CRYPTO_NUM_NV_BLOCK_ARRAY_SIZE       1
#define CRYPTO_NUM_PRIMITIVE_ALGORITHM_FAMILY 1
#define CRYPTO_NUM_PRIMITIVE_ALGORITHM_MODE 1
#define CRYPTO_NUM_PRIMITIVE_ALGORITHM_SECONDARY_FAMILY  1
#define CRYPTO_NUM_PRIMITIVE_ALGORITHM_FAMILY_CUSTOM 1
#define CRYPTO_NUM_PRIMITIVE_ALGORITHM_MODE_CUSTOM 1
#define CRYPTO_NUM_PRIMITIVE_ALGORITHM_SECONDARY_FAMILY_CUSTOM 1
#define CRYPTO_PRIMITIVE_ARRAY_SIZE 1
#define CRYPTO_PRIMITIVE_ALGORITHM_FAMILY_CUSTOM_ARRAY_SIZE 1
#define CRYPTO_PRIMITIVE_ALGORITHM_MODE_CUSTOM_ARRAY_SIZE 1
#define CRYPTO_KEY_TYPE_ARRAY_SIZE 1
#define CRYPTO_KEY_ELEMENT_ARRAY_SIZE 1
#define CRYPTO_KEY_ARRAY_SIZE 1
#define CRYPTO_DRIVER_OBJECTS_ARRAY_SIZE 1
#define CRYPTO_NUM_PRIMITIVE_REFS 2
#define CRYPTO_NV_BLOCK_ARRAY_SIZE 1
#define CRYPTO_PRIMITIVE_ARRAY_SIZE 1
#define CRYPTO_PRIMITIVE_ALGORITHM_FAMILY_CUSTOM_ARRAY_SIZE 1
#define CRYPTO_PRIMITIVE_ALGORITHM_MODE_CUSTOM_ARRAY_SIZE 1



// /* ===================[CHECK VERSION COMPATIBILITY]========================= */
// #if (   (CRYPTO_GENERALTYPES_AR_RELEASE_MAJOR_VERSION != STD_AR_RELEASE_MAJOR_VERSION) \
//      || (CRYPTO_GENERALTYPES_AR_RELEASE_MINOR_VERSION != STD_AR_RELEASE_MINOR_VERSION) )
// #error "AutoSAR version mismatch between Crypto_GeneralTypes.h and Std_Types.h"
// #endif


/*----------------------------------------------------------------------------*/
/*--- PBCFG Sizing Macros – keep these in sync with your instantiation below */
/*----------------------------------------------------------------------------*/
#define CRYPTO_MAX_PRIMITIVES       (2u)
#define CRYPTO_MAX_DRIVER_OBJECTS   (1u)
#define CRYPTO_MAX_KEYS             (1u)


/* ===================[TYPE DEFINITIONS]==================================== */



/* =====================================================================================
 * Enumerations
 * ===================================================================================== */
typedef enum{
    CRYPTO_KE_FORMAT_BIN_IDENT_PRIVATEKEY_PKCS8 = 0x03,
    CRYPTO_KE_FORMAT_BIN_IDENT_PUBLICKEY = 0x04,
    CRYPTO_KE_FORMAT_BIN_OCTET = 0x01,
    CRYPTO_KE_FORMAT_BIN_RSA_PRIVATEKEY = 0x05,
    CRYPTO_KE_FORMAT_BIN_RSA_PUBLICKEY = 0x06,
    CRYPTO_KE_FORMAT_BIN_SHEKEYS = 0x02
}CryptoKeyElementFormatType;

typedef enum {
    CRYPTO_RA_ALLOWED = 0x00,        // Key element can be read as plaintext
    CRYPTO_RA_ENCRYPTED = 0x01,      // Key element can be read encrypted (e.g., SHE Ram-Key export)
    CRYPTO_RA_INTERNAL_COPY = 0x02,  // Key element can be copied to another key element in the same crypto driver
    CRYPTO_RA_DENIED = 0x03          // Key element cannot be read from outside the CryptoDriver
} CryptoKeyElementReadAccessType;

typedef enum {
    CRYPTO_WA_ALLOWED = 0x00,      // Key element can be read as plaintext
    CRYPTO_WA_DENIED = 0x03,       // Key element can be read encrypted (e.g., SHE Ram-Key export)
    CRYPTO_WA_ENCRYPTED = 0x01,    // Key element can be copied to another key element in the same crypto driver
    CRYPTO_WA_INTERNAL_COPY = 0x02 // Key element cannot be read from outside the CryptoDriver
} CryptoKeyElementWriteAccessType;

//typedef enum{
//    CRYPTO_ALGOMODE_12ROUNDS,
//    CRYPTO_ALGOMODE_20ROUNDS,
//    CRYPTO_ALGOMODE_8ROUNDS,
//    CRYPTO_ALGOMODE_AESKEYWRAP,
//    CRYPTO_ALGOMODE_CBC,
//    CRYPTO_ALGOMODE_CFB,
//    CRYPTO_ALGOMODE_CMAC,
//    CRYPTO_ALGOMODE_CTR,
//    CRYPTO_ALGOMODE_CTRDRBG,
//    CRYPTO_ALGOMODE_CUSTOM,
//    CRYPTO_ALGOMODE_ECB,
//    CRYPTO_ALGOMODE_GCM,
//    CRYPTO_ALGOMODE_GMAC,
//    CRYPTO_ALGOMODE_HMAC,
//    CRYPTO_ALGOMODE_NOT_SET,
//    CRYPTO_ALGOMODE_OFB,
//    CRYPTO_ALGOMODE_PXXXR,
//    CRYPTO_ALGOMODE_RSAES_OAEP,
//    CRYPTO_ALGOMODE_RSAES_PKCS1_v1_5,
//    CRYPTO_ALGOMODE_RSASSA_PKCS1_v1_5,
//    CRYPTO_ALGOMODE_RSASSA_PSS,
//    CRYPTO_ALGOMODE_SIPHASH_2_4,
//    CRYPTO_ALGOMODE_SIPHASH_4_8,
//    CRYPTO_ALGOMODE_XTS
//}CryptoPrimitiveAlgorithmModeType;

//typedef enum{
//    CRYPTO_ALGOFAM_3DES,
//    CRYPTO_ALGOFAM_AES,
//    CRYPTO_ALGOFAM_BLAKE_1_256,
//    CRYPTO_ALGOFAM_BLAKE_1_512,
//    CRYPTO_ALGOFAM_BLAKE_2s_256,
//    CRYPTO_ALGOFAM_BLAKE_2s_512,
//    CRYPTO_ALGOFAM_BRAINPOOL,
//    CRYPTO_ALGOFAM_CHACHA,
//    CRYPTO_ALGOFAM_CUSTOM,
//    CRYPTO_ALGOFAM_DH,
//    CRYPTO_ALGOFAM_DRBG,
//    CRYPTO_ALGOFAM_ECCANSI,
//    CRYPTO_ALGOFAM_ECCNIST,
//    CRYPTO_ALGOFAM_ECCSEC,
//    CRYPTO_ALGOFAM_ECDH,
//    CRYPTO_ALGOFAM_ECDSA,
//    CRYPTO_ALGOFAM_ED25519,
//    CRYPTO_ALGOFAM_EEA3,
//    CRYPTO_ALGOFAM_EIA3,
//    CRYPTO_ALGOFAM_FIPS186,
//    CRYPTO_ALGOFAM_HKDF,
//    CRYPTO_ALGOFAM_KDFX963,
//    CRYPTO_ALGOFAM_NOT_SET,
//    CRYPTO_ALGOFAM_PADDING_ONEWITHZEROS,
//    CRYPTO_ALGOFAM_PADDING_PKCS7,
//    CRYPTO_ALGOFAM_PBKDF2,
//    CRYPTO_ALGOFAM_POLY1305,
//    CRYPTO_ALGOFAM_RIPEMD160,
//    CRYPTO_ALGOFAM_RNG,
//    CRYPTO_ALGOFAM_RSA,
//    CRYPTO_ALGOFAM_SHA1,
//    CRYPTO_ALGOFAM_SHA2_224,
//    CRYPTO_ALGOFAM_SHA2_256,
//    CRYPTO_ALGOFAM_SHA2_384,
//    CRYPTO_ALGOFAM_SHA2_512,
//    CRYPTO_ALGOFAM_SHA2_512_224,
//    CRYPTO_ALGOFAM_SHA2_512_256,
//    CRYPTO_ALGOFAM_SHA3_224,
//    CRYPTO_ALGOFAM_SHA3_256,
//    CRYPTO_ALGOFAM_SHA3_384,
//    CRYPTO_ALGOFAM_SHA3_512,
//    CRYPTO_ALGOFAM_SHAKE128,
//    CRYPTO_ALGOFAM_SHAKE256,
//    CRYPTO_ALGOFAM_SIPHASH,
//    CRYPTO_ALGOFAM_SM2,
//    CRYPTO_ALGOFAM_SM3,
//    CRYPTO_ALGOFAM_X25519
//}CryptoPrimitiveAlgorithmFamilyType;


//typedef enum{
//    CRYPTO_HASH = 0x00,
//    CRYPTO_MACGENERATE = 0x01,
//    CRYPTO_MACVERIFY = 0x02,
//    CRYPTO_ENCRYPT = 0x03,
//    CRYPTO_DECRYPT = 0x04,
//    CRYPTO_AEADENCRYPT = 0x05,
//    CRYPTO_AEADDECRYPT = 0x06,
//    CRYPTO_SIGNATUREGENERATE = 0x07,
//    CRYPTO_SIGNATUREVERIFY = 0x08,
//    CRYPTO_RANDOMGENERATE = 0x0B,
//    CRYPTO_RANDOMSEED = 0x0C,
//    CRYPTO_KEYGENERATE = 0x0D,
//    CRYPTO_KEYDERIVE = 0x0E,
//    CRYPTO_KEYEXCHANGECALCPUBVAL = 0x0F,
//    CRYPTO_KEYEXCHANGECALCSECRET = 0x10,
//    CRYPTO_KEYWRAP = 0x11,
//    CRYPTO_KEYUNWRAP = 0x12,
//    CRYPTO_KEYSETVALID = 0x13,
//    CRYPTO_KEYSETINVALID = 0x14,
//    CUSTOM_SERVICE = 0x15
//}CryptoPrimitiveServiceType;

typedef enum{
    CRYPTO_NB_BLOCK_DEFERRED= 0x01,
    CRYPTO_NB_BLOCK_IMMEDIATE= 0x02,
}CryptoNvBlockMode;


typedef struct{
    uint8 CryptoPrimitiveAlgorithmFamilyCustomId; // The custom value of this algorithm family
}CryptoPrimitiveAlgorithmFamilyCustom;

typedef struct{
    uint8 CryptoPrimitiveAlgorithmModeCustomId; // The custom value of this algorithm mode
}CryptoPrimitiveAlgorithmModeCustom;

typedef struct{
    Crypto_AlgorithmFamilyType CryptoPrimitiveAlgorithmFamily[CRYPTO_NUM_PRIMITIVE_ALGORITHM_FAMILY];
    Crypto_AlgorithmModeType CryptoPrimitiveAlgorithmMode[CRYPTO_NUM_PRIMITIVE_ALGORITHM_MODE];
    Crypto_AlgorithmFamilyType CryptoPrimitiveAlgorithmSecondaryFamily[CRYPTO_NUM_PRIMITIVE_ALGORITHM_SECONDARY_FAMILY]; // Determines the algorithm family used for the crypto service
    Crypto_ServiceInfoType CryptoPrimitiveService;
    boolean CryptoPrimitiveSupportContext;
    CryptoPrimitiveAlgorithmFamilyCustom*  CryptoPrimitiveAlgorithmFamilyCustomRef[CRYPTO_NUM_PRIMITIVE_ALGORITHM_FAMILY_CUSTOM];
    CryptoPrimitiveAlgorithmModeCustom* CryptoPrimitiveAlgorithmModeCustomRef[CRYPTO_NUM_PRIMITIVE_ALGORITHM_FAMILY_CUSTOM]; // Determines the algorithm mode used for the crypto service
    CryptoPrimitiveAlgorithmFamilyCustom* CryptoPrimitiveAlgorithmSecondaryFamilyCustomRef[CRYPTO_NUM_PRIMITIVE_ALGORITHM_SECONDARY_FAMILY_CUSTOM];
}CryptoPrimitive;

typedef struct{
    boolean CryptoKeyElementAllowPartialAccess;  //Enable or disable writing and reading the key element with data smaller than the size of the element.
    CryptoKeyElementFormatType CryptoKeyElementFormat; // Enable or disable writing and reading the key element with data smaller than the size of the element.
    uint32 CryptoKeyElementId; // Defines the format for the key element. This is the format used to provide or extract the key data from the driver.
    const char *CryptoKeyElementInitValue; // Value which will be used to fill the key element during startup
    boolean CryptoKeyElementPersist; //
    CryptoKeyElementReadAccessType CryptoKeyElementReadAccess; //
    uint32 CryptoKeyElementSize; // Maximum Size size of a CRYPTO key element in bytes
    CryptoKeyElementWriteAccessType CryptoKeyElementWriteAccess; //
}CryptoKeyElement;

typedef struct{
    CryptoKeyElement* CryptoKeyElementRef;
}CryptoKeyType;

/*Container to configure key storage in NVM*/
typedef struct{
    uint16 CryptoNvBlockFailedRetries; //Number of retries to request an NVM service operation.
    CryptoNvBlockMode CryptoNvBlockProcessing;
    //NvMBlockDescriptor* CryptoNvBlockDescriptorRef; //Reference to an NvM block descriptor
}CryptoNvBlock;


typedef struct{
    uint32 CryptoKeyId; // Identifier of the CRYPTO Key
    const CryptoNvBlock* CryptoKeyNvBlockRef; // Reference to the NV block where the persistent key elements of this key shall be stored to.
    const CryptoKeyType* CryptoKeyTypeRef; // Refers to a pointer in the CRYPTO to a CryptoKeyType. The CryptoKeyType provides the information on which key elements are contained in a CryptoKey.
}CryptoKey;


typedef struct{
    uint32 CryptoDriverObjectId; // Identifier of the Crypto Driver Object. The Crypto Driver Object offers different crypto primitives.
    uint32 CryptoQueueSize; // Size of the queue in the CryptoDriver. Defines the maximum number of jobs in the CryptoDriverObject queue. If it is set to 0, queueing is disabled in the CryptoDriverObject.
    CryptoKey* CryptoDefaultRandomKeyRef; //This is a reference to the CryptoKey that is used by the CryptoDefaultRandomPrimitiveRef. The key contains key elements that are necessary to seed the random number generator. 
    CryptoPrimitive* CryptoDefaultRandomPrimitiveRef;// This is a reference to a primitive that configures a default random number generator. If a CryptoDriver object needs to perform a crypto primitive that requires a random number generator, but the configuration of this primitive does not provide a parameter for a random number generator, then this default random number generator shall be used.
    //EcucPartition* CryptoDriverObjectEcucPartitionRef;
    CryptoPrimitive* CryptoPrimitiveRef[CRYPTO_NUM_PRIMITIVE_REFS];

}CryptoDriverObject;

typedef struct{
    CryptoDriverObject* CryptoDriverObjectArray[CRYPTO_DRIVER_OBJECTS_ARRAY_SIZE];
}CryptoDriverObjects;

typedef struct{
    boolean CryptoDevErrorDetect; // Switches the development error detection and notification on or off.
    uint8 CryptoInstanceId; // This ID is used to distinguish between multiple CryptoDriver instances in case more than one driver is used in the same ECU
    const uint32* CryptoMainFunctionPeriod; // Specifies the period of main function Crypto_MainFunction in seconds.
    boolean CryptoVersionInfoApi;// Pre-processor switch to enable and disable availability of the API Crypto_GetVersionInfo().
    //const EcucPartitionRef* CryptoEcucPartitionRef[CRYPTO_NUM_PARTITION_REFS]; // Maps the Crypto driver to zero or multiple ECUC partitions to make the modules API available in this partition.
}CryptoGeneral;




typedef struct{
CryptoKeyElement* CryptoKeyElementArray[CRYPTO_KEY_ELEMENT_ARRAY_SIZE];
}CryptoKeyElements;


typedef struct{
    CryptoKeyType* CryptokeyTypeArray[CRYPTO_KEY_TYPE_ARRAY_SIZE];
}CryptoKeyTypes;




typedef struct{
    CryptoKey* CryptoKeyArray[CRYPTO_KEY_ARRAY_SIZE];
}CryptoKeys;

typedef struct{
    CryptoNvBlock* CryptoNvBlockArray[CRYPTO_NV_BLOCK_ARRAY_SIZE];
}CryptoNvStorage;



typedef struct{
    CryptoNvBlock* CryptoNvBlockArray[CRYPTO_NUM_NV_BLOCK_ARRAY_SIZE]; // The custom value of this algorithm mode
}CryptNvStorage;



typedef struct{
    CryptoPrimitive* CryptoPrimitiveArray[CRYPTO_PRIMITIVE_ARRAY_SIZE];
    CryptoPrimitiveAlgorithmFamilyCustom* CryptoPrimitiveAlgorithmFamilyCustomArray[CRYPTO_PRIMITIVE_ALGORITHM_FAMILY_CUSTOM_ARRAY_SIZE];
    CryptoPrimitiveAlgorithmModeCustom* CryptoPrimitiveAlgorithmModeCustomArray[CRYPTO_PRIMITIVE_ALGORITHM_MODE_CUSTOM_ARRAY_SIZE] ;
}CryptoPrimitives;





/* ===================[EXTERN DECLARATIONS]================================= */

extern const CryptoDriverObject CryptoObject_MAC;

/* ===================[END OF FILE]========================================= */

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_GENERALTYPES_H */

