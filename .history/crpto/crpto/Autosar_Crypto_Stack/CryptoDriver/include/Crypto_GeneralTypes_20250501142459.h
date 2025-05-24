#ifndef CRYPTO_GENERALTYPES_H
#define CRYPTO_GENERALTYPES_H

/*
 *  Crypto_GeneralTypes.h
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

#define CRYPTO_GENERALTYPES_SW_MAJOR_VERSION            (1U)
#define CRYPTO_GENERALTYPES_SW_MINOR_VERSION            (0U)
#define CRYPTO_GENERALTYPES_SW_PATCH_VERSION            (0U)

// /* ===================[CHECK VERSION COMPATIBILITY]========================= */
// #if (   (CRYPTO_GENERALTYPES_AR_RELEASE_MAJOR_VERSION != STD_AR_RELEASE_MAJOR_VERSION) \
//      || (CRYPTO_GENERALTYPES_AR_RELEASE_MINOR_VERSION != STD_AR_RELEASE_MINOR_VERSION) )
// #error "AutoSAR version mismatch between Crypto_GeneralTypes.h and Std_Types.h"
// #endif

/* ===================[TYPE DEFINITIONS]==================================== */

/* =====================================================================================
 * Std_ReturnType extensions for Crypto Service Manager (SWS_Csm_91043)
 * ===================================================================================== */
#define CRYPTO_E_BUSY               ((Std_ReturnType)0x02u)
#define CRYPTO_E_ENTROPY_EXHAUSTED ((Std_ReturnType)0x04u)
#define CRYPTO_E_KEY_READ_FAIL     ((Std_ReturnType)0x06u)
#define CRYPTO_E_KEY_WRITE_FAIL    ((Std_ReturnType)0x07u)
#define CRYPTO_E_KEY_NOT_AVAILABLE ((Std_ReturnType)0x08u)
#define CRYPTO_E_KEY_NOT_VALID     ((Std_ReturnType)0x09u)
#define CRYPTO_E_KEY_SIZE_MISMATCH ((Std_ReturnType)0x0Au)
#define CRYPTO_E_JOB_CANCELED      ((Std_ReturnType)0x0Cu)
#define CRYPTO_E_KEY_EMPTY         ((Std_ReturnType)0x0Du)
#define CRYPTO_E_CUSTOM_ERROR      ((Std_ReturnType)0x0Eu)

/* =====================================================================================
 * Enumerations
 * ===================================================================================== */


/* [SWS_Csm_01047] Definition of datatype Crypto_AlgorithmFamilyType */
typedef enum {
    CRYPTO_ALGOFAM_NOT_SET       = 0x00,
    CRYPTO_ALGOFAM_SHA1          = 0x01,
    CRYPTO_ALGOFAM_SHA2_224      = 0x02,
    CRYPTO_ALGOFAM_SHA2_256      = 0x03,
    CRYPTO_ALGOFAM_SHA2_384      = 0x04,
    CRYPTO_ALGOFAM_SHA2_512      = 0x05,
    CRYPTO_ALGOFAM_SHA2_512_224  = 0x06,
    CRYPTO_ALGOFAM_SHA2_512_256  = 0x07,
    CRYPTO_ALGOFAM_SHA3_224      = 0x08,
    CRYPTO_ALGOFAM_SHA3_256      = 0x09,
    CRYPTO_ALGOFAM_SHA3_384      = 0x0a,
    CRYPTO_ALGOFAM_SHA3_512      = 0x0b,
    CRYPTO_ALGOFAM_SHAKE128      = 0x0c,
    CRYPTO_ALGOFAM_SHAKE256      = 0x0d,
    CRYPTO_ALGOFAM_RIPEMD160     = 0x0e,
    CRYPTO_ALGOFAM_BLAKE_1_256   = 0x0f,
    CRYPTO_ALGOFAM_BLAKE_1_512   = 0x10,
    CRYPTO_ALGOFAM_BLAKE_2S_256  = 0x11,
    CRYPTO_ALGOFAM_BLAKE_2S_512  = 0x12,
    CRYPTO_ALGOFAM_3DES          = 0x13,
    CRYPTO_ALGOFAM_AES           = 0x14,
    CRYPTO_ALGOFAM_CHACHA        = 0x15,
    CRYPTO_ALGOFAM_RSA           = 0x16,
    CRYPTO_ALGOFAM_ED25519       = 0x17,
    CRYPTO_ALGOFAM_BRAINPOOL     = 0x18,
    CRYPTO_ALGOFAM_ECCNIST       = 0x19,
    CRYPTO_ALGOFAM_RNG           = 0x1b,
    CRYPTO_ALGOFAM_SIPHASH       = 0x1c,
    CRYPTO_ALGOFAM_ECCANSI       = 0x1e,
    CRYPTO_ALGOFAM_ECCSEC        = 0x1f,
    CRYPTO_ALGOFAM_DRBG          = 0x20,
    CRYPTO_ALGOFAM_FIPS186       = 0x21,
    CRYPTO_ALGOFAM_PADDING_PKCS7 = 0x22,
    CRYPTO_ALGOFAM_PADDING_ONEWITHZEROS = 0x23,
    CRYPTO_ALGOFAM_PBKDF2        = 0x24,
    CRYPTO_ALGOFAM_KDFX963       = 0x25,
    CRYPTO_ALGOFAM_DH            = 0x26,
    CRYPTO_ALGOFAM_SM2           = 0x27,
    CRYPTO_ALGOFAM_EEA3          = 0x28,
    CRYPTO_ALGOFAM_SM3           = 0x29,
    CRYPTO_ALGOFAM_EIA3          = 0x2A,
    CRYPTO_ALGOFAM_HKDF          = 0x2B,
    CRYPTO_ALGOFAM_ECDSA         = 0x2C,
    CRYPTO_ALGOFAM_POLY1305      = 0x2D,
    CRYPTO_ALGOFAM_X25519        = 0x2E,
    CRYPTO_ALGOFAM_ECDH          = 0x2F,
    CRYPTO_ALGOFAM_CUSTOM        = 0xFF
} Crypto_AlgorithmFamilyType;


/* [SWS_Csm_01048] Definition of datatype Crypto_AlgorithmModeType */
typedef enum {
    CRYPTO_ALGOMODE_NOT_SET         = 0x00,
    CRYPTO_ALGOMODE_ECB             = 0x01,
    CRYPTO_ALGOMODE_CBC             = 0x02,
    CRYPTO_ALGOMODE_CFB             = 0x03,
    CRYPTO_ALGOMODE_OFB             = 0x04,
    CRYPTO_ALGOMODE_CTR             = 0x05,
    CRYPTO_ALGOMODE_GCM             = 0x06,
    CRYPTO_ALGOMODE_XTS             = 0x07,
    CRYPTO_ALGOMODE_RSAES_OAEP      = 0x08,
    CRYPTO_ALGOMODE_RSAES_PKCS1_v1_5 = 0x09,
    CRYPTO_ALGOMODE_RSASSA_PSS      = 0x0a,
    CRYPTO_ALGOMODE_RSASSA_PKCS1_v1_5 = 0x0b,
    CRYPTO_ALGOMODE_8ROUNDS         = 0x0c,
    CRYPTO_ALGOMODE_12ROUNDS        = 0x0d,
    CRYPTO_ALGOMODE_20ROUNDS        = 0x0e,
    CRYPTO_ALGOMODE_HMAC            = 0x0f,
    CRYPTO_ALGOMODE_CMAC            = 0x10,
    CRYPTO_ALGOMODE_GMAC            = 0x11,
    CRYPTO_ALGOMODE_CTRDRBG         = 0x12,
    CRYPTO_ALGOMODE_SIPHASH_2_4     = 0x13,
    CRYPTO_ALGOMODE_SIPHASH_4_8     = 0x14,
    CRYPTO_ALGOMODE_PXXKDF1         = 0x15,
    CRYPTO_ALGOMODE_AESKEYWRAP      = 0x16,
    CRYPTO_ALGOMODE_CUSTOM          = 0xFF
} Crypto_AlgorithmModeType;


/* [SWS_Csm_91024] Definition of datatype Crypto_InputOutputRedirectionConfig
 Type */
typedef enum {
    CRYPTO_REDIRECT_CONFIG_PRIMARY_INPUT   = 0x01,
    CRYPTO_REDIRECT_CONFIG_SECONDARY_INPUT = 0x02,
    CRYPTO_REDIRECT_CONFIG_TERTIARY_INPUT  = 0x04,
    CRYPTO_REDIRECT_CONFIG_PRIMARY_OUTPUT  = 0x10,
    CRYPTO_REDIRECT_CONFIG_SECONDARY_OUTPUT= 0x20
} Crypto_InputOutputRedirectionConfigType;


/* [SWS_Csm_01028] Definition of datatype Crypto_JobStateType ⌈ */
typedef enum {
    CRYPTO_JOBSTATE_IDLE   = 0x00,  // Job is in the state "idle". This state is reached after Csm_Init() or when the "Finish" state is finished.
    CRYPTO_JOBSTATE_ACTIVE = 0x01   // Job is in the state "active". There was already some input or there are intermediate results.
                                    // This state is reached when the "update" or "start" operation finishes.
} Crypto_JobStateType;


/* [SWS_Csm_01031] Definition of datatype Crypto_ServiceInfoType ⌈*/
typedef enum {
    CRYPTO_HASH                     = 0x00,  /* Hash Service */
    CRYPTO_MACGENERATE              = 0x01,  /* MacGenerate Service */
    CRYPTO_MACVERIFY                = 0x02,  /* MacVerify Service */
    CRYPTO_ENCRYPT                  = 0x03,  /* Encrypt Service */
    CRYPTO_DECRYPT                  = 0x04,  /* Decrypt Service */
    CRYPTO_AEADENCRYPT              = 0x05,  /* AEADEncrypt Service */
    CRYPTO_AEADDECRYPT              = 0x06,  /* AEADDecrypt Service */
    CRYPTO_SIGNATUREGENERATE        = 0x07,  /* SignatureGenerate Service */
    CRYPTO_SIGNATUREVERIFY          = 0x08,  /* SignatureVerify Service */
    CRYPTO_RANDOMGENERATE           = 0x09,  /* RandomGenerate Service */
    CRYPTO_RANDOMSEED               = 0x10,  /* RandomSeed Service */
    CRYPTO_KEYGENERATE              = 0x10,  /* KeyGenerate Service */
    CRYPTO_KEYDERIVE                = 0x10,  /* KeyDerive Service */
    CRYPTO_KEYEXCHANGE_CALCPUBVAL   = 0x10,  /* KeyExchangeCalcPubVal Service */
    CRYPTO_KEYEXCHANGE_CALCSECRET   = 0x10,  /* KeyExchangeCalcSecret Service */
    CRYPTO_KEYSETVALID              = 0x13,  /* KeySetValid Service */
    CRYPTO_KEYSETINVALID            = 0x14,  /* KeySetInvalid Service */
    CRYPTO_CUSTOM_SERVICE           = 0x15,  /* Custom service job */
    CRYPTO_KEYWRAP                  = 0x16,  /* KeyWrap Service */
    CRYPTO_KEYUNWRAP                = 0x17   /* KeyUnwrap Service */
} Crypto_ServiceInfoType;


/*
 * Definition of ImplementationDataType Crypto_OperationModeType
 * [SWS_Csm_01029]
 */
typedef enum {
    CRYPTO_OPERATIONMODE_START = 0x01,           /**< Start: Reset job state. */
    CRYPTO_OPERATIONMODE_UPDATE = 0x02,          /**< Update: Calculate intermediate results. */
    CRYPTO_OPERATIONMODE_STREAMSTART = 0x03,     /**< Stream Start: Mix of Start and Update. */
    CRYPTO_OPERATIONMODE_FINISH = 0x04,          /**< Finish: Finalize calculations. */
    CRYPTO_OPERATIONMODE_SINGLECALL = 0x07,      /**< Single Call: Start, Update, and Finish combined. */
    CRYPTO_OPERATIONMODE_SAVE_CONTEXT = 0x08,    /**< Save operation context. */
    CRYPTO_OPERATIONMODE_RESTORE_CONTEXT = 0x10  /**< Restore previously saved context. */
} Crypto_OperationModeType;


/*
 * Definition of ImplementationDataType Crypto_VerifyResultType
 * [SWS_Csm_01024]
 */
typedef enum {
    CRYPTO_E_VER_OK = 0x00,         /**< Verification successful (true). */
    CRYPTO_E_VER_NOT_OK = 0x01      /**< Verification failed (false). */
} Crypto_VerifyResultType;


/* [SWS_Csm_91026] Definition of datatype Crypto_JobRedirectionInfoType  */
typedef struct {
    uint8 redirectionConfig;  /* Bit structure indicating buffers to redirect (Crypto_inputOutputRedirectionConfigType values combined with OR) */
    uint32 inputKeyId;        /* Identifier of the key used as input */
    uint32 inputKeyElementId; /* Identifier of the key element used as input */
    uint32 secondaryinputKeyId;       /* Identifier of the key used as secondary input */
    uint32 secondaryinputKeyElementId; /* Identifier of the key element used as secondary input */
    uint32 tertiaryinputKeyId;        /* Identifier of the key used as tertiary input */
    uint32 tertiaryinputKeyElementId; /* Identifier of the key element used as tertiary input */
    uint32 outputKeyId;       /* Identifier of the key used as output */
    uint32 outputKeyElementId; /* Identifier of the key element used as output */
    uint32 secondaryOutputKeyId;      /* Identifier of the key used as secondary output */
    uint32 secondaryOutputKeyElementId; /* Identifier of the key element used as secondary output */
} Crypto_JobRedirectionInfoType;


/* Algorithm configuration structure. Available via Crypto_GeneralTypes.h */
typedef struct {
    Crypto_AlgorithmFamilyType family;          /* The family of the algorithm */
    Crypto_AlgorithmFamilyType secondaryFamily; /* The secondary family of the algorithm (if applicable) */
    uint32 keyLength;                           /* Key length in bits for the algorithm */
    Crypto_AlgorithmModeType mode;              /* Operation mode of the algorithm */
} Crypto_AlgorithmInfoType;


/* Processing type enumeration. Available via Crypto_GeneralTypes.h */
typedef enum {
    CRYPTO_PROCESSING_ASYNC = 0x00,  /* Asynchronous job processing */
    CRYPTO_PROCESSING_SYNC  = 0x01   /* Synchronous job processing */
} Crypto_ProcessingType;


/* Primitive information structure. Available via Crypto_GeneralTypes.h */
typedef struct {
    const Crypto_ServiceInfoType service;   /* Service type (e.g., Encrypt/Decrypt) */
    const Crypto_AlgorithmInfoType algorithm; /* Algorithm configuration */
} Crypto_PrimitiveInfoType;




/* [SWS_Csm_01009] Definition of datatype Crypto_JobPrimitiveInputOutputType */

typedef struct {
    const uint8* inputPtr;                     // Pointer to the input data
    uint32 inputLength;                        // Contains the input length in bytes

    const uint8* secondaryInputPtr;            // Pointer to the secondary input data (for MacVerify, SignatureVerify)
    uint32 secondaryInputLength;               // Contains the secondary input length in bits or bytes

    const uint8* tertiaryInputPtr;             // Pointer to the tertiary input data (for MacVerify, SignatureVerify)
    uint32 tertiaryInputLength;                // Contains the tertiary input length in bytes

    uint8* outputPtr;                          // Pointer to the output data
    uint32* outputLengthPtr;                   // Pointer to memory location containing output length in bytes

    uint8* secondaryOutputPtr;                 // Pointer to the secondary output data
    uint32* secondaryOutputLengthPtr;          // Pointer to memory location containing secondary output length in bytes

    Crypto_VerifyResultType* verifyPtr;        // Output pointer to memory location holding a verify result

    Crypto_OperationModeType mode;             // Indicator of the mode(s)/operation(s) to be performed

    uint32 cryIfKeyId;                         // Key ID to be used in the Crypto Interface
    
    uint32 targetCryIfKeyId;                   // Holds the target CryIf key id for key operation services.

} Crypto_JobPrimitiveInputOutputType;




/* Structure containing job-specific primitive information. Available via Crypto_GeneralTypes.h */
typedef struct {
    uint32 callbackId;        /* Internal callback function identifier (called when service completes) */
    const Crypto_PrimitiveInfoType* primitiveInfo; /* Pointer to crypto primitive configuration */
    uint32 crylfKeyId;        /* Identifier of the Crylf key used for the operation */
    Crypto_ProcessingType processingType; /* Synchronous/Asynchronous behavior selector (CRYPTO_PROCESSING_SYNC/ASYNC) */
} Crypto_JobPrimitiveInfoType;


/* [SWS_Csm_01013] Definition of datatype Crypto_JobType ⌈ */
typedef struct {
    uint32 jobId;  // Identifier for the job structure

    Crypto_JobStateType jobState;  // Determines the current job state

    Crypto_JobPrimitiveInputOutputType jobPrimitiveInputOutput;  // Structure containing input and output info depending on the job and primitive

    const Crypto_JobPrimitiveInfoType* jobPrimitiveInfo;  // Pointer to structure with additional info for the job and primitive

    Crypto_JobRedirectionInfoType* jobRedirectionInfoRef;  // Pointer to structure on key usage in jobs

    uint32 cryptoKeyId;  // Crypto Driver key ID (written by Crypto Interface)

    uint32 targetCryptoKeyId;  // Target Crypto Driver key ID (written by Crypto Interface)

    const uint32 jobPriority;  // Importance of the job
} Crypto_JobType;




/* ===================[EXTERN DECLARATIONS]================================= */
/* None in this file */

/* ===================[END OF FILE]========================================= */

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_GENERALTYPES_H */
