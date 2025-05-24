 /******************************************************************************
 *
 * Module: Crypto
 *
 * File Name: Crypto.h
 *
 * Description: Header file for - Crypto Driver
 *
 * Author: Ahmed Gamal
 ******************************************************************************/

 #ifndef CRYPTO_H_
 #define CRYPTO_H_
 #include "Crypto_GeneralTypes.h"
 #include "Crypto_Cfg.h"



#define KEY_STATE_VALID      ((uint8)0)
#define KEY_STATE_INVALID    ((uint8)1)
/*******************************************************************************
 *                              API IDs                              *
 *******************************************************************************/
#define CRYPTO_INIT_API_ID 0
#define CRYPTO_PROCESSJOB_API_ID 1
 /*******************************************************************************
  *                              Module Data Types                              *
  *******************************************************************************/
 typedef struct {
    uint32 DriverObjectId; // Identifier of the Driver Object.
    Crypto_JobStateType status;       // Idle or Active
    uint32 jobId;   // Current job being handled
//    boolean        isProcessing; // Flag: job actively processing
//    const CryptoServiceHandler* handler;    // Active service handler
    CryptoKey Key;
} driveobject_type;


 /* Data Structure required for initializing the Crypto Driver */
typedef struct {
  uint8   NumPrimitives;
  const CryptoPrimitive*       PrimitiveRefs[CRYPTO_MAX_PRIMITIVES];

  uint8   NumDriverObjects;
  const CryptoDriverObject*    DriverObjectRefs[CRYPTO_MAX_DRIVER_OBJECTS];

  uint8   NumKeys;
  const CryptoKey*             KeyRefs[CRYPTO_MAX_KEYS];
} Crypto_ConfigType;

 
 /*******************************************************************************
  *                      DET Error Codes                                        *
  *******************************************************************************/
 
 /* API called before initialization */
 #define CRYPTO_E_UNINIT          0x00
 
 /* Initialization failure */
 #define CRYPTO_E_INIT_FAILED     0x01
 
 /* Invalid null pointer parameter */
 #define CRYPTO_E_PARAM_POINTER   0x02
 
 /* Parameter out of range */
 #define CRYPTO_E_PARAM_HANDLE    0x04
 
 /* Invalid parameter value */
 #define CRYPTO_E_PARAM_VALUE     0x05
 
 /* Buffer too small for operation */
 #define CRYPTO_E_SMALL_BUFFER    0x06
 
 /*******************************************************************************
  *                      Function Prototypes                                    *
  *******************************************************************************/
 
 /* Function for Crypto Initialization API */
 void Crypto_Init (const Crypto_ConfigType* configPtr);
 

 /*******************************************************************************
  *                       External Variables                                    *
  *******************************************************************************/
 // CryptoObject Instantation
extern CryptoPrimitive MacVerify_Primitive ;
extern CryptoPrimitive MacGenerate_Primitive;
extern CryptoPrimitive Encrypt_Primitive ;
extern CryptoPrimitive Decrypt_Primitive ;
extern CryptoDriverObject CryptoObject_MAC ;

extern const Crypto_AlgorithmInfoType aesGCM ;

extern const Crypto_PrimitiveInfoType verifyPrimitive ;
extern const Crypto_PrimitiveInfoType macGeneratePrimitive ;
extern const Crypto_PrimitiveInfoType encryptPrimitive ;
extern const Crypto_PrimitiveInfoType decryptPrimitive ;
extern Crypto_JobPrimitiveInfoType verifyJob ;

extern Crypto_JobPrimitiveInfoType macGenerateJob ;

extern Crypto_JobPrimitiveInfoType encryptJob ;

extern Crypto_JobPrimitiveInfoType decryptJob;


extern const char AES_KEY_DATA[AES_KEY_SIZE] ;

extern CryptoKeyElement GCM_KeyElement ;

extern CryptoKeyType GCM_KeyType ;

extern CryptoKey CryptoKey1;
/* PB structure used with Crypto_Init API */
extern const Crypto_ConfigType Crypto_PBConfig;
 
 #endif /* CRYPTO_H_ */
 
