#ifndef MKA_CFG_H_
#define MKA_CFG_H_

#define MKA_MAX_PAE_INSTANCES 1

/* MkaPaeConfiguration */
typedef struct{
    boolean MkaAutoStart;
    void* MkaGetMacSecStatisticsCallbackNotification;  //EcucFunctionNameDef
    uint8 MkaPaeConfigurationIdx;
    float32 MkaRetryBaseDelay;
    float32 MkaRetryCyclicDelay;
    float32 MkaSakRekeyTimeSpan;
} MkaPaeConfiguration;





/* MkaGeneral */
typedef struct {
    boolean MkaDevErrorDetect;
    boolean MkaEnableSecurityEventReporting;
    float32 MkaHelloTime;
    float32 MkaLifeTime;
    float32 MkaMainFunctionPeriod;
    float32 MkaSakRetireTime;
    boolean MkaVersionInfoApi;
} MkaGeneral;



/* MkaCipherSuites */
typedef enum {
    GCM_AES_128,
    GCM_AES_256,
    GCM_AES_XPN_128,
    GCM_AES_XPN_256
} MkaMacSecCipherSuite;

typedef struct {
    MkaMacSecCipherSuite MkaMacSecCipherSuite;
    int MkaMacSecCipherSuitePrio;
} MkaCipherSuites;

/* MkaCryptoAlgoConfig */
typedef enum {
    INTEGRITY_WITHOUT_CONFIDENTIALITY,INTEGRITY_AND_CONFIDENTIALITY
} MkaMacSecCapability;

typedef enum {
    OFFSET_0,OFFSET_30,OFFSET_50
} MkaMacSecConfidentialityOffset;

typedef struct {
    uint8 MkaCryptoAlgoConfigIdx;
    MkaMacSecCapability MkaMacSecCapability;
    MkaMacSecConfidentialityOffset MkaMacSecConfidentialityOffset;
    boolean MkaMacSecReplayProtection;
    uint64 MkaMacSecReplayProtectionWindow;
    MkaCipherSuites CipherSuite;
} MkaCryptoAlgoConfig;




/* MkaKayParticipant */
typedef struct {
    boolean MkaParticipantActivate;
    MkaCryptoAlgoConfig* MkaCryptoAlgoRef; // reference
    void* MkaCryptoCknCakKeyRef; //Symbolic name reference to CsmKey
    void* MkaCryptoHashKey128DerivationJobRef; //Symbolic name reference to CsmJob
    void* MkaCryptoHashKey256DerivationJobRef; //Symbolic name reference to CsmJob
    void* MkaCryptoIckDeriveJobRef; //Symbolic name reference to CsmJob
    void* MkaCryptoIcvGenerateJobRef; //Symbolic name reference to CsmJob
    void* MkaCryptoIcvVerifyJobRef; //Symbolic name reference to CsmJob
    void* MkaCryptoKekDeriveJobRef; //Symbolic name reference to CsmJob
    void* MkaCryptoKeyUnwrapJobRef; //Symbolic name reference to CsmJob
    void* MkaCryptoKeyWrapJobRef; //Symbolic name reference to CsmJob
    void* MkaCryptoRandomJobRef; //Symbolic name reference to CsmJob
    void* MkaCryptoSakKeyRef; //Symbolic name reference to CsmKey
} MkaKayParticipant;

/* MkaKay */
typedef enum {
    MKA_KEY_SERVER,MKA_PEER
} MkaRole;

/* MkaPaeTxPdu */
typedef struct {
    uint16 MkaTxPduId;
    void* MkaPaeTxPduRef; //Reference to Pdu
} MkaPaeTxPdu;

/* MkaPaeRxPdu */
typedef struct {
    uint16 MkaRxPduId;
    void* MkaPaeRxPduRef; //Reference to Pdu
} MkaPaeRxPdu;

typedef struct {
    int MkaBypassEtherType[255];
    int MkaBypassVlan[255];
    char MkaDstMacAddress[32];
    uint8 MkaKeyServerPriority;
    MkaRole MkaRole;
    char MkaSrcMacAddress[32];
    MkaKayParticipant Participants[MKA_MAX_PAE_INSTANCES];
} MkaKay;

typedef enum {
    MKA_PERMISSIVE_MODE_NEVER,MKA_PERMISSIVE_MODE_TIMEOUT
}MkaOnFailPermissiveMode;

/* MkaPaeInstance */
typedef struct {
    MkaOnFailPermissiveMode PermisMode;
    float32 MkaOnFailPermissiveModeTimeout;
    uint8 MkaPaeIdx;
    void* MkaEthIfControllerRef; // Symbolic name reference to EthIfController
    MkaPaeConfiguration* MkaPaeConfRef; // reference
    void* MkaSwitchPortRef; //Symbolic name reference to EthSwtPort
    MkaKay KayInstance;
    MkaPaeRxPdu RxPdu;
    MkaPaeTxPdu TxPdu;
} MkaPaeInstance;




/* Mka - Root Configuration */
typedef struct {
    MkaCryptoAlgoConfig CryptoAlgoConfigs[MKA_MAX_PAE_INSTANCES];
    MkaGeneral General;
    MkaPaeConfiguration PaeConfig[MKA_MAX_PAE_INSTANCES];
    MkaPaeInstance Paeinstance[MKA_MAX_PAE_INSTANCES];
} Mka;




#endif /* MKA_CFG_H_ */
