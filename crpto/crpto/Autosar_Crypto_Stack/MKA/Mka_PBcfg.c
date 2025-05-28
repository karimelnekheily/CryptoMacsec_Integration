// #include "Mka.h"

// /* Post-build configuration for MkaGeneral */
// static const MkaGeneral Mka_GeneralConfig = {
//     .MkaDevErrorDetect = TRUE, /* Enable development error detection [ECUC_Mka_00001] */
//     .MkaEnableSecurityEventReporting = TRUE, /* Enable security event reporting [ECUC_Mka_00004] */
//     .MkaHelloTime = 2.0f, /* MKPDU transmission interval (2 seconds) [ECUC_Mka_00007] */
//     .MkaLifeTime = 604800.0f, /* Secure Channel lifetime (7 days) [ECUC_Mka_00009] */
//     .MkaMainFunctionPeriod = 0.01f, /* Main function period (10ms) [ECUC_Mka_00003] */
//     .MkaSakRetireTime = 3600.0f, /* SAK retirement time (1 hour) */
//     .MkaVersionInfoApi = TRUE /* Enable version info API [ECUC_Mka_00002] */
// };

// /* Post-build configuration for MkaCipherSuites */
// static const MkaCipherSuites Mka_CipherSuiteConfig = {
//     .MkaMacSecCipherSuite = GCM_AES_128, /* Use GCM-AES-128 [ECUC_Mka_00049] */
//     .MkaMacSecCipherSuitePrio = 1 /* Priority 1 [ECUC_Mka_00051] */
// };

// /* Post-build configuration for MkaCryptoAlgoConfig */
// static const MkaCryptoAlgoConfig Mka_CryptoAlgoConfig = {
//     .MkaCryptoAlgoConfigIdx = 0, /* Configuration index */
//     .MkaMacSecCapability = INTEGRITY_AND_CONFIDENTIALITY, /* Support integrity and confidentiality */
//     .MkaMacSecConfidentialityOffset = OFFSET_0, /* No offset [ECUC_Mka_00026] */
//     .MkaMacSecReplayProtection = TRUE, /* Enable replay protection [ECUC_Mka_00027] */
//     .MkaMacSecReplayProtectionWindow = 0, /* Replay window size [ECUC_Mka_00028] */
//     .CipherSuite = Mka_CipherSuiteConfig /* Reference to cipher suite */
// };

// /* Post-build configuration for MkaKayParticipant */
// static const MkaKayParticipant Mka_KayParticipantConfig = {
//     .MkaParticipantActivate = TRUE, /* Activate participant */
//     .MkaCryptoAlgoRef = (MkaCryptoAlgoConfig*)&Mka_CryptoAlgoConfig, /* Reference to crypto algo config */
//     .MkaCryptoCknCakKeyRef = (void*)"CsmKey_CknCak_0", /* Symbolic name reference to CSM key for CAK/CKN [ECUC_Mka_00040] */
//     .MkaCryptoHashKey128DerivationJobRef = (void*)"CsmJob_HashKey128_0", /* Symbolic name reference to CSM job */
//     .MkaCryptoHashKey256DerivationJobRef = (void*)"CsmJob_HashKey256_0", /* Symbolic name reference to CSM job */
//     .MkaCryptoIckDeriveJobRef = (void*)"CsmJob_IckDerive_0", /* Symbolic name reference to CSM job */
//     .MkaCryptoIcvGenerateJobRef = (void*)"CsmJob_IcvGenerate_0", /* Symbolic name reference to CSM job [ECUC_Mka_00043] */
//     .MkaCryptoIcvVerifyJobRef = (void*)"CsmJob_IcvVerify_0", /* Symbolic name reference to CSM job [ECUC_Mka_00044] */
//     .MkaCryptoKekDeriveJobRef = (void*)"CsmJob_KekDerive_0", /* Symbolic name reference to CSM job [ECUC_Mka_00045] */
//     .MkaCryptoKeyUnwrapJobRef = (void*)"CsmJob_KeyUnwrap_0", /* Symbolic name reference to CSM job [ECUC_Mka_00060] */
//     .MkaCryptoKeyWrapJobRef = (void*)"CsmJob_KeyWrap_0", /* Symbolic name reference to CSM job [ECUC_Mka_00047] */
//     .MkaCryptoRandomJobRef = (void*)"CsmJob_Random_0", /* Symbolic name reference to CSM job */
//     .MkaCryptoSakKeyRef = (void*)"CsmKey_Sak_0" /* Symbolic name reference to CSM key for SAK [ECUC_Mka_00046] */
// };

// /* Post-build configuration for MkaPaeTxPdu */
// static const MkaPaeTxPdu Mka_TxPduConfig = {
//     .MkaTxPduId = 0, /* TX PDU ID */
//     .MkaPaeTxPduRef = NULL /* Reference to TX PDU (to be configured) [ECUC_Mka_00033] */
// };

// /* Post-build configuration for MkaPaeRxPdu */
// static const MkaPaeRxPdu Mka_RxPduConfig = {
//     .MkaRxPduId = 0, /* RX PDU ID */
//     .MkaPaeRxPduRef = NULL /* Reference to RX PDU (to be configured) [ECUC_Mka_00034] */
// };

// /* Post-build configuration for MkaKay */
// static const MkaKay Mka_KayConfig = {
//     .MkaBypassEtherType = {0x88E5}, /* MACsec EtherType (single entry) */
//     .MkaBypassVlan = {0}, /* No VLAN bypass [ECUC_Mka_00036] */
//     .MkaDstMacAddress = "01:80:C2:00:00:03", /* IEEE 802.1X group address [ECUC_Mka_00032] */
//     .MkaKeyServerPriority = 0xFF, /* Lowest priority for key server [ECUC_Mka_00022] */
//     .MkaRole = MKA_PEER, /* Peer role [ECUC_Mka_00029] */
//     .MkaSrcMacAddress = "00:1A:2B:3C:4D:5E", /* Example source MAC [ECUC_Mka_00031] */
//     .Participants = {Mka_KayParticipantConfig} /* Array of participants (single entry) */
// };

// /* Post-build configuration for MkaPaeConfiguration */
// static const MkaPaeConfiguration Mka_PaeConfig = {
//     .MkaAutoStart = TRUE, /* Automatically start PAE [ECUC_Mka_00012] */
//     .MkaGetMacSecStatisticsCallbackNotification = NULL, /* Callback for statistics (to be configured) */
//     .MkaPaeConfigurationIdx = 0, /* Configuration index */
//     .MkaRetryBaseDelay = 1.0f, /* Base retry delay (1 second) */
//     .MkaRetryCyclicDelay = 0.5f, /* Cyclic retry delay (500ms) */
//     .MkaSakRekeyTimeSpan = 86400.0f /* SAK rekey every 24 hours [ECUC_Mka_00024] */
// };

// /* Post-build conffiguration for MkaPaeInstance */
// static const MkaPaeInstance Mka_PaeInstanceConfig = {
//     .PermisMode = MKA_PERMISSIVE_MODE_NEVER, /* Never use permissive mode [ECUC_Mka_00018] */
//     .MkaOnFailPermissiveModeTimeout = 0.0f, /* No timeout for permissive mode */
//     .MkaPaeIdx = 0, /* PAE index */
//     .MkaEthIfControllerRef = (void*)"EthIfCtrl_0", /* Symbolic name reference to EthIf controller */
//     .MkaPaeConfRef = (MkaPaeConfiguration*)&Mka_PaeConfig, /* Reference to PAE configuration */
//     .MkaSwitchPortRef = NULL, /* Reference to EthSwtPort (to be configured) */
//     .KayInstance = Mka_KayConfig, /* KaY configuration */
//     .RxPdu = Mka_RxPduConfig, /* RX PDU configuration */
//     .TxPdu = Mka_TxPduConfig /* TX PDU configuration */
// };

// /* Post-build configuration for Mka (root) */
// static const Mka Mka_PostBuildConfig = {
//     .CryptoAlgoConfigs = {Mka_CryptoAlgoConfig}, /* Array of crypto algo configs (single entry) */
//     .General = Mka_GeneralConfig, /* General configuration */
//     .PaeConfig = {Mka_PaeConfig}, /* Array of PAE configs (single entry) */
//     .Paeinstance = {Mka_PaeInstanceConfig} /* Array of PAE instances (single entry) */
// };

// Mka_ConfigType Configtype = {
//     .MKA_Instance = Mka_PostBuildConfig
// };
