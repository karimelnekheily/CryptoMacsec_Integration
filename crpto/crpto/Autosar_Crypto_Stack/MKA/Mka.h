#ifndef MKA_H_
#define MKA_H_

#include "Std_Types.h"
#include "Det.h"
#include "Mka_Cfg.h"
#include <string.h>

/*******************************************************************************
 *                                   MACROS                                    *
 *******************************************************************************/
 #define MKA_VENDOR_ID 123
 #define MKA_MODULE_ID 45
 #define MKA_SW_MAJOR_VERSION 1
 #define MKA_SW_MINOR_VERSION 0
 #define MKA_SW_PATCH_VERSION 0
 
 
 #define MKA_MAX_PAE_INSTANCES 1
 
 /******************************************************************************
  *                      API Service Id Macros                                 *
  ******************************************************************************/
 #define MKA_INSTANCE_ID                   (0u)
 
 #define MKA_INIT_API_ID                   (uint8)0x01
 #define MKA_GETVERSIONINFO_API_ID         (uint8)0x02
 #define Mka_SETCKNSTATU_API_ID            (uint8)0x03
 #define Mka_GETCKNSTATU_API_ID            (uint8)0x04
 #define Mka_SETENABLE_API_ID              (uint8)0x08
 #define Mka_GETENABLE_API_ID              (uint8)0x05
 #define Mka_GETPAESTATUS_API_ID           (uint8)0x06
 #define Mka_SETPAEPERMISSIVEMODE_API_ID   (uint8)0x09
 #define Mka_STARTPAE_API_ID               (uint8)0x10
 #define Mka_GETMACSECSTATISTICS_API_ID    (uint8)0x1E
 #define Mka_LINKSTATECHANGE_API_ID        (uint8)0x1D
 #define Mka_RX_INDICATION_API_ID          (uint8)0x42
 #define Mka_MACSEC_ADD_TX_SA_NOTIFICATION_API_ID         (uint8)0x22
 #define Mka_MACSEC_ADD_RX_SA_NOTIFICATION_API_ID          (uint8)0x23

 
 
 /*******************************************************************************
  *                      DET Error Codes                                        *
  *******************************************************************************/
 
 #define MKA_E_INVALID_PARAM               (uint8)0x0A
 #define MKA_E_NOT_INITIALIZED             (uint8)0xF0
 
 
/*******************************************************************************
 *                              Module Data Types                              *
 *******************************************************************************/
typedef struct
{ // CUSTOMIZED For simulating MACsec Frame
    uint64 *Dmac;
    uint64 *Smac;
    // Sec Tag
    uint16 EtherType;
    uint8 TciAn;
    uint8 ShortLength;
    uint32 PacketNumber;
    uint64 SecureChannelIdentifier;
    // end of sec tag
    uint8 Payload[1500];
    uint64 ICV[2];
    uint32 CRC;
} MACsec_Frame;

typedef struct
{ // CUSTOMIZED For simulating pdu Frame
    uint64 *Dmac;
    uint64 *Smac;
    uint8 Payload[1500];
} PDU_Frame;
////////////////////////////////// According to Autosar SWS //////////////////////////////////////////////////////////////

typedef enum{
    MKA_VALIDATE_DISABLED,MKA_VALIDATE_CHECKED,MKA_VALIDATE_STRICT
}Mka_ValidateFramesType;

typedef enum{
    MKA_CONFIDENTIALITY_NONE,MKA_CONFIDENTIALITY_OFFSET_0,MKA_CONFIDENTIALITY_OFFSET_30,MKA_CONFIDENTIALITY_OFFSET_50
}Mka_ConfidentialityOffsetType;

typedef struct{
    boolean ProtectFrames;
    boolean ReplayProtect;
    uint32 ReplayWindow;
    Mka_ValidateFramesType ValidateFrames;
    uint64 CurrentCipherSuite;
    Mka_ConfidentialityOffsetType ConfidentialityOffset;
    boolean ControlledPortEnabled;
    const uint16* BypassedVlanPtrs;
    uint8 BypassedVlansLength;
    const uint16* BypassedEtherTypesPtr;
    uint8 BypassedEtherTypesLength;
}Mka_MacSecConfigType;

typedef struct
{
    uint64 OutPkts_Untagged;
    uint64 OutPkts_TooLong;
    uint64 OutOctets_Protected;
    uint64 OutOctets_Encrypted;
} Mka_Stats_Tx_SecYType;

typedef struct
{
    uint64 InPkts_Untagged;
    uint64 nPkts_NoTag;
    uint64 InPkts_BadTag;
    uint64 InPkts_NoSa;
    uint64 InPkts_NoSaError;
    uint64 InPkts_Overrun;
    uint64 InOctets_Validated;
    uint64 InOctets_Decrypted;
} Mka_Stats_Rx_SecYType;

typedef struct
{
    uint64 OutPkts_Protected;
    uint64 OutPkts_Encrypted;
} Mka_Stats_Tx_ScType;

typedef struct
{
    uint64 InPkts_Ok;
    uint64 InPkts_Unchecked;
    uint64 InPkts_Delayed;
    uint64 InPkts_Late;
    uint64 InPkts_Invalid;
    uint64 InPkts_NotValid;
} Mka_Stats_Rx_ScType;

typedef struct
{
    const uint8 *HashKeyPtr;
    const uint8 *SakKeyPtr;
    const uint8 *SaltKeyPtr;
} Mka_SakKeyPtrType;

typedef enum
{
    MKA_PERMISSIVE_MODE_NEVER,
    MKA_PERMISSIVE_MODE_TIMEOUT
} Mka_PermissiveModeType;

typedef struct
{
    Mka_Stats_Tx_SecYType StatsTxPhy;
    Mka_Stats_Rx_SecYType StatsRxPhy;
    Mka_Stats_Tx_ScType StatsTxSc;
    Mka_Stats_Rx_ScType StatsRxSc;
} Mka_Stats_SecYType;

typedef enum
{
    MKA_STATUS_MACSEC_RUNNING,
    MKA_STATUS_WAITING_PEER_LINK,
    MKA_STATUS_WAITING_PEER,
    MKA_STATUS_IN_PROGRESS,
    MKA_STATUS_AUTH_FAIL_UNKNOWN_PEER,
    MKA_STATUS_UNDEFINED = 0xFF
} Mka_MkaStatus;

typedef struct
{
    Mka_MkaStatus ConnectionStatus;
    uint64 PeerSci;
    uint8 CknInUse[32];
} Mka_PaeStatusType;

//gad3na mnini
typedef struct{
    
}EthTrcv_LinkStateType;

//gad3na mnini
typedef struct{
}PduIdType;

//gad3na mnini
typedef struct{
}PduInfoType;


typedef struct{
    Mka MKA_Instance;
}Mka_ConfigType;



/*******************************************************************************
 *                      Function Prototypes                                    *
 *******************************************************************************/

void Mka_Init(const Mka_ConfigType *ConfigPtr);

Std_ReturnType Mka_SetCknStatus(uint8 MkaPaeIdx, boolean Enable, const uint8 *Ckn, uint8 CknLength);

Std_ReturnType Mka_GetCknStatus(uint8 MkaPaeIdx, const uint8 *Ckn, uint8 CknLength, boolean *EnablePtr);

Std_ReturnType Mka_SetEnable(uint8 MkaPaeIdx, boolean Enable);

Std_ReturnType Mka_GetEnable(uint8 MkaPaeIdx, boolean *EnablePtr);

Std_ReturnType Mka_GetPaeStatus(uint8 MkaPaeIdx, Mka_PaeStatusType *PaeStatusPtr);

Std_ReturnType Mka_SetPaePermissiveMode(uint8 MkaPaeIdx, Mka_PermissiveModeType PermissiveMode);

Std_ReturnType Mka_StartPae(uint8 MkaPaeIdx);

Std_ReturnType Mka_GetMacSecStatistics(uint8 MkaPaeIdx, Mka_Stats_SecYType *MacSecStatsPtr);

Std_ReturnType Mka_LinkStateChange(uint8 MkaPaeIdx, EthTrcv_LinkStateType TransceiverLinkState);

// customized for SECY
Std_ReturnType CheckICV(MACsec_Frame Mpdu);
MACsec_Frame GenerateMACsec_Frame(PDU_Frame PD_Frame);
Std_ReturnType getSAK(Mka_SakKeyPtrType *SakKeyPtr);
void getKeyDerivaions(uint64 *CAK, uint64 *KEK, uint64 *ICK);
////////////////////call backs///////////////////////////////////

void Mka_GetMacSecStatisticsNotification (uint8 MkaPaeIdx,Std_ReturnType Result);

void Mka_RxIndication (PduIdType RxPduId,const PduInfoType* PduInfoPtr);

void Mka_TxConfirmation (PduIdType TxPduId,Std_ReturnType result);

void Mka_MacSecUpdateSecYNotification (uint8 MkaPaeIdx,Std_ReturnType Result);

void Mka_MacSecAddTxSaNotification (uint8 MkaPaeIdx,Std_ReturnType Result);

void Mka_MacSecAddRxSaNotification (uint8 MkaPaeIdx,Std_ReturnType Result);



#endif /* MKA_H_ */
