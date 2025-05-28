#include "Mka.h"
#include "Crypto.h"
#include "Crypto_Cfg.h"
#include "Crypto_GeneralTypes.h"
#include "Std_Types.h"
#include "stdbool.h"
#include "stdio.h"
#include "mbedtls/gcm.h"

/* Static Module State */
static Mka_ConfigType Mka_Config;
static Mka_PaeStatusType Mka_PaeStatus[MKA_MAX_PAE_INSTANCES];
static Mka_Stats_SecYType Mka_Stats;
static uint8 Mka_IsInitialized = FALSE;

// DONE
void Mka_Init(const Mka_ConfigType *ConfigPtr)
{

    Mka_Config = *ConfigPtr;

    // Initialize PAE instances
    for (uint8 i = 0; i < MKA_MAX_PAE_INSTANCES; i++)
    {
        Mka_PaeStatus[i].ConnectionStatus = MKA_STATUS_UNDEFINED;
        Mka_PaeStatus[i].PeerSci = 0;
        for (uint8 j = 0; j < 32; j++)
        {
            Mka_PaeStatus[i].CknInUse[j] = 0;
        }
    }
    // Initialize statistics
    // Initialize SecY module statistics
    // FOR Transmission
    Mka_Stats.StatsTxPhy.OutPkts_Untagged = 0;
    Mka_Stats.StatsTxPhy.OutPkts_TooLong = 0;
    Mka_Stats.StatsTxPhy.OutOctets_Protected = 0;
    Mka_Stats.StatsTxPhy.OutOctets_Encrypted = 0;
    // FOR Reception
    Mka_Stats.StatsRxPhy.InPkts_Untagged = 0;
    Mka_Stats.StatsRxPhy.InPkts_BadTag = 0;
    Mka_Stats.StatsRxPhy.InPkts_NoSa = 0;
    Mka_Stats.StatsRxPhy.InPkts_NoSaError = 0;
    Mka_Stats.StatsRxPhy.InPkts_Overrun = 0;
    Mka_Stats.StatsRxPhy.InOctets_Validated = 0;
    Mka_Stats.StatsRxPhy.InOctets_Decrypted = 0;
    // SET Secure Channel transmission statistics
    Mka_Stats.StatsTxSc.OutPkts_Protected = 0;
    Mka_Stats.StatsTxSc.OutPkts_Encrypted = 0;
    // SET Secure Channel Reception statistics
    Mka_Stats.StatsRxSc.InPkts_Ok = 0;
    Mka_Stats.StatsRxSc.InPkts_Unchecked = 0;
    Mka_Stats.StatsRxSc.InPkts_Delayed = 0;
    Mka_Stats.StatsRxSc.InPkts_Late = 0;
    Mka_Stats.StatsRxSc.InPkts_Invalid = 0;
    Mka_Stats.StatsRxSc.InPkts_NotValid = 0;
// mafroud eli y set ethernetSM maarfsh anani al keda leh 
    // Configure EthIf for MKA messages
    for (uint8 i = 0; i < MKA_MAX_PAE_INSTANCES; i++)
    {
       // EthIf_SetControllerMode(Mka_Config.MKA_Instance.Paeinstance[i].MkaPaeConfRef->MkaEthIfControllerRef, ETH_MODE_ACTIVE);
    }
    Mka_IsInitialized = TRUE;
}
// DONE
void Mka_GetVersionInfo(Std_VersionInfoType *VersionInfoPtr)
{
    if (VersionInfoPtr == NULL)
    {
        if (Mka_Config.MKA_Instance.General.MkaDevErrorDetect == STD_ON)
        {
            Det_ReportError(MKA_MODULE_ID, MKA_INSTANCE_ID, MKA_GETVERSIONINFO_API_ID, MKA_E_INVALID_PARAM);
        }
        return;
    }

    VersionInfoPtr->vendorID = MKA_VENDOR_ID;
    VersionInfoPtr->moduleID = MKA_MODULE_ID;
    VersionInfoPtr->sw_major_version = MKA_SW_MAJOR_VERSION;
    VersionInfoPtr->sw_minor_version = MKA_SW_MINOR_VERSION;
    VersionInfoPtr->sw_patch_version = MKA_SW_PATCH_VERSION;
}

// Done but need to be revised with crypto team
Std_ReturnType Mka_SetCknStatus(uint8 MkaPaeIdx, boolean Enable, const uint8 *Ckn, uint8 CknLength)
{
    Std_ReturnType retVal = E_OK;

    /* Check if the MKA module is initialized */
    if (!Mka_IsInitialized)
    {
        if (Mka_Config.MKA_Instance.General.MkaDevErrorDetect == STD_ON)
        {
            Det_ReportError(MKA_MODULE_ID, MKA_INSTANCE_ID, Mka_SETCKNSTATU_API_ID, MKA_E_NOT_INITIALIZED);
        }
        return E_NOT_OK;
    }

    /*Validate MkaPaeIdx */
    if (MkaPaeIdx >= MKA_MAX_PAE_INSTANCES)
    {
        if (Mka_Config.MKA_Instance.General.MkaDevErrorDetect == STD_ON)
        {
            Det_ReportError(MKA_MODULE_ID, MKA_INSTANCE_ID, Mka_SETCKNSTATU_API_ID, MKA_E_INVALID_PARAM);
        }
        return E_NOT_OK;
    }

    /*Validate Ckn and CknLength */
    if (Ckn == NULL || CknLength == 0 || CknLength > 32)
    {
        if (Mka_Config.MKA_Instance.General.MkaDevErrorDetect == STD_ON)
        {
            Det_ReportError(MKA_MODULE_ID, MKA_INSTANCE_ID, Mka_SETCKNSTATU_API_ID, MKA_E_INVALID_PARAM);
        }
        return E_NOT_OK;
    }

    Mka_Config.MKA_Instance.Paeinstance[MkaPaeIdx].KayInstance.Participants[MkaPaeIdx].MkaParticipantActivate = Enable;


    Mka_Config.MKA_Instance.Paeinstance[MkaPaeIdx].KayInstance.Participants[MkaPaeIdx].MkaCryptoCknCakKeyRef = Ckn; 

    // under discussion
    // if (WriteToNvm(MkaPaeIdx, Enable) != E_OK)
    // {
    //     retVal = E_NOT_OK;
    //     /* Optionally report to DET if needed */
    // }

    return retVal;
}

Std_ReturnType Mka_GetCknStatus(uint8 MkaPaeIdx, const uint8 *Ckn, uint8 CknLength, boolean *EnablePtr)
{

    /* Check if the MKA module is initialized */
    if (!Mka_IsInitialized)
    {
        if (Mka_Config.MKA_Instance.General.MkaDevErrorDetect == STD_ON)
        {
            Det_ReportError(MKA_MODULE_ID, MKA_INSTANCE_ID, Mka_SETCKNSTATU_API_ID, MKA_E_NOT_INITIALIZED);
        }
        return E_NOT_OK;
    }

    /*Validate MkaPaeIdx */
    if (MkaPaeIdx >= MKA_MAX_PAE_INSTANCES)
    {
        if (Mka_Config.MKA_Instance.General.MkaDevErrorDetect == STD_ON)
        {
            Det_ReportError(MKA_MODULE_ID, MKA_INSTANCE_ID, Mka_SETCKNSTATU_API_ID, MKA_E_INVALID_PARAM);
        }
        return E_NOT_OK;
    }

    /*Validate Ckn and CknLength */
    if (Ckn == NULL || CknLength == 0 || CknLength > 32)
    {
        if (Mka_Config.MKA_Instance.General.MkaDevErrorDetect == STD_ON)
        {
            Det_ReportError(MKA_MODULE_ID, MKA_INSTANCE_ID, Mka_SETCKNSTATU_API_ID, MKA_E_INVALID_PARAM);
        }
        return E_NOT_OK;
    }

    for (uint8 i = 0; ((i < CknLength) && (i < 32)); i++)
    {
        if (&Mka_Config.MKA_Instance.Paeinstance[MkaPaeIdx].KayInstance.Participants[MkaPaeIdx].MkaCryptoCknCakKeyRef[i] != (void *)&Ckn[i]) /* Placeholder; actual key reference needed */
        {
            return E_NOT_OK;
        }
    }

    *EnablePtr = Mka_Config.MKA_Instance.Paeinstance[MkaPaeIdx].KayInstance.Participants[MkaPaeIdx].MkaParticipantActivate;
    return E_OK;
}

// Done
Std_ReturnType Mka_SetEnable(uint8 MkaPaeIdx, boolean Enable)
{
    if (MkaPaeIdx >= MKA_MAX_PAE_INSTANCES)
    {
        if (Mka_Config.MKA_Instance.General.MkaDevErrorDetect == STD_ON)
        {
            Det_ReportError(MKA_MODULE_ID, MKA_INSTANCE_ID, Mka_SETENABLE_API_ID, MKA_E_INVALID_PARAM);
        }
        return E_NOT_OK;
    }
    Mka_Config.MKA_Instance.Paeinstance[MkaPaeIdx].KayInstance.Participants[MkaPaeIdx].MkaParticipantActivate = Enable;
    return E_OK;
}
// DONE
Std_ReturnType Mka_GetEnable(uint8 MkaPaeIdx, boolean *EnablePtr)
{
    if (MkaPaeIdx >= MKA_MAX_PAE_INSTANCES || EnablePtr == NULL)
    {
        if (Mka_Config.MKA_Instance.General.MkaDevErrorDetect == STD_ON)
        {
            Det_ReportError(MKA_MODULE_ID, MKA_INSTANCE_ID, Mka_SETENABLE_API_ID, MKA_E_INVALID_PARAM);
        }
        return E_NOT_OK;
    }
    *EnablePtr = Mka_Config.MKA_Instance.Paeinstance[MkaPaeIdx].KayInstance.Participants[MkaPaeIdx].MkaParticipantActivate;
    return E_OK;
}
// DONE
Std_ReturnType Mka_GetPaeStatus(uint8 MkaPaeIdx, Mka_PaeStatusType *StatusPtr)
{
    if (MkaPaeIdx >= MKA_MAX_PAE_INSTANCES || StatusPtr == NULL)
    {
        if ((Mka_Config.MKA_Instance.General.MkaDevErrorDetect == STD_ON))
        {
            Det_ReportError(MKA_MODULE_ID, MKA_INSTANCE_ID, Mka_GETPAESTATUS_API_ID, MKA_E_INVALID_PARAM);
        }
        return E_NOT_OK;
    }

    *StatusPtr = Mka_PaeStatus[MkaPaeIdx];
    return E_OK;
}
// Done
Std_ReturnType Mka_SetPaePermissiveMode(uint8 MkaPaeIdx, Mka_PermissiveModeType Mode)
{
    if (MkaPaeIdx >= MKA_MAX_PAE_INSTANCES)
    {
        if (Mka_Config.MKA_Instance.General.MkaDevErrorDetect == STD_ON)
        {
            Det_ReportError(MKA_MODULE_ID, MKA_INSTANCE_ID, Mka_SETENABLE_API_ID, MKA_E_INVALID_PARAM);
        }
        return E_NOT_OK;
    }
    Mka_Config.MKA_Instance.Paeinstance[MkaPaeIdx].PermisMode = Mode;
    return E_OK;
}

Std_ReturnType Mka_StartPae(uint8 MkaPaeIdx)
{
    if (!Mka_IsInitialized)
    {
        if (Mka_Config.MKA_Instance.General.MkaDevErrorDetect == STD_ON)
        {
            Det_ReportError(MKA_MODULE_ID, MKA_INSTANCE_ID, Mka_SETCKNSTATU_API_ID, MKA_E_NOT_INITIALIZED);
        }
        return E_NOT_OK;
    }

    /*Validate MkaPaeIdx */
    if (MkaPaeIdx >= MKA_MAX_PAE_INSTANCES)
    {
        if (Mka_Config.MKA_Instance.General.MkaDevErrorDetect == STD_ON)
        {
            Det_ReportError(MKA_MODULE_ID, MKA_INSTANCE_ID, Mka_SETCKNSTATU_API_ID, MKA_E_INVALID_PARAM);
        }
        return E_NOT_OK;
    }
    if (!Mka_Config.MKA_Instance.Paeinstance[MkaPaeIdx].MkaPaeConfRef->MkaAutoStart)
    {
        // Interact with Ethernet interface to start PAE
        // Assuming EthIf_StartPae is a function to initiate PAE on Ethernet
        // Question: Sync/Key agreeament ?
        // ana eli a3rafo ne3mel EthIf_Transmit fiha el PDU w allah a3lam
        // d kalam anani basha 
        if (EthIf_StartPae(MkaPaeIdx))
        {
            return E_OK;
        }
        else
        {
            return E_NOT_OK;
        }
    }
    // No effect if MkaAutoStart is TRUE
    return E_OK;
}

// Done
Std_ReturnType Mka_GetMacSecStatistics(uint8 MkaPaeIdx, Mka_Stats_SecYType *MacSecStatsPtr)
{
    if (MkaPaeIdx >= MKA_MAX_PAE_INSTANCES || MacSecStatsPtr == NULL)
    {
        if (Mka_Config.MKA_Instance.General.MkaDevErrorDetect == STD_ON)
        {
            Det_ReportError(MKA_MODULE_ID, MKA_INSTANCE_ID, Mka_GETMACSECSTATISTICS_API_ID, MKA_E_INVALID_PARAM);
        }
        return E_NOT_OK;
    }

    *MacSecStatsPtr = Mka_Stats;
    // must be writen in nvm/flash
    return E_OK;
}

// DONE
// NEED TO BE REVISED With Bootloader team (EthIf)
// triggers mka ??
// Std_ReturnType Mka_LinkStateChange(uint8 MkaPaeIdx, EthTrcv_LinkStateType TransceiverLinkState)
// {
//     Validate initialization
//     if (Mka_Config == NULL)
//     {
//         Det_ReportError(MKA_MODULE_ID, MKA_INSTANCE_ID, Mka_LINKSTATECHANGE_API_ID, MKA_E_NOT_INITIALIZED);
//         return E_NOT_OK;
//     }
//     Validate MkaPaeIdx
//     if (MkaPaeIdx >= MKA_MAX_PAE_INSTANCES)
//     {
//         if ((Mka_Config.MKA_Instance.General.MkaDevErrorDetect == STD_ON))
//         {
//             Det_ReportError(MKA_MODULE_ID, MKA_INSTANCE_ID, Mka_LINKSTATECHANGE_API_ID, MKA_E_INVALID_PARAM);
//         }
//         return E_NOT_OK;
//     }
//     // Validate TransceiverLinkState
//     if (Mka_Config.MKA_Instance.General.MkaDevErrorDetect == STD_ON)
//     {
//         if (TransceiverLinkState != ETHTRCV_LINK_STATE_ACTIVE && TransceiverLinkState != ETHTRCV_LINK_STATE_DOWN)
//         {
//             Det_ReportError(MKA_MODULE_ID, MKA_INSTANCE_ID, Mka_LINKSTATECHANGE_API_ID, MKA_E_INVALID_PARAM);
//             return E_NOT_OK;
//         }
//     }

//     Store the current state to check if it changes
//     Mka_MkaStatus previousState = Mka_PaeStatus[MkaPaeIdx].ConnectionStatus;

//      Update state based on link state
//     if (TransceiverLinkState == ETHTRCV_LINK_STATE_ACTIVE)
//     {
//         Mka_PaeStatus[MkaPaeIdx].ConnectionStatus = MKA_STATUS_WAITING_PEER;
//     }
//     else
//     {
//         Mka_PaeStatus[MkaPaeIdx].ConnectionStatus = MKA_STATUS_WAITING_PEER_LINK;
//         // Reset peer-related state when link goes down
//         Mka_PaeStatus[MkaPaeIdx].PeerSci = 0;
//         for (uint8 j = 0; j < 32; j++)
//         {
//             Mka_PaeStatus[MkaPaeIdx].CknInUse[j] = 0;
//         }
//     }

//      Return E_OK if the state changed (indicating the MKA sequence can proceed), E_NOT_OK otherwise
//     if (previousState != Mka_PaeStatus[MkaPaeIdx].ConnectionStatus)
//     {
//         return E_OK;
//     }
//     else
//     {
//         return E_NOT_OK;
//     }
// }

////////////////////////////CALL BACKS////////////////////////////////////////////////
/** 
*
* note:      all call back functions not completed and needs to be updated
*            there is some implmentations according to IEEE as there is no info in AUTOSAR
*
*/

void Mka_GetMacSecStatisticsNotification(uint8 MkaPaeIdx, Std_ReturnType Result)
{
    /* Check if the MKA module is initialized */
    if (!Mka_IsInitialized)
    {
        if (Mka_Config.MKA_Instance.General.MkaDevErrorDetect == STD_ON)
        {
            Det_ReportError(MKA_MODULE_ID, MKA_INSTANCE_ID, Mka_GETMACSECSTATISTICS_API_ID, MKA_E_NOT_INITIALIZED);
        }
        return;
    }

    /* Check if MkaPaeIdx is valid */
    if (MkaPaeIdx >= MKA_MAX_PAE_INSTANCES)
    {
        if (Mka_Config.MKA_Instance.General.MkaDevErrorDetect == STD_ON)
        {
            Det_ReportError(MKA_MODULE_ID, MKA_INSTANCE_ID, Mka_GETMACSECSTATISTICS_API_ID, MKA_E_INVALID_PARAM);
        }
        return;
    }

    /* Process the result of getting MACsec statistics */
    if (Result == E_OK)
    {
        /* Statistics retrieval successful - can perform any necessary actions */
        if (Mka_Config.MKA_Instance.Paeinstance[MkaPaeIdx].MkaPaeConfRef->MkaGetMacSecStatisticsCallbackNotification != NULL)
        {
            /* Call the user-configured callback if available */
            ((void (*)(uint8, Std_ReturnType))Mka_Config.MKA_Instance.Paeinstance[MkaPaeIdx].MkaPaeConfRef->MkaGetMacSecStatisticsCallbackNotification)(MkaPaeIdx, Result);
        }
    }
    else
    {
        /* Statistics retrieval failed - handle error case */
        if (Mka_Config.MKA_Instance.General.MkaEnableSecurityEventReporting == TRUE)
        {
            /* Report security event if enabled */
            /* This would typically call a security event reporting function */
        }
    }
}

// not completed ----- needs updates and should be integrated by bootLoader team
// PduInfoPtr  this should be taken from boot loader
// PduInfoPtr:	Pointer to a structure containing the received PDU data
// void Mka_RxIndication(PduIdType RxPduId, const PduInfoType *PduInfoPtr)
// {
//     uint8 i;
//     boolean validPdu = FALSE;
//     uint8 targetMkaPaeIdx = 0xFF;

//     /* Check if the MKA module is initialized */
//     if (!Mka_IsInitialized)
//     {
//         if (Mka_Config.MKA_Instance.General.MkaDevErrorDetect == STD_ON)
//         {
//             Det_ReportError(MKA_MODULE_ID, MKA_INSTANCE_ID, Mka_RX_INDICATION_API_ID, MKA_E_NOT_INITIALIZED);
//         }
//         return;
//     }

//     /* Validate parameters */
//     if (PduInfoPtr == NULL)
//     {
//         if (Mka_Config.MKA_Instance.General.MkaDevErrorDetect == STD_ON)
//         {
//             Det_ReportError(MKA_MODULE_ID, MKA_INSTANCE_ID, Mka_RX_INDICATION_API_ID, MKA_E_INVALID_PARAM);
//         }
//         return;
//     }

//     /*EAPOL-MKA frame:   */
//     if (PduInfoPtr->SduLength < 4)
//     {
//         /* Too short to be a valid EAPOL frame */
//         return;
//     }

//     /* Find the PAE instance matching the RxPduId */
//     for (i = 0; i < MKA_MAX_PAE_INSTANCES; i++)
//     {
//         if (Mka_Config.MKA_Instance.Paeinstance[i].RxPdu.MkaRxPduId == RxPduId)
//         {
//             validPdu = TRUE;
//             targetMkaPaeIdx = i;
//             break;
//         }
//     }

//     if (!validPdu)
//     {
//         /* No matching PAE instance for this PduId */
//         if (Mka_Config.MKA_Instance.General.MkaDevErrorDetect == STD_ON)
//         {
//             Det_ReportError(MKA_MODULE_ID, MKA_INSTANCE_ID, Mka_RX_INDICATION_API_ID, MKA_E_INVALID_PARAM);
//         }
//         return;
//     }

//     /* Check if this PAE instance is active */
//     if (!Mka_Config.MKA_Instance.Paeinstance[targetMkaPaeIdx].KayInstance.Participants[targetMkaPaeIdx].MkaParticipantActivate)
//     {
//         /* PAE instance is not active, ignore the PDU */
//         return;
//     }

//     /* Verify this is an EAPOL-MKA frame (EAPOL type 5) */
//     if (PduInfoPtr->SduDataPtr[1] != 5) /* Not MKA type */
//     {
//         /* Not an MKA packet, ignore */
//         return;
//     }

//     /* Process the received EAPOL-MKA frame */

//     if (PduInfoPtr->SduLength >= 4) /* Minimum size of EAPOL header */
//     {
//         /* Verify this is an EAPOL-MKA frame (EAPOL type 5) */
//         if (PduInfoPtr->SduDataPtr[1] == 5) /* MKA type */
//         {
//             /* Process the MKA PDU */
//             /* This would typically include:
//              * 1. Validate the ICV (Integrity Check Value)
//              * 2. Extract the Basic Parameter Set
//              * 3. Update peer information
//              * 4. Process key server election if needed
//              * 5. Handle SAK distribution if needed
//              */
//             if (CheckICV(*(MACsec_Frame *)PduInfoPtr->SduDataPtr) == E_OK)
//             {
//                 /* ICV validation successful, update PAE status */
//                 Mka_PaeStatus[targetMkaPaeIdx].ConnectionStatus = MKA_STATUS_IN_PROGRESS;

//                 /* Update peer SCI from the received PDU (simplified for this implementation) */
//                 /* In a real implementation, you would extract the SCI from the appropriate field */
//                 Mka_PaeStatus[targetMkaPaeIdx].PeerSci = 0x1234567890ABCDEF; /* Example value */

//                 /* Additional MKA protocol processing would happen here */
//             }
//             else
//             {
//                 /* ICV validation failed, potential security breach */
//                 Mka_PaeStatus[targetMkaPaeIdx].ConnectionStatus = MKA_STATUS_AUTH_FAIL_UNKNOWN_PEER;

//                 if (Mka_Config.MKA_Instance.General.MkaEnableSecurityEventReporting == TRUE)
//                 {
//                     /* Report security event if enabled */
//                     /* This would typically call a security event reporting function */
//                 }
//             }
//         }
//     }
// }

// void Mka_TxConfirmation(PduIdType TxPduId, Std_ReturnType Result)
// {
//     uint8 i;
//     boolean validPdu = FALSE;
//     uint8 targetMkaPaeIdx = 0xFF;

//     /* Check if the MKA module is initialized */
//     if (!Mka_IsInitialized)
//     {
//         if (Mka_Config.MKA_Instance.General.MkaDevErrorDetect == STD_ON)
//         {
//             Det_ReportError(MKA_MODULE_ID, MKA_INSTANCE_ID, 0x21, MKA_E_NOT_INITIALIZED);
//         }
//         return;
//     }

//     /* Find the PAE instance matching the TxPduId */
//     for (i = 0; i < MKA_MAX_PAE_INSTANCES; i++)
//     {
//         if (Mka_Config.MKA_Instance.Paeinstance[i].TxPdu.MkaTxPduId == TxPduId)
//         {
//             validPdu = TRUE;
//             targetMkaPaeIdx = i;
//             break;
//         }
//     }

//     if (!validPdu)
//     {
//         /* No matching PAE instance for this PduId */
//         if (Mka_Config.MKA_Instance.General.MkaDevErrorDetect == STD_ON)
//         {
//             Det_ReportError(MKA_MODULE_ID, MKA_INSTANCE_ID, 0x21, MKA_E_INVALID_PARAM);
//         }
//         return;
//     }

//     /* Process the transmission confirmation result */
//     if (Result == E_OK)
//     {
//         /* Transmission successful */
//         /* Update any statistics or state if needed */
//         Mka_Stats.StatsTxPhy.OutPkts_Untagged++;
//     }
//     else
//     {
//         /* Transmission failed */
//         /* Handle retransmission or report error */
//         if (Mka_Config.MKA_Instance.General.MkaEnableSecurityEventReporting == TRUE)
//         {
//             /* Report security event if enabled */
//             /* This would typically call a security event reporting function */
//         }
//     }
// }

// void Mka_MacSecUpdateSecYNotification(uint8 MkaPaeIdx, Std_ReturnType Result)
// {
//     /* Check if the MKA module is initialized */
//     if (!Mka_IsInitialized)
//     {
//         if (Mka_Config.MKA_Instance.General.MkaDevErrorDetect == STD_ON)
//         {
//             Det_ReportError(MKA_MODULE_ID, MKA_INSTANCE_ID, 0x22, MKA_E_NOT_INITIALIZED);
//         }
//         return;
//     }

//     /* Check if MkaPaeIdx is valid */
//     if (MkaPaeIdx >= MKA_MAX_PAE_INSTANCES)
//     {
//         if (Mka_Config.MKA_Instance.General.MkaDevErrorDetect == STD_ON)
//         {
//             Det_ReportError(MKA_MODULE_ID, MKA_INSTANCE_ID, 0x22, MKA_E_INVALID_PARAM);
//         }
//         return;
//     }

//     /* Process the SecY update result */
//     if (Result == E_OK)
//     {
//         /* SecY update successful */
//         /* Update MKA state to reflect the successful SecY update */
//         if (Mka_PaeStatus[MkaPaeIdx].ConnectionStatus == MKA_STATUS_IN_PROGRESS)
//         {
//             Mka_PaeStatus[MkaPaeIdx].ConnectionStatus = MKA_STATUS_MACSEC_RUNNING;
//         }
//     }
//     else
//     {
//         /* SecY update failed */
//         /* Handle error case */
//         if (Mka_Config.MKA_Instance.General.MkaEnableSecurityEventReporting == TRUE)
//         {
//             /* Report security event if enabled */
//             /* This would typically call a security event reporting function */
//         }
//     }
// }

// void Mka_MacSecAddTxSaNotification(uint8 MkaPaeIdx, Std_ReturnType Result)
// {
//     /* Check if the MKA module is initialized */
//     if (!Mka_IsInitialized)
//     {
//         if (Mka_Config.MKA_Instance.General.MkaDevErrorDetect == STD_ON)
//         {
//             Det_ReportError(MKA_MODULE_ID, MKA_INSTANCE_ID, Mka_MACSEC_ADD_TX_SA_NOTIFICATION_API_ID, MKA_E_NOT_INITIALIZED);
//         }
//         return;
//     }

//     /* Check if MkaPaeIdx is valid */
//     if (MkaPaeIdx >= MKA_MAX_PAE_INSTANCES)
//     {
//         if (Mka_Config.MKA_Instance.General.MkaDevErrorDetect == STD_ON)
//         {
//             Det_ReportError(MKA_MODULE_ID, MKA_INSTANCE_ID, Mka_MACSEC_ADD_TX_SA_NOTIFICATION_API_ID, MKA_E_INVALID_PARAM);
//         }
//         return;
//     }

//     /* Process the result of adding a transmit secure association */
//     if (Result == E_OK)
//     {

//     }
//     else
//     {
//         /* TX SA add failed */
//         /* Handle error case */
//         if (Mka_Config.MKA_Instance.General.MkaEnableSecurityEventReporting == TRUE)
//         {

//         }
//     }
// }

// void Mka_MacSecAddRxSaNotification(uint8 MkaPaeIdx, Std_ReturnType Result)
// {
//     /* Check if the MKA module is initialized */
//     if (!Mka_IsInitialized)
//     {
//         if (Mka_Config.MKA_Instance.General.MkaDevErrorDetect == STD_ON)
//         {
//             Det_ReportError(MKA_MODULE_ID, MKA_INSTANCE_ID, Mka_MACSEC_ADD_RX_SA_NOTIFICATION_API_ID, MKA_E_NOT_INITIALIZED);
//         }
//         return;
//     }

//     /* Check if MkaPaeIdx is valid */
//     if (MkaPaeIdx >= MKA_MAX_PAE_INSTANCES)
//     {
//         if (Mka_Config.MKA_Instance.General.MkaDevErrorDetect == STD_ON)
//         {
//             Det_ReportError(MKA_MODULE_ID, MKA_INSTANCE_ID, Mka_MACSEC_ADD_RX_SA_NOTIFICATION_API_ID, MKA_E_INVALID_PARAM);
//         }
//         return;
//     }

//     /* Process the result of adding a receive secure association */
//     if (Result == E_OK)
//     {
//         /* RX SA add successful */
//         /* Update any state or statistics if needed */
//         /* For example, we might want to update reception statistics */
//     }
//     else
//     {
//         /* RX SA add failed */
//         /* Handle error case */
//         if (Mka_Config.MKA_Instance.General.MkaEnableSecurityEventReporting == TRUE)
//         {
//             /* Report security event if enabled */
//             /* This would typically call a security event reporting function */
//         }
//     }
// }

// //////////////////////SCHEDULED FUNCTIONS/////////////////////////////////////////////
// void Mka_MainFunction(void)
// {
//     if (Mka_IsInitialized)
//     {
//         // Cyclic job: Check timers, refresh keys, update states.
//     }
// }

///////////////////////////customized Methods for SECY///////////////////////////////

//Method To check ICV of given (M/MK)PDU "Recieved from peer"
Std_ReturnType CheckICV( uint8_t *Mpdu, uint32 length, uint8_t *mac)
{    
    // w mehtag jobId w channelId
    Crypto_JobType macVerifyJob;

    macVerifyJob.jobState = CRYPTO_JOBSTATE_IDLE;
    // array 
    //uint32 dataLength = sizeof(data);
    //array bet3 icv
    //uint32 macLength = sizeof(mac);
    Crypto_VerifyResultType verifyResult;


    // Assign pointers to your data and MAC
    const uint8* dataPtr = &Mpdu;
    const uint8* macPtr = &mac;                            //   &Mpdu[length];// hanshil el ICV w crc
    uint16 DataLen=length;// hanshil el ICV w crc
    uint32 outputLenght = 16;
    uint8 output[16] ;
    macVerifyJob.jobPrimitiveInputOutput.inputPtr = dataPtr;
    macVerifyJob.jobPrimitiveInputOutput.inputLength = DataLen;
    
    macVerifyJob.jobPrimitiveInputOutput.secondaryInputPtr = macPtr;
    macVerifyJob.jobPrimitiveInputOutput.secondaryInputLength = 16;

    macVerifyJob.jobPrimitiveInputOutput.outputPtr = output;
    macVerifyJob.jobPrimitiveInputOutput.outputLengthPtr = &outputLenght;

    macVerifyJob.jobPrimitiveInputOutput.verifyPtr = &verifyResult;
   // encrypt or decrypt or verify or macgenerate 
    macVerifyJob.jobPrimitiveInfo = &verifyJob ;
   // operation mode
    macVerifyJob.jobPrimitiveInputOutput.mode=CRYPTO_OPERATIONMODE_SINGLECALL;
Crypto_Init(&Crypto_PBConfig);
macVerifyJob.cryptoKeyId = 0; // Use your actual key ID
macVerifyJob.jobState = CRYPTO_JOBSTATE_ACTIVE;

Crypto_ProcessJob(0, &macVerifyJob);
// check if the ICV is correct
//uint8* output1 = macVerifyJob.jobPrimitiveInputOutput.outputPtr;



Std_ReturnType retVal = E_NOT_OK;
        if(*(macVerifyJob.jobPrimitiveInputOutput.verifyPtr) == 0x00) {
            printf("\nMAC verification succeeded - Message is authentic\n");
            retVal = E_OK;
        } else {
            printf("\nMAC verification failed - Potential tampering detected!\n");

        }
    return retVal;
}
 
// Method to generate ICV for pdu frame "Gonna be transimted to peer"
// also add sec tag
Std_ReturnType GenerateMACsec_Frame(uint8_t *pdu, uint16 length,  uint8_t *Mpdu)
{
    uint16 pduLength = length; // D + S + PayLoad + CRC
    uint16 MpduLength = length + 16;     // pdu length + 16 bytes for sectag

    //CLONE DATA FROM PDU TO MPDU EXCLUDING CRC
    for(uint16 i = 0 ; i<(pduLength-4) ; i++) // SUBTRACT 4 bytes for CRC NEGLECTION
    {
        if(i >= 12){
            Mpdu[i+16] = pdu[i];
        }
        else
        {
            Mpdu[i] = pdu[i];
        }
    }
    //length += 12;
    // add sec tag from location 12 to 27
    Mpdu[12]=0x88;
    Mpdu[13]=0x8e;
    Mpdu[14]=0x00;
    Mpdu[15]=0x00;
    Mpdu[16]=0x00;
    Mpdu[17]=0x00;
    Mpdu[18]=0x00;
    Mpdu[19]=0x00;
    Mpdu[20]=0x00;
    Mpdu[21]=0x00;
    Mpdu[22]=0x00;
    Mpdu[23]=0x00;
    Mpdu[24]=0x00;
    Mpdu[25]=0x00;
    Mpdu[26]=0x00;
    Mpdu[27]=0x00;
    // N.B : 4 bytes of CRC is EMPTY in Mpdu
    
    // w mehtag jobId w channelId
    Crypto_JobType macVerifyJob;

    macVerifyJob.jobState = CRYPTO_JOBSTATE_IDLE;
    // array 
    //uint32 dataLength = sizeof(data);
    //array bet3 icv
    //uint32 macLength = sizeof(mac);
    Crypto_VerifyResultType verifyResult;


    // Assign pointers to your data and MAC
    const uint8* dataPtr = &Mpdu;
    const uint8* macPtr = &Mpdu[MpduLength];// SUBTRACT 4 bytes for CRC NEGLECTION
    uint16 DataLen=MpduLength - 4;
    uint32 outputLength = 16;
    uint8 output[16] ;
    macVerifyJob.jobPrimitiveInputOutput.inputPtr = dataPtr;
    macVerifyJob.jobPrimitiveInputOutput.inputLength = DataLen;
    
    // macVerifyJob.jobPrimitiveInputOutput.secondaryInputPtr = macPtr;
    // macVerifyJob.jobPrimitiveInputOutput.secondaryInputLength = 16;

    macVerifyJob.jobPrimitiveInputOutput.outputPtr = output;
    macVerifyJob.jobPrimitiveInputOutput.outputLengthPtr = &outputLength;
     

    //macVerifyJob.jobPrimitiveInputOutput.verifyPtr = &verifyResult;
   // encrypt or decrypt or verify or macgenerate 
    macVerifyJob.jobPrimitiveInfo = &macGenerateJob ;
   // operation mode
    macVerifyJob.jobPrimitiveInputOutput.mode=CRYPTO_OPERATIONMODE_SINGLECALL;
Crypto_Init(&Crypto_PBConfig);
macVerifyJob.cryptoKeyId = 0; // Use your actual key ID
macVerifyJob.jobState = CRYPTO_JOBSTATE_ACTIVE;
 uint8* output1 = macVerifyJob.jobPrimitiveInputOutput.outputPtr;   

 for(uint16 i=DataLen;i<DataLen+16;i++){
    Mpdu[i]=output1[i-DataLen];
 }

 DataLen += 16; // added ICV
// crc storing 
for(uint16 i=0 ; i<4 ;i++)
{
    Mpdu[DataLen+i]=pdu[pduLength - 3 + i];
}
    printf("\nOutput:");
    for (int i = 0; i < *(macVerifyJob.jobPrimitiveInputOutput.outputLengthPtr); i++) {
        printf("%02x ", output1[i]);
    }


//     Std_ReturnType retVal=Csm_MacGenerate(
//     0,
//     CRYPTO_OPERATIONMODE_SINGLECALL ,
//     dataPtr,
//     DataLen,
//     (uint8*)macPtr,
//      16
//    );

}

// Std_ReturnType getSAK(Mka_SakKeyPtrType *SakKeyPtrStruct)
// {
//     // job(CSM) struct >> Khalifa
//     // call method from CSM to Generate SAK
//     uint64 sak = 0x12345678;
//     SakKeyPtrStruct->SakKeyPtr = sak;
//     return E_OK;
//     // if not true return E_NOT_OK;
// }
// void getKeyDerivaions(uint64 *CAK, uint64 *KEK, uint64 *ICK)
// {
//     // job(CSM) struct >> Khalifa
//     // call method from CSM to Generate kek , ick
// }
int main(void){

        uint8_t data[] = {
        0x37, 0x6f, 0x41, // Original data
        0x82, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    // data[0]=(*uint8)(mpdu & 0x0000000000ff)
    // data[1]=(*uint8)(mpdu & 0x00000000ff00)
    // data[2]=(*uint8)(mpdu & 0x000000ff0000)
    // data[3]=(*uint8)(mpdu & 0x0000000000ff)
    // data[4]=(*uint8)(mpdu & 0x0000000000ff)
    // data[5]=(*uint8)(mpdu & 0x0000000000ff)
    // data[6]=(*uint8)(mpdu & 0x0000000000ff)
    // data[0]=(*uint8)(mpdu & 0x0000000000ff)


 
    uint32 dataLength = sizeof(data);
    printf("%d",dataLength);
    // MAC array (16 bytes)
    uint8_t mac[] = {
        0xb8, 0xfb , 0x4b , 0x0f , 0x2a , 0xd0 , 0x25 , 0xbc , 0xe4 , 0x6b , 0x67 , 0x62 , 0x9f , 0x1b , 0xed , 0x9f 
    }; 
    // Your actual MAC value
    uint32 macLength = sizeof(mac);

    
      CheckICV(data,dataLength,mac);



}