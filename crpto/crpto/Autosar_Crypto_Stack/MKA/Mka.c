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
// Std_ReturnType Mka_SetPaePermissiveMode(uint8 MkaPaeIdx, Mka_PermissiveModeType Mode)
// {
//     if (MkaPaeIdx >= MKA_MAX_PAE_INSTANCES)
//     {
//         if (Mka_Config.MKA_Instance.General.MkaDevErrorDetect == STD_ON)
//         {
//             Det_ReportError(MKA_MODULE_ID, MKA_INSTANCE_ID, Mka_SETENABLE_API_ID, MKA_E_INVALID_PARAM);
//         }
//         return E_NOT_OK;
//     }
//     Mka_Config.MKA_Instance.Paeinstance[MkaPaeIdx].PermisMode = Mode;
//     return E_OK;
// }

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
        // if (EthIf_StartPae(MkaPaeIdx))
        // {
        //     return E_OK;
        // }
        // else
        // {
        //     return E_NOT_OK;
        // }
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

// Method To check ICV of given (M/MK)PDU "Recieved from peer"
Std_ReturnType CheckICV(uint8 *Mpdu, uint32 length)
{
    // w mehtag jobId w channelId
    Crypto_JobType macVerifyJob;

    macVerifyJob.jobState = CRYPTO_JOBSTATE_IDLE;
    // array
    // uint32 dataLength = sizeof(data);
    // array bet3 icv
    // uint32 macLength = sizeof(mac);
    Crypto_VerifyResultType verifyResult;

    // Assign pointers to your data and MAC
    const uint8 *dataPtr = Mpdu;
    printf("\n MPDU \n");
    for (int i = 0; i < length - 20; i++)
    {
        printf("%02x ", dataPtr[i]);
    }
    printf("\n MAC \n");
    const uint8 *macPtr = &Mpdu[length - 20];
    for (int i = 0; i < 16; i++)
    {
        printf("%02x ", macPtr[i]);
    } //   &Mpdu[length];// hanshil el ICV w crc
    uint32 DataLen = length - 20; // hanshil el ICV w crc
    uint32 outputLength = 16;
    uint8 output[16];
    macVerifyJob.jobPrimitiveInputOutput.inputPtr = dataPtr;
    macVerifyJob.jobPrimitiveInputOutput.inputLength = DataLen;

    macVerifyJob.jobPrimitiveInputOutput.secondaryInputPtr = macPtr;
    macVerifyJob.jobPrimitiveInputOutput.secondaryInputLength = 16;

    macVerifyJob.jobPrimitiveInputOutput.outputPtr = output;
    macVerifyJob.jobPrimitiveInputOutput.outputLengthPtr = &outputLength;

    macVerifyJob.jobPrimitiveInputOutput.verifyPtr = &verifyResult;
    // encrypt or decrypt or verify or macgenerate
    macVerifyJob.jobPrimitiveInfo = &verifyJob;
    // operation mode
    macVerifyJob.jobPrimitiveInputOutput.mode = CRYPTO_OPERATIONMODE_SINGLECALL;
    Crypto_Init(&Crypto_PBConfig);
    macVerifyJob.cryptoKeyId = 0; // Use your actual key ID
    macVerifyJob.jobState = CRYPTO_JOBSTATE_ACTIVE;

    Crypto_ProcessJob(0, &macVerifyJob);
    // check if the ICV is correct
    uint8 *output1 = macVerifyJob.jobPrimitiveInputOutput.outputPtr;

    Std_ReturnType retVal = E_NOT_OK;
    if (*(macVerifyJob.jobPrimitiveInputOutput.verifyPtr) == 0x00)
    {
        printf("\nMAC verification succeeded - Message is authentic\n");
        retVal = E_OK;
    }
    else
    {
        printf("\nMAC verification failed - Potential tampering detected!\n");
    }
    printf("\nOutput: \n");
    for (int i = 0; i < *(macVerifyJob.jobPrimitiveInputOutput.outputLengthPtr); i++)
    {
        printf("%02x \n", output1[i]);
    }
    return retVal;
}

Std_ReturnType GenerateMac(uint8 *data, uint32 length, uint8 *mac)
{
    // w mehtag jobId w channelId
    Crypto_JobType macVerifyJob;

    macVerifyJob.jobState = CRYPTO_JOBSTATE_IDLE;
    // array
    // uint32 dataLength = sizeof(data);
    // array bet3 icv
    // uint32 macLength = sizeof(mac);
    Crypto_VerifyResultType verifyResult;

    // Assign pointers to your data and MAC


    const uint8 *dataPtr = data;
    printf("\n DATA : \n");
    for (int i = 0; i < length; i++)
    {
        printf("%02x ", dataPtr[i]);
    }
    printf("\n");


    //  printf("/n MAC");
    // const uint8* macPtr = mac;
    //         for (int i = 0; i < 16; i++) {
    //     printf("%02x ", macPtr[i]);
    // }                           //   &Mpdu[length];// hanshil el ICV w crc
    uint32 DataLen = length; // hanshil el ICV w crc
    uint32 outputLenght = 16;
    uint8 output[16];
    macVerifyJob.jobPrimitiveInputOutput.inputPtr = dataPtr;
    macVerifyJob.jobPrimitiveInputOutput.inputLength = DataLen;

    // macVerifyJob.jobPrimitiveInputOutput.secondaryInputPtr = macPtr;
    // macVerifyJob.jobPrimitiveInputOutput.secondaryInputLength = 16;

    macVerifyJob.jobPrimitiveInputOutput.outputPtr = output;
    macVerifyJob.jobPrimitiveInputOutput.outputLengthPtr = &outputLenght;

    macVerifyJob.jobPrimitiveInputOutput.verifyPtr = &verifyResult;
    // encrypt or decrypt or verify or macgenerate
    macVerifyJob.jobPrimitiveInfo = &macGenerateJob;
    // operation mode
    macVerifyJob.jobPrimitiveInputOutput.mode = CRYPTO_OPERATIONMODE_SINGLECALL;
    Crypto_Init(&Crypto_PBConfig);
    macVerifyJob.cryptoKeyId = 0; // Use your actual key ID
    macVerifyJob.jobState = CRYPTO_JOBSTATE_ACTIVE;

    Crypto_ProcessJob(0, &macVerifyJob);
    // check if the ICV is correct
    // mac = macVerifyJob.jobPrimitiveInputOutput.outputPtr;
    memcpy(mac, output, 16);

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
Std_ReturnType GenerateMACsec_Frame(uint8 *pdu, uint32 length,  uint8 *Mpdu)
{
     uint16 pduLength = length; // D + S + PayLoad + CRC
     uint16 payloadSize = length-((6*2)+4); //get payload length from pdu
     uint16 MpduCumLength = 0 ;  // cummilative MPdu size

     //add source and destination address from pdu to Mpdu
     for(uint16 i = 0 ; i<=11; i++) 
     {
        Mpdu[i] = pdu[i];
     }

     MpduCumLength += 12;

    //add sec tag from location 12 to 27
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
    Mpdu[27]=0xff;

    MpduCumLength += 16;
    
    //add payload stored in pdu in Mpdu
    uint16 j = 12;
    for(uint16 i = MpduCumLength;i<(payloadSize+MpduCumLength);i++){
        Mpdu[i] = pdu[j];
        j++;
    }

    MpduCumLength += payloadSize;

    //generate ICV 
    uint8* ICV;
    Std_ReturnType retval = GenerateMac(Mpdu,MpduCumLength,ICV);

    //add ICV to Mpdu
    uint8 k = 0;
    for(uint16 i = MpduCumLength;i<(MpduCumLength+16);i++){
        Mpdu[i]=ICV[k];
        k++;
    }

    MpduCumLength += 16;

    //add CRC
    uint16 h = length-4;
    for(uint16 i = MpduCumLength;i<(MpduCumLength+4);i++){
        Mpdu[i]=pdu[h];
        h++;
    }

    return retval;
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
int main(void)
{
    Std_ReturnType retval;
    /*   //////////////////////////////////Karim Debuging//////////////////////////////////
    uint8 data[] = {
        0x37, 0x6f, 0x41, // Original data payload + ICV 
        0x82, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xf2, 0xf9, 0x1f, 0xdb, 0x01, 0x8a, 0x9a, 0x53, 0x98, 0x30, 0x58, 0xf0, 0x00, 0xa4, 0xae, 0xb0,
        0x12, 0x34, 0x56, 0x78};

    uint8 pdu[] = {
        0x37, 0x6f, 0x41, // Original data payload + CRC 
        0x82, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};    

    uint32 dataLength = sizeof(pdu);
    //printf("%d \n", dataLength);
    // MAC array (16 bytes)
    //uint8 Mpdu[20+32];
    uint8*mac;

    */   //////////////////////////////////////////////////////////////////////////////////

    // uint8 mac[] = {
    //     0xf2, 0xf9, 0x1f, 0xdb, 0x01, 0x8a, 0x9a, 0x53, 0x98, 0x30, 0x58, 0xf0, 0x00, 0xa4, 0xae, 0xb0};

       
    // retval=GenerateMACsec_Frame(pdu,dataLength,Mpdu); 
    // if(retval == E_OK){
    // printf("Mac is correct\n");
    // }
    // else{
    //     printf("Mac is incorrect\n");
    // }   

    

    /*  ////////////////////////////////////////Philo Debugging 1///////////////////////////////////
    uint8 pdu[] = {
        0x37, 0x6f, 0x41,0x82, 0x00, 0x00, //source address
        0x37, 0x6f, 0x41,0x82, 0x00, 0x00, //destination address
        0x11, 0x22, 0x33,0x44, 0x55, 0x66, //payload
        0xE6, 0xE1, 0xF4, 0xA3             //CRC
    };

    uint8* Mpdu;
    uint16 MpduSize = sizeof(pdu)+16*2; // length of Pdu + 16 byte of secTag + 16 byte of ICV

    
    retval=GenerateMACsec_Frame(pdu,sizeof(pdu),Mpdu);
    

    printf("\n Output:\n");
    for (int i = 0; i < MpduSize; i++)
    {
        printf("%02x ", Mpdu[i]);
    }
    */   ////////////////////////////////////////////////////////////////////////////////////////

    
    /////////////////////////////////////////philo Debugging 2////////////////////////////////////
    //lets test by a dummy data as if it is an Mpdu from its start till end of payload 
    uint8 dummyData[]={
        0x37, 0x6f, 0x41, 0x82, 0x00, 0x00, //source address
        0x37, 0x6f, 0x41, 0x82, 0x00, 0x00, //destination address
        //0x88, 0x8e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0xff, //secTag
        0x11, 0x22, 0x33, 0x44, 0x55//, 0x66  //payload
    }; //34 value test

    uint8* mac;

    retval=GenerateMac(dummyData,sizeof(dummyData),mac);

    printf("\n Output:\n");
    for (int i = 0; i < 16; i++)
    {
        printf("%02x ", mac[i]);
    }

     if(retval == E_OK){
    printf("\nMac is correct\n");
     }
    else{
    printf("\nMac is incorrect\n");
     }

    /////////////////////////////////////////////////////////////////////////////////////////////////
    // uint8*mac1=mac;

    // Your actual MAC value
    // uint32 macLength = sizeof(mac);
    // retval = CheckICV(data, dataLength);// kan mafroud maknha data 
    // if (retval == E_OK)
    // {
    //     printf("ICV is correct\n");
    // }
    // else
    // {
    //     printf("ICV is incorrect\n");
    // }
    // printf("\n before \n");
    // for (int i = 0; i < 16; i++) {
    // printf("%02x ", mac1[i]);
    // }
    //     retval= GenerateMac(data, dataLength, mac1);

    //     printf("\n after \n");
    //     for (int i = 0; i < 16; i++) {
    //     printf("%02x ", mac1[i]);
    // }

    // retval=CheckICV(data,dataLength,mac1);
    // if(retval == E_OK){
    // printf("ICV is correct\n");
    // }
    // else{
    //     printf("ICV is incorrect\n");
    // }

    while (1);
    return 0;
}
