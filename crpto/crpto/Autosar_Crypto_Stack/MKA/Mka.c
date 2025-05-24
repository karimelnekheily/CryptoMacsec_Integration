#include "Mka.h"
#include "EthernetIf.h"
// #include "Csm.h"

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

    // Configure EthIf for MKA messages
    for (uint8 i = 0; i < MKA_MAX_PAE_INSTANCES; i++)
    {
        EthIf_SetControllerMode(Mka_Config.MKA_Instance.Paeinstance[i].MkaPaeIdx, ETH_MODE_ACTIVE);
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

    /* Copy CKN to internal state(simplified; actual storage depends on implementation) */

    Mka_Config.MKA_Instance.Paeinstance[MkaPaeIdx].KayInstance.Participants[MkaPaeIdx].MkaCryptoCknCakKeyRef = Ckn; /* Placeholder; actual key reference needed */

    // under discussion
    // if (WriteToNvm(MkaPaeIdx, Enable) != E_OK)
    // {
    //     retVal = E_NOT_OK;
    //     /* Optionally report to DET if needed */
    // }

    return retVal;
}

// done but not sure
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
Std_ReturnType Mka_LinkStateChange(uint8 MkaPaeIdx, EthTrcv_LinkStateType TransceiverLinkState)
{
    // Validate initialization
    if (Mka_Config == NULL)
    {
        Det_ReportError(MKA_MODULE_ID, MKA_INSTANCE_ID, Mka_LINKSTATECHANGE_API_ID, MKA_E_NOT_INITIALIZED);
        return E_NOT_OK;
    }
    // Validate MkaPaeIdx
    if (MkaPaeIdx >= MKA_MAX_PAE_INSTANCES)
    {
        if ((Mka_Config.MKA_Instance.General.MkaDevErrorDetect == STD_ON))
        {
            Det_ReportError(MKA_MODULE_ID, MKA_INSTANCE_ID, Mka_LINKSTATECHANGE_API_ID, MKA_E_INVALID_PARAM);
        }
        return E_NOT_OK;
    }
    // Validate TransceiverLinkState
    if (Mka_Config.MKA_Instance.General.MkaDevErrorDetect == STD_ON)
    {
        if (TransceiverLinkState != ETHTRCV_LINK_STATE_ACTIVE && TransceiverLinkState != ETHTRCV_LINK_STATE_DOWN)
        {
            Det_ReportError(MKA_MODULE_ID, MKA_INSTANCE_ID, Mka_LINKSTATECHANGE_API_ID, MKA_E_INVALID_PARAM);
            return E_NOT_OK;
        }
    }

    // Store the current state to check if it changes
    Mka_MkaStatus previousState = Mka_PaeStatus[MkaPaeIdx].ConnectionStatus;

    // Update state based on link state
    if (TransceiverLinkState == ETHTRCV_LINK_STATE_ACTIVE)
    {
        Mka_PaeStatus[MkaPaeIdx].ConnectionStatus = MKA_STATUS_WAITING_PEER;
    }
    else
    {
        Mka_PaeStatus[MkaPaeIdx].ConnectionStatus = MKA_STATUS_WAITING_PEER_LINK;
        // Reset peer-related state when link goes down
        Mka_PaeStatus[MkaPaeIdx].PeerSci = 0;
        for (uint8 j = 0; j < 32; j++)
        {
            Mka_PaeStatus[MkaPaeIdx].CknInUse[j] = 0;
        }
    }

    // Return E_OK if the state changed (indicating the MKA sequence can proceed), E_NOT_OK otherwise
    if (previousState != Mka_PaeStatus[MkaPaeIdx].ConnectionStatus)
    {
        return E_OK;
    }
    else
    {
        return E_NOT_OK;
    }
}

////////////////////////////CALL BACKS////////////////////////////////////////////////
/******************************
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
void Mka_RxIndication(PduIdType RxPduId, const PduInfoType *PduInfoPtr)
{
    uint8 i;
    boolean validPdu = FALSE;
    uint8 targetMkaPaeIdx = 0xFF;

    /* Check if the MKA module is initialized */
    if (!Mka_IsInitialized)
    {
        if (Mka_Config.MKA_Instance.General.MkaDevErrorDetect == STD_ON)
        {
            Det_ReportError(MKA_MODULE_ID, MKA_INSTANCE_ID, Mka_RX_INDICATION_API_ID, MKA_E_NOT_INITIALIZED);
        }
        return;
    }

    /* Validate parameters */
    if (PduInfoPtr == NULL)
    {
        if (Mka_Config.MKA_Instance.General.MkaDevErrorDetect == STD_ON)
        {
            Det_ReportError(MKA_MODULE_ID, MKA_INSTANCE_ID, Mka_RX_INDICATION_API_ID, MKA_E_INVALID_PARAM);
        }
        return;
    }

    /*EAPOL-MKA frame:   */
    if (PduInfoPtr->SduLength < 4)
    {
        /* Too short to be a valid EAPOL frame */
        return;
    }

    /* Find the PAE instance matching the RxPduId */
    for (i = 0; i < MKA_MAX_PAE_INSTANCES; i++)
    {
        if (Mka_Config.MKA_Instance.Paeinstance[i].RxPdu.MkaRxPduId == RxPduId)
        {
            validPdu = TRUE;
            targetMkaPaeIdx = i;
            break;
        }
    }

    if (!validPdu)
    {
        /* No matching PAE instance for this PduId */
        if (Mka_Config.MKA_Instance.General.MkaDevErrorDetect == STD_ON)
        {
            Det_ReportError(MKA_MODULE_ID, MKA_INSTANCE_ID, Mka_RX_INDICATION_API_ID, MKA_E_INVALID_PARAM);
        }
        return;
    }

    /* Check if this PAE instance is active */
    if (!Mka_Config.MKA_Instance.Paeinstance[targetMkaPaeIdx].KayInstance.Participants[targetMkaPaeIdx].MkaParticipantActivate)
    {
        /* PAE instance is not active, ignore the PDU */
        return;
    }

    /* Verify this is an EAPOL-MKA frame (EAPOL type 5) */
    if (PduInfoPtr->SduDataPtr[1] != 5) /* Not MKA type */
    {
        /* Not an MKA packet, ignore */
        return;
    }

    /* Process the received EAPOL-MKA frame */

    if (PduInfoPtr->SduLength >= 4) /* Minimum size of EAPOL header */
    {
        /* Verify this is an EAPOL-MKA frame (EAPOL type 5) */
        if (PduInfoPtr->SduDataPtr[1] == 5) /* MKA type */
        {
            /* Process the MKA PDU */
            /* This would typically include:
             * 1. Validate the ICV (Integrity Check Value)
             * 2. Extract the Basic Parameter Set
             * 3. Update peer information
             * 4. Process key server election if needed
             * 5. Handle SAK distribution if needed
             */
            if (CheckICV(*(MACsec_Frame *)PduInfoPtr->SduDataPtr) == E_OK)
            {
                /* ICV validation successful, update PAE status */
                Mka_PaeStatus[targetMkaPaeIdx].ConnectionStatus = MKA_STATUS_IN_PROGRESS;

                /* Update peer SCI from the received PDU (simplified for this implementation) */
                /* In a real implementation, you would extract the SCI from the appropriate field */
                Mka_PaeStatus[targetMkaPaeIdx].PeerSci = 0x1234567890ABCDEF; /* Example value */

                /* Additional MKA protocol processing would happen here */
            }
            else
            {
                /* ICV validation failed, potential security breach */
                Mka_PaeStatus[targetMkaPaeIdx].ConnectionStatus = MKA_STATUS_AUTH_FAIL_UNKNOWN_PEER;

                if (Mka_Config.MKA_Instance.General.MkaEnableSecurityEventReporting == TRUE)
                {
                    /* Report security event if enabled */
                    /* This would typically call a security event reporting function */
                }
            }
        }
    }
}

void Mka_TxConfirmation(PduIdType TxPduId, Std_ReturnType Result)
{
    uint8 i;
    boolean validPdu = FALSE;
    uint8 targetMkaPaeIdx = 0xFF;

    /* Check if the MKA module is initialized */
    if (!Mka_IsInitialized)
    {
        if (Mka_Config.MKA_Instance.General.MkaDevErrorDetect == STD_ON)
        {
            Det_ReportError(MKA_MODULE_ID, MKA_INSTANCE_ID, 0x21, MKA_E_NOT_INITIALIZED);
        }
        return;
    }

    /* Find the PAE instance matching the TxPduId */
    for (i = 0; i < MKA_MAX_PAE_INSTANCES; i++)
    {
        if (Mka_Config.MKA_Instance.Paeinstance[i].TxPdu.MkaTxPduId == TxPduId)
        {
            validPdu = TRUE;
            targetMkaPaeIdx = i;
            break;
        }
    }

    if (!validPdu)
    {
        /* No matching PAE instance for this PduId */
        if (Mka_Config.MKA_Instance.General.MkaDevErrorDetect == STD_ON)
        {
            Det_ReportError(MKA_MODULE_ID, MKA_INSTANCE_ID, 0x21, MKA_E_INVALID_PARAM);
        }
        return;
    }

    /* Process the transmission confirmation result */
    if (Result == E_OK)
    {
        /* Transmission successful */
        /* Update any statistics or state if needed */
        Mka_Stats.StatsTxPhy.OutPkts_Untagged++;
    }
    else
    {
        /* Transmission failed */
        /* Handle retransmission or report error */
        if (Mka_Config.MKA_Instance.General.MkaEnableSecurityEventReporting == TRUE)
        {
            /* Report security event if enabled */
            /* This would typically call a security event reporting function */
        }
    }
}

void Mka_MacSecUpdateSecYNotification(uint8 MkaPaeIdx, Std_ReturnType Result)
{
    /* Check if the MKA module is initialized */
    if (!Mka_IsInitialized)
    {
        if (Mka_Config.MKA_Instance.General.MkaDevErrorDetect == STD_ON)
        {
            Det_ReportError(MKA_MODULE_ID, MKA_INSTANCE_ID, 0x22, MKA_E_NOT_INITIALIZED);
        }
        return;
    }

    /* Check if MkaPaeIdx is valid */
    if (MkaPaeIdx >= MKA_MAX_PAE_INSTANCES)
    {
        if (Mka_Config.MKA_Instance.General.MkaDevErrorDetect == STD_ON)
        {
            Det_ReportError(MKA_MODULE_ID, MKA_INSTANCE_ID, 0x22, MKA_E_INVALID_PARAM);
        }
        return;
    }

    /* Process the SecY update result */
    if (Result == E_OK)
    {
        /* SecY update successful */
        /* Update MKA state to reflect the successful SecY update */
        if (Mka_PaeStatus[MkaPaeIdx].ConnectionStatus == MKA_STATUS_IN_PROGRESS)
        {
            Mka_PaeStatus[MkaPaeIdx].ConnectionStatus = MKA_STATUS_MACSEC_RUNNING;
        }
    }
    else
    {
        /* SecY update failed */
        /* Handle error case */
        if (Mka_Config.MKA_Instance.General.MkaEnableSecurityEventReporting == TRUE)
        {
            /* Report security event if enabled */
            /* This would typically call a security event reporting function */
        }
    }
}

void Mka_MacSecAddTxSaNotification(uint8 MkaPaeIdx, Std_ReturnType Result)
{
    /* Check if the MKA module is initialized */
    if (!Mka_IsInitialized)
    {
        if (Mka_Config.MKA_Instance.General.MkaDevErrorDetect == STD_ON)
        {
            Det_ReportError(MKA_MODULE_ID, MKA_INSTANCE_ID, Mka_MACSEC_ADD_TX_SA_NOTIFICATION_API_ID, MKA_E_NOT_INITIALIZED);
        }
        return;
    }

    /* Check if MkaPaeIdx is valid */
    if (MkaPaeIdx >= MKA_MAX_PAE_INSTANCES)
    {
        if (Mka_Config.MKA_Instance.General.MkaDevErrorDetect == STD_ON)
        {
            Det_ReportError(MKA_MODULE_ID, MKA_INSTANCE_ID, Mka_MACSEC_ADD_TX_SA_NOTIFICATION_API_ID, MKA_E_INVALID_PARAM);
        }
        return;
    }

    /* Process the result of adding a transmit secure association */
    if (Result == E_OK)
    {
        /* TX SA add successful */
        /* Update any state or statistics if needed */
        /* For example, we might want to trigger a state transition in the MKA state machine */
    }
    else
    {
        /* TX SA add failed */
        /* Handle error case */
        if (Mka_Config.MKA_Instance.General.MkaEnableSecurityEventReporting == TRUE)
        {
            /* Report security event if enabled */
            /* This would typically call a security event reporting function */
        }
    }
}

void Mka_MacSecAddRxSaNotification(uint8 MkaPaeIdx, Std_ReturnType Result)
{
    /* Check if the MKA module is initialized */
    if (!Mka_IsInitialized)
    {
        if (Mka_Config.MKA_Instance.General.MkaDevErrorDetect == STD_ON)
        {
            Det_ReportError(MKA_MODULE_ID, MKA_INSTANCE_ID, Mka_MACSEC_ADD_RX_SA_NOTIFICATION_API_ID, MKA_E_NOT_INITIALIZED);
        }
        return;
    }

    /* Check if MkaPaeIdx is valid */
    if (MkaPaeIdx >= MKA_MAX_PAE_INSTANCES)
    {
        if (Mka_Config.MKA_Instance.General.MkaDevErrorDetect == STD_ON)
        {
            Det_ReportError(MKA_MODULE_ID, MKA_INSTANCE_ID, Mka_MACSEC_ADD_RX_SA_NOTIFICATION_API_ID, MKA_E_INVALID_PARAM);
        }
        return;
    }

    /* Process the result of adding a receive secure association */
    if (Result == E_OK)
    {
        /* RX SA add successful */
        /* Update any state or statistics if needed */
        /* For example, we might want to update reception statistics */
    }
    else
    {
        /* RX SA add failed */
        /* Handle error case */
        if (Mka_Config.MKA_Instance.General.MkaEnableSecurityEventReporting == TRUE)
        {
            /* Report security event if enabled */
            /* This would typically call a security event reporting function */
        }
    }
}

//////////////////////SCHEDULED FUNCTIONS/////////////////////////////////////////////
void Mka_MainFunction(void)
{
    if (Mka_IsInitialized)
    {
        // Cyclic job: Check timers, refresh keys, update states.
    }
}

///////////////////////////customized Methods for SECY///////////////////////////////

// Method To check ICV of given (M/MK)PDU "Recieved from peer"
Std_ReturnType CheckICV(MACsec_Frame Mpdu)
{
    // job(CSM) struct >> Khalifa
    //  check ICV IF True return E_OK else  return E_NOT_OK
    return E_OK;
}

// Method to generate ICV for pdu frame "Gonna be transimted to peer"
// also add sec tag
MACsec_Frame GenerateMACsec_Frame(PDU_Frame PD_Frame)
{
    // job(CSM) struct >> Khalifa
    //  generate ICV
    MACsec_Frame Mpdu = NULL;
    Mpdu.Dmac = PD_Frame.Dmac;
    Mpdu.Smac = PD_Frame.Smac;
    // ADD sec tag
    Mpdu.Payload = PD_Frame.Payload;
    // add ICV 
    return Mpdu;
}

Std_ReturnType getSAK(Mka_SakKeyPtrType *SakKeyPtrStruct)
{
    // job(CSM) struct >> Khalifa
    // call method from CSM to Generate SAK
    uint64 sak = 0x12345678;
    SakKeyPtrStruct->SakKeyPtr = sak;
    return E_OK;
    // if not true return E_NOT_OK;
}
void getKeyDerivaions(uint64 *CAK, uint64 *KEK, uint64 *ICK)
{
    // job(CSM) struct >> Khalifa
    // call method from CSM to Generate kek , ick
}
