/*
 * CryIf.h
 *
 *  Created on: Apr 8, 2025
 *      Author: Ahmed Gamal
 */

#ifndef CRYIF_H_
#define CRYIF_H_

/*==================[Includes]===============================================*/
#include "Std_Types.h"
#include "Crypto_GeneralTypes.h"
#include "Rte_Csm_Type.h"

/*==================[Type Definitions]=======================================*/

// CryIf_Types.h or CryIf_Cfg.h
typedef struct {
    uint32 channelId;
    uint8 backendId;     // Which backend (e.g., driver or service)
    boolean isAsync;     // Should job be queued or processed directly
} CryIf_ConfigType;

// Dummy back end IDs
#define CRYIF_BACKEND_CSM     0
#define CRYIF_BACKEND_DRIVER  1

#define CRYIF_NUM_CHANNELS 2

// Static channel config array (just an example)
static const CryIf_ConfigType CryIf_ChannelConfig[CRYIF_NUM_CHANNELS] = {
    { .channelId = 0, .backendId = CRYIF_BACKEND_CSM, .isAsync = FALSE },
    { .channelId = 1, .backendId = CRYIF_BACKEND_DRIVER, .isAsync = TRUE },
};


#endif /* CRYIF_H_ */
