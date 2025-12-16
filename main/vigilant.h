#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    NW_MODE_AP = 0,
    NW_MODE_STA,
    NW_MODE_APSTA
} NW_MODE;

esp_err_t vigilant_init(NW_MODE _NETWORK_MODE);

#ifdef __cplusplus
}
#endif
