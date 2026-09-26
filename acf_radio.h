/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    AcfRadioNone,
    AcfRadioSubGhz,
    AcfRadioNfc,
    AcfRadioLfRfid,
} AcfRadioMode;

typedef struct AcfRadio AcfRadio;

#define ACF_RADIO_HISTORY_SIZE 64

typedef struct {
    AcfRadioMode mode;
    bool running;
    bool log_error;
    uint32_t frequency;
    uint32_t events;
    uint32_t last_timestamp;
    float rssi;
    int8_t history[ACF_RADIO_HISTORY_SIZE];
    uint8_t history_count;
    char protocol[32];
    char identifier[65];
    char error[48];
} AcfRadioSnapshot;

AcfRadio* acf_radio_alloc(void);
void acf_radio_free(AcfRadio* radio);
bool acf_radio_start(AcfRadio* radio, AcfRadioMode mode, uint32_t frequency);
void acf_radio_stop(AcfRadio* radio);
void acf_radio_tick(AcfRadio* radio);
void acf_radio_snapshot(const AcfRadio* radio, AcfRadioSnapshot* snapshot);
void acf_radio_set_log_error(AcfRadio* radio, bool error);
