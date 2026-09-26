/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef struct AcfExternal AcfExternal;

typedef struct {
    bool active;
    bool connected;
    bool capturing;
    uint32_t protocol_version;
    uint32_t channel;
    uint32_t last_update;
    uint32_t serial_errors;
    uint64_t packets;
    uint64_t bytes;
    uint64_t management;
    uint64_t data;
    uint64_t control;
    uint64_t eapol;
    uint64_t dropped;
    char state[16];
    char backend_version[24];
    char aircrack_version[32];
    char interface_name[24];
    char capture_path[80];
    char error[64];
} AcfExternalSnapshot;

AcfExternal* acf_external_alloc(void);
void acf_external_free(AcfExternal* external);
bool acf_external_start(AcfExternal* external, uint32_t baudrate);
void acf_external_stop(AcfExternal* external);
bool acf_external_capture_start(AcfExternal* external, uint32_t channel);
bool acf_external_capture_stop(AcfExternal* external);
void acf_external_snapshot(AcfExternal* external, AcfExternalSnapshot* snapshot);

