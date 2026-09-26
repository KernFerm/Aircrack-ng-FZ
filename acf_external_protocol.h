/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ACF_EXTERNAL_PROTOCOL_VERSION 1U
#define ACF_EXTERNAL_LINE_MAX 192U

typedef enum {
    AcfExternalMessageNone,
    AcfExternalMessageInfo,
    AcfExternalMessageStatus,
    AcfExternalMessageError,
} AcfExternalMessageType;

typedef struct {
    AcfExternalMessageType type;
    uint32_t protocol_version;
    char backend_version[24];
    char aircrack_version[32];
    char interface_name[24];
    char capture_path[80];
    char state[16];
    uint32_t channel;
    uint64_t packets;
    uint64_t bytes;
    uint64_t management;
    uint64_t data;
    uint64_t control;
    uint64_t eapol;
    uint64_t dropped;
    char error[64];
} AcfExternalMessage;

typedef struct {
    char line[ACF_EXTERNAL_LINE_MAX];
    size_t length;
    bool overflow;
} AcfExternalDecoder;

typedef void (*AcfExternalMessageCallback)(const AcfExternalMessage* message, void* context);

void acf_external_decoder_reset(AcfExternalDecoder* decoder);
void acf_external_decoder_feed(
    AcfExternalDecoder* decoder,
    const uint8_t* data,
    size_t length,
    AcfExternalMessageCallback callback,
    void* context);
bool acf_external_parse_line(const char* line, AcfExternalMessage* message);

