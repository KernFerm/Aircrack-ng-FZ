/*
 * Aircrack-ng FZ bounded offline parser.
 * PCAP and IVS2 constants/structures are adapted from Aircrack-ng
 * include/aircrack-ng/support/pcap_local.h (GPL-2.0-or-later).
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    AcfFormatUnknown,
    AcfFormatPcap,
    AcfFormatPcapNg,
    AcfFormatIvs2,
} AcfFormat;

typedef enum {
    AcfStatusOk,
    AcfStatusCancelled,
    AcfStatusIo,
    AcfStatusMalformed,
    AcfStatusUnsupported,
} AcfStatus;

typedef struct {
    void* context;
    size_t (*read)(void* context, void* data, size_t size);
    bool (*seek)(void* context, uint32_t absolute_offset);
    uint64_t (*tell)(void* context);
    uint64_t (*size)(void* context);
} AcfReader;

typedef struct {
    AcfFormat format;
    uint32_t link_type;
    uint32_t packets;
    uint32_t management_frames;
    uint32_t control_frames;
    uint32_t data_frames;
    uint32_t protected_frames;
    uint32_t eapol_frames;
    uint32_t ivs2_records;
    uint32_t ivs2_wpa_records;
    uint64_t captured_bytes;
    char first_ssid[33];
    uint8_t first_bssid[6];
    bool has_bssid;
} AcfAnalysis;

AcfStatus acf_analyze(AcfReader* reader, volatile bool* cancel, AcfAnalysis* result);
const char* acf_status_name(AcfStatus status);
const char* acf_format_name(AcfFormat format);

