/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "acf_radio.h"

#include <furi.h>
#include <furi_hal.h>
#include <nfc/nfc.h>
#include <nfc/nfc_device.h>
#include <nfc/nfc_scanner.h>
#include <lfrfid/lfrfid_worker.h>
#include <lfrfid/protocols/lfrfid_protocols.h>
#include <subghz/devices/devices.h>
#include <subghz/devices/cc1101_int/cc1101_int_interconnect.h>
#include <toolbox/protocols/protocol_dict.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct AcfRadio {
    AcfRadioMode mode;
    bool running;
    bool log_error;
    bool subghz_active;
    bool charge_suppressed;
    bool signal_active;
    const SubGhzDevice* subghz;
    Nfc* nfc;
    NfcScanner* scanner;
    ProtocolDict* lf_dict;
    LFRFIDWorker* lf_worker;
    FuriMutex* data_mutex;
    uint32_t frequency;
    uint32_t events;
    uint32_t last_timestamp;
    float rssi;
    int8_t history[ACF_RADIO_HISTORY_SIZE];
    uint8_t history_count;
    char protocol[32];
    char identifier[65];
    char error[48];
};

static void acf_set_error(AcfRadio* radio, const char* text) {
    furi_mutex_acquire(radio->data_mutex, FuriWaitForever);
    snprintf(radio->error, sizeof(radio->error), "%s", text);
    furi_mutex_release(radio->data_mutex);
}

static void acf_nfc_detected(NfcScannerEvent event, void* context) {
    AcfRadio* radio = context;
    if(event.type == NfcScannerEventTypeDetected && event.data.protocol_num) {
        NfcProtocol protocol = event.data.protocols[event.data.protocol_num - 1];
        furi_mutex_acquire(radio->data_mutex, FuriWaitForever);
        snprintf(
            radio->protocol,
            sizeof(radio->protocol),
            "%s",
            nfc_device_get_protocol_name(protocol));
        radio->events++;
        radio->last_timestamp = furi_hal_rtc_get_timestamp();
        furi_mutex_release(radio->data_mutex);
    }
}

static void acf_lf_detected(
    LFRFIDWorkerReadResult result,
    ProtocolId protocol,
    void* context) {
    AcfRadio* radio = context;
    if(result != LFRFIDWorkerReadDone || protocol < 0 || protocol >= LFRFIDProtocolMax) return;
    furi_mutex_acquire(radio->data_mutex, FuriWaitForever);
    snprintf(
        radio->protocol,
        sizeof(radio->protocol),
        "%s",
        protocol_dict_get_name(radio->lf_dict, (size_t)protocol));
    size_t size = protocol_dict_get_data_size(radio->lf_dict, (size_t)protocol);
    uint8_t data[32];
    if(size > sizeof(data)) size = sizeof(data);
    protocol_dict_get_data(radio->lf_dict, (size_t)protocol, data, size);
    size_t used = 0;
    for(size_t i = 0; i < size && used + 2 < sizeof(radio->identifier); i++) {
        used += snprintf(radio->identifier + used, sizeof(radio->identifier) - used, "%02X", data[i]);
    }
    radio->events++;
    radio->last_timestamp = furi_hal_rtc_get_timestamp();
    furi_mutex_release(radio->data_mutex);
}

AcfRadio* acf_radio_alloc(void) {
    AcfRadio* radio = calloc(1, sizeof(AcfRadio));
    if(radio) {
        radio->data_mutex = furi_mutex_alloc(FuriMutexTypeNormal);
        if(!radio->data_mutex) {
            free(radio);
            radio = NULL;
        }
    }
    return radio;
}

void acf_radio_stop(AcfRadio* radio) {
    if(!radio) return;
    furi_mutex_acquire(radio->data_mutex, FuriWaitForever);
    radio->running = false;
    furi_mutex_release(radio->data_mutex);
    if(radio->mode == AcfRadioSubGhz && radio->subghz) {
        if(radio->subghz_active) {
            subghz_devices_idle(radio->subghz);
            subghz_devices_sleep(radio->subghz);
            radio->subghz_active = false;
        }
        if(radio->charge_suppressed) {
            furi_hal_power_suppress_charge_exit();
            radio->charge_suppressed = false;
        }
        subghz_devices_deinit();
        radio->subghz = NULL;
    } else if(radio->mode == AcfRadioNfc) {
        if(radio->scanner) {
            nfc_scanner_stop(radio->scanner);
            nfc_scanner_free(radio->scanner);
            radio->scanner = NULL;
        }
        if(radio->nfc) {
            nfc_free(radio->nfc);
            radio->nfc = NULL;
        }
    } else if(radio->mode == AcfRadioLfRfid) {
        if(radio->lf_worker) {
            lfrfid_worker_stop(radio->lf_worker);
            lfrfid_worker_stop_thread(radio->lf_worker);
            lfrfid_worker_free(radio->lf_worker);
            radio->lf_worker = NULL;
        }
        if(radio->lf_dict) {
            protocol_dict_free(radio->lf_dict);
            radio->lf_dict = NULL;
        }
    }
    furi_mutex_acquire(radio->data_mutex, FuriWaitForever);
    radio->mode = AcfRadioNone;
    furi_mutex_release(radio->data_mutex);
}

void acf_radio_free(AcfRadio* radio) {
    if(!radio) return;
    acf_radio_stop(radio);
    furi_mutex_free(radio->data_mutex);
    free(radio);
}

bool acf_radio_start(AcfRadio* radio, AcfRadioMode mode, uint32_t frequency) {
    if(!radio || mode == AcfRadioNone) return false;
    acf_radio_stop(radio);
    furi_mutex_acquire(radio->data_mutex, FuriWaitForever);
    memset(radio->history, -127, sizeof(radio->history));
    radio->history_count = 0;
    radio->rssi = -127.0f;
    radio->signal_active = false;
    radio->events = 0;
    radio->last_timestamp = 0;
    radio->protocol[0] = '\0';
    radio->identifier[0] = '\0';
    radio->error[0] = '\0';
    radio->log_error = false;
    radio->mode = mode;
    furi_mutex_release(radio->data_mutex);

    if(mode == AcfRadioSubGhz) {
        subghz_devices_init();
        radio->subghz = subghz_devices_get_by_name(SUBGHZ_DEVICE_CC1101_INT_NAME);
        if(!radio->subghz || !subghz_devices_is_connect(radio->subghz)) {
            acf_set_error(radio, "Sub-GHz radio unavailable");
            acf_radio_stop(radio);
            furi_mutex_acquire(radio->data_mutex, FuriWaitForever);
            radio->mode = mode;
            furi_mutex_release(radio->data_mutex);
            return false;
        }
        radio->subghz_active = true;
        if(!subghz_devices_is_frequency_valid(radio->subghz, frequency)) {
            acf_set_error(radio, "Unsupported frequency");
            acf_radio_stop(radio);
            furi_mutex_acquire(radio->data_mutex, FuriWaitForever);
            radio->mode = mode;
            furi_mutex_release(radio->data_mutex);
            return false;
        }
        subghz_devices_reset(radio->subghz);
        subghz_devices_load_preset(radio->subghz, FuriHalSubGhzPresetOok650Async, NULL);
        uint32_t actual_frequency = subghz_devices_set_frequency(radio->subghz, frequency);
        subghz_devices_flush_rx(radio->subghz);
        furi_hal_power_suppress_charge_enter();
        radio->charge_suppressed = true;
        subghz_devices_set_rx(radio->subghz);
        furi_mutex_acquire(radio->data_mutex, FuriWaitForever);
        radio->frequency = actual_frequency;
        snprintf(radio->protocol, sizeof(radio->protocol), "RSSI activity");
        furi_mutex_release(radio->data_mutex);
    } else if(mode == AcfRadioNfc) {
        furi_mutex_acquire(radio->data_mutex, FuriWaitForever);
        radio->frequency = 13560000;
        furi_mutex_release(radio->data_mutex);
        radio->nfc = nfc_alloc();
        if(!radio->nfc) {
            acf_set_error(radio, "NFC unavailable");
            acf_radio_stop(radio);
            furi_mutex_acquire(radio->data_mutex, FuriWaitForever);
            radio->mode = mode;
            furi_mutex_release(radio->data_mutex);
            return false;
        }
        radio->scanner = nfc_scanner_alloc(radio->nfc);
        if(!radio->scanner) {
            acf_set_error(radio, "NFC scanner allocation failed");
            acf_radio_stop(radio);
            furi_mutex_acquire(radio->data_mutex, FuriWaitForever);
            radio->mode = mode;
            furi_mutex_release(radio->data_mutex);
            return false;
        }
        furi_mutex_acquire(radio->data_mutex, FuriWaitForever);
        snprintf(radio->protocol, sizeof(radio->protocol), "Scanning");
        furi_mutex_release(radio->data_mutex);
        nfc_scanner_start(radio->scanner, acf_nfc_detected, radio);
    } else if(mode == AcfRadioLfRfid) {
        furi_mutex_acquire(radio->data_mutex, FuriWaitForever);
        radio->frequency = 125000;
        furi_mutex_release(radio->data_mutex);
        radio->lf_dict = protocol_dict_alloc(lfrfid_protocols, LFRFIDProtocolMax);
        if(!radio->lf_dict) {
            acf_set_error(radio, "LF decoder allocation failed");
            acf_radio_stop(radio);
            furi_mutex_acquire(radio->data_mutex, FuriWaitForever);
            radio->mode = mode;
            furi_mutex_release(radio->data_mutex);
            return false;
        }
        radio->lf_worker = lfrfid_worker_alloc(radio->lf_dict);
        if(!radio->lf_worker) {
            acf_set_error(radio, "LF radio unavailable");
            acf_radio_stop(radio);
            furi_mutex_acquire(radio->data_mutex, FuriWaitForever);
            radio->mode = mode;
            furi_mutex_release(radio->data_mutex);
            return false;
        }
        furi_mutex_acquire(radio->data_mutex, FuriWaitForever);
        snprintf(radio->protocol, sizeof(radio->protocol), "Scanning");
        furi_mutex_release(radio->data_mutex);
        lfrfid_worker_start_thread(radio->lf_worker);
        lfrfid_worker_read_start(
            radio->lf_worker, LFRFIDWorkerReadTypeAuto, acf_lf_detected, radio);
    }
    furi_mutex_acquire(radio->data_mutex, FuriWaitForever);
    radio->running = true;
    furi_mutex_release(radio->data_mutex);
    return true;
}

void acf_radio_tick(AcfRadio* radio) {
    if(!radio || !radio->running || radio->mode != AcfRadioSubGhz || !radio->subghz) return;
    float rssi = subghz_devices_get_rssi(radio->subghz);
    furi_mutex_acquire(radio->data_mutex, FuriWaitForever);
    radio->rssi = rssi;
    if(radio->rssi > -85.0f && !radio->signal_active) {
        radio->signal_active = true;
        radio->events++;
        radio->last_timestamp = furi_hal_rtc_get_timestamp();
    } else if(radio->rssi < -90.0f) {
        radio->signal_active = false;
    }
    int value = (int)radio->rssi;
    if(value < -127) value = -127;
    if(value > 0) value = 0;
    if(radio->history_count < ACF_RADIO_HISTORY_SIZE) {
        radio->history[radio->history_count++] = (int8_t)value;
    } else {
        memmove(radio->history, radio->history + 1, ACF_RADIO_HISTORY_SIZE - 1);
        radio->history[ACF_RADIO_HISTORY_SIZE - 1] = (int8_t)value;
    }
    furi_mutex_release(radio->data_mutex);
}

void acf_radio_snapshot(const AcfRadio* radio, AcfRadioSnapshot* snapshot) {
    if(!snapshot) return;
    memset(snapshot, 0, sizeof(*snapshot));
    if(!radio) return;
    furi_mutex_acquire(radio->data_mutex, FuriWaitForever);
    snapshot->mode = radio->mode;
    snapshot->running = radio->running;
    snapshot->log_error = radio->log_error;
    snapshot->frequency = radio->frequency;
    snapshot->events = radio->events;
    snapshot->last_timestamp = radio->last_timestamp;
    snapshot->rssi = radio->rssi;
    snapshot->history_count = radio->history_count;
    memcpy(snapshot->history, radio->history, sizeof(snapshot->history));
    snprintf(snapshot->protocol, sizeof(snapshot->protocol), "%s", radio->protocol);
    snprintf(snapshot->identifier, sizeof(snapshot->identifier), "%s", radio->identifier);
    snprintf(snapshot->error, sizeof(snapshot->error), "%s", radio->error);
    furi_mutex_release(radio->data_mutex);
}

void acf_radio_set_log_error(AcfRadio* radio, bool error) {
    if(!radio) return;
    furi_mutex_acquire(radio->data_mutex, FuriWaitForever);
    radio->log_error = error;
    furi_mutex_release(radio->data_mutex);
}
