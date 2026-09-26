/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "acf_external.h"
#include "acf_external_protocol.h"

#include <furi.h>
#include <furi_hal.h>
#include <expansion/expansion.h>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    AcfExternalFlagStop = 1U << 0,
    AcfExternalFlagRx = 1U << 1,
    AcfExternalFlagError = 1U << 2,
};

struct AcfExternal {
    FuriMutex* data_mutex;
    FuriMutex* tx_mutex;
    FuriStreamBuffer* rx_stream;
    FuriThread* worker;
    bool worker_started;
    FuriHalSerialHandle* serial;
    Expansion* expansion;
    AcfExternalDecoder decoder;
    AcfExternalSnapshot snapshot;
};

static void acf_external_set_error(AcfExternal* external, const char* text) {
    furi_mutex_acquire(external->data_mutex, FuriWaitForever);
    snprintf(external->snapshot.error, sizeof(external->snapshot.error), "%s", text);
    furi_mutex_release(external->data_mutex);
}

static bool acf_external_send(AcfExternal* external, const char* command) {
    if(!external->serial) return false;
    furi_mutex_acquire(external->tx_mutex, FuriWaitForever);
    furi_hal_serial_tx(external->serial, (const uint8_t*)command, strlen(command));
    furi_hal_serial_tx_wait_complete(external->serial);
    furi_mutex_release(external->tx_mutex);
    return true;
}

static void acf_external_message(const AcfExternalMessage* message, void* context) {
    AcfExternal* external = context;
    furi_mutex_acquire(external->data_mutex, FuriWaitForever);
    AcfExternalSnapshot* snapshot = &external->snapshot;
    snapshot->last_update = furi_hal_rtc_get_timestamp();
    if(message->type == AcfExternalMessageInfo) {
        snapshot->protocol_version = message->protocol_version;
        if(message->protocol_version == ACF_EXTERNAL_PROTOCOL_VERSION) {
            snapshot->connected = true;
            snapshot->error[0] = 0;
            snprintf(snapshot->backend_version, sizeof(snapshot->backend_version), "%s", message->backend_version);
            snprintf(snapshot->aircrack_version, sizeof(snapshot->aircrack_version), "%s", message->aircrack_version);
            snprintf(snapshot->interface_name, sizeof(snapshot->interface_name), "%s", message->interface_name);
            snprintf(snapshot->capture_path, sizeof(snapshot->capture_path), "%s", message->capture_path);
        } else {
            snapshot->connected = false;
            snprintf(snapshot->error, sizeof(snapshot->error), "Protocol mismatch: Pi=%" PRIu32, message->protocol_version);
        }
    } else if(message->type == AcfExternalMessageStatus) {
        snprintf(snapshot->state, sizeof(snapshot->state), "%s", message->state);
        snapshot->capturing = !strcmp(message->state, "CAPTURING") || !strcmp(message->state, "STARTING");
        snapshot->channel = message->channel;
        snapshot->packets = message->packets;
        snapshot->bytes = message->bytes;
        snapshot->management = message->management;
        snapshot->data = message->data;
        snapshot->control = message->control;
        snapshot->eapol = message->eapol;
        snapshot->dropped = message->dropped;
    } else if(message->type == AcfExternalMessageError) {
        snprintf(snapshot->error, sizeof(snapshot->error), "%s", message->error);
        snapshot->capturing = false;
    }
    furi_mutex_release(external->data_mutex);
}

static void acf_external_irq(
    FuriHalSerialHandle* handle,
    FuriHalSerialRxEvent event,
    void* context) {
    AcfExternal* external = context;
    uint32_t flags = 0;
    if(event & FuriHalSerialRxEventData) {
        uint8_t byte = furi_hal_serial_async_rx(handle);
        if(furi_stream_buffer_send(external->rx_stream, &byte, 1, 0) == 1) flags |= AcfExternalFlagRx;
        else flags |= AcfExternalFlagError;
    }
    if(event &
       (FuriHalSerialRxEventFrameError | FuriHalSerialRxEventNoiseError |
        FuriHalSerialRxEventOverrunError | FuriHalSerialRxEventParityError))
        flags |= AcfExternalFlagError;
    if(flags && external->worker) furi_thread_flags_set(furi_thread_get_id(external->worker), flags);
}

static int32_t acf_external_worker(void* context) {
    AcfExternal* external = context;
    while(true) {
        uint32_t flags = furi_thread_flags_wait(
            AcfExternalFlagStop | AcfExternalFlagRx | AcfExternalFlagError,
            FuriFlagWaitAny,
            1000);
        if(flags & FuriFlagError) {
            if(flags == (uint32_t)FuriFlagErrorTimeout) {
                acf_external_send(external, "ACF1 STATUS\n");
            } else {
                acf_external_set_error(external, "UART worker failure");
            }
            continue;
        }
        if(flags & AcfExternalFlagStop) break;
        if(flags & AcfExternalFlagError) {
            furi_mutex_acquire(external->data_mutex, FuriWaitForever);
            external->snapshot.serial_errors++;
            snprintf(
                external->snapshot.error,
                sizeof(external->snapshot.error),
                "UART receive error (%" PRIu32 ")",
                external->snapshot.serial_errors);
            furi_mutex_release(external->data_mutex);
        }
        if(flags & AcfExternalFlagRx) {
            uint8_t buffer[64];
            size_t received;
            do {
                received = furi_stream_buffer_receive(external->rx_stream, buffer, sizeof(buffer), 0);
                if(received)
                    acf_external_decoder_feed(
                        &external->decoder,
                        buffer,
                        received,
                        acf_external_message,
                        external);
            } while(received);
        }
    }
    return 0;
}

AcfExternal* acf_external_alloc(void) {
    AcfExternal* external = calloc(1, sizeof(AcfExternal));
    if(!external) return NULL;
    external->data_mutex = furi_mutex_alloc(FuriMutexTypeNormal);
    external->tx_mutex = furi_mutex_alloc(FuriMutexTypeNormal);
    if(!external->data_mutex || !external->tx_mutex) {
        if(external->tx_mutex) furi_mutex_free(external->tx_mutex);
        if(external->data_mutex) furi_mutex_free(external->data_mutex);
        free(external);
        return NULL;
    }
    snprintf(external->snapshot.state, sizeof(external->snapshot.state), "DISCONNECTED");
    return external;
}

bool acf_external_start(AcfExternal* external, uint32_t baudrate) {
    if(!external || external->serial || baudrate < 9600U) return false;
    memset(&external->snapshot, 0, sizeof(external->snapshot));
    snprintf(external->snapshot.state, sizeof(external->snapshot.state), "CONNECTING");
    external->snapshot.active = true;
    acf_external_decoder_reset(&external->decoder);
    external->rx_stream = furi_stream_buffer_alloc(1024, 1);
    external->worker = furi_thread_alloc_ex("AcfExternal", 2048, acf_external_worker, external);
    if(!external->rx_stream || !external->worker) {
        acf_external_set_error(external, "Allocation failed");
        acf_external_stop(external);
        return false;
    }
    external->expansion = furi_record_open(RECORD_EXPANSION);
    expansion_disable(external->expansion);
    external->serial = furi_hal_serial_control_acquire(FuriHalSerialIdUsart);
    if(!external->serial) {
        acf_external_set_error(external, "USART busy");
        acf_external_stop(external);
        return false;
    }
    furi_thread_start(external->worker);
    external->worker_started = true;
    furi_hal_serial_init(external->serial, baudrate);
    furi_hal_serial_async_rx_start(external->serial, acf_external_irq, external, true);
    acf_external_send(external, "ACF1 HELLO\n");
    acf_external_send(external, "ACF1 STATUS\n");
    return true;
}

void acf_external_stop(AcfExternal* external) {
    if(!external) return;
    if(external->serial) {
        acf_external_send(external, "ACF1 STOP\n");
        furi_hal_serial_async_rx_stop(external->serial);
    }
    if(external->worker) {
        if(external->worker_started) {
            furi_thread_flags_set(furi_thread_get_id(external->worker), AcfExternalFlagStop);
            furi_thread_join(external->worker);
        }
        furi_thread_free(external->worker);
        external->worker = NULL;
        external->worker_started = false;
    }
    if(external->serial) {
        furi_hal_serial_deinit(external->serial);
        furi_hal_serial_control_release(external->serial);
        external->serial = NULL;
    }
    if(external->expansion) {
        expansion_enable(external->expansion);
        furi_record_close(RECORD_EXPANSION);
        external->expansion = NULL;
    }
    if(external->rx_stream) {
        furi_stream_buffer_free(external->rx_stream);
        external->rx_stream = NULL;
    }
    furi_mutex_acquire(external->data_mutex, FuriWaitForever);
    external->snapshot.active = false;
    external->snapshot.connected = false;
    external->snapshot.capturing = false;
    snprintf(external->snapshot.state, sizeof(external->snapshot.state), "DISCONNECTED");
    furi_mutex_release(external->data_mutex);
}

bool acf_external_capture_start(AcfExternal* external, uint32_t channel) {
    if(!external || channel < 1U || channel > 14U) return false;
    AcfExternalSnapshot snapshot;
    acf_external_snapshot(external, &snapshot);
    if(!snapshot.connected || snapshot.capturing) return false;
    char command[40];
    snprintf(command, sizeof(command), "ACF1 START %" PRIu32 "\n", channel);
    if(!acf_external_send(external, command)) return false;
    furi_mutex_acquire(external->data_mutex, FuriWaitForever);
    snprintf(external->snapshot.state, sizeof(external->snapshot.state), "STARTING");
    external->snapshot.capturing = true;
    external->snapshot.channel = channel;
    furi_mutex_release(external->data_mutex);
    return true;
}

bool acf_external_capture_stop(AcfExternal* external) {
    if(!external) return false;
    AcfExternalSnapshot snapshot;
    acf_external_snapshot(external, &snapshot);
    if(!snapshot.connected) return false;
    if(!acf_external_send(external, "ACF1 STOP\n")) return false;
    furi_mutex_acquire(external->data_mutex, FuriWaitForever);
    snprintf(external->snapshot.state, sizeof(external->snapshot.state), "STOPPING");
    external->snapshot.capturing = false;
    furi_mutex_release(external->data_mutex);
    return true;
}

void acf_external_snapshot(AcfExternal* external, AcfExternalSnapshot* snapshot) {
    if(!external || !snapshot) return;
    furi_mutex_acquire(external->data_mutex, FuriWaitForever);
    *snapshot = external->snapshot;
    furi_mutex_release(external->data_mutex);
}

void acf_external_free(AcfExternal* external) {
    if(!external) return;
    acf_external_stop(external);
    furi_mutex_free(external->tx_mutex);
    furi_mutex_free(external->data_mutex);
    free(external);
}
