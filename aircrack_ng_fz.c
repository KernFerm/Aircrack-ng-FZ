/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "acf_parser.h"
#include "acf_radio.h"
#include "acf_external.h"

#include <furi.h>
#include <furi/core/memmgr.h>
#include <furi_hal.h>
#include <gui/gui.h>
#include <gui/view.h>
#include <gui/view_dispatcher.h>
#include <gui/modules/file_browser.h>
#include <gui/modules/submenu.h>
#include <gui/modules/variable_item_list.h>
#include <gui/modules/widget.h>
#include <storage/storage.h>
#include <flipper_format/flipper_format.h>
#include <nfc/nfc_device.h>
#include <lfrfid/lfrfid_dict_file.h>
#include <lfrfid/protocols/lfrfid_protocols.h>
#include <toolbox/protocols/protocol_dict.h>

#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#define ACF_DATA_DIR APP_DATA_PATH("")
#define ACF_LOG_PATH APP_DATA_PATH("radio_log.csv")
#define ACF_REPORT_PATH APP_DATA_PATH("report.txt")
#define ACF_APP_VERSION "1.0.5"

typedef enum {
    AcfViewMain,
    AcfViewOffline,
    AcfViewSaved,
    AcfViewBrowser,
    AcfViewText,
    AcfViewRadio,
    AcfViewExternal,
    AcfViewSettings,
} AcfViewId;

typedef enum {
    AcfMenuOffline,
    AcfMenuExternalWifi,
    AcfMenuSubGhz,
    AcfMenuNfc,
    AcfMenuLfRfid,
    AcfMenuSaved,
    AcfMenuStatistics,
    AcfMenuReports,
    AcfMenuCompatibility,
    AcfMenuResourceTest,
    AcfMenuSettings,
} AcfMainItem;

typedef enum {
    AcfTaskCapture,
    AcfTaskSavedNfc,
    AcfTaskSavedLf,
    AcfTaskSavedSub,
    AcfTaskResourceTest,
} AcfTask;

typedef enum {
    AcfEventAnalysisDone = 1,
    AcfEventRadioUpdate,
} AcfEvent;

typedef struct {
    Gui* gui;
    Storage* storage;
    ViewDispatcher* dispatcher;
    Submenu* main_menu;
    Submenu* offline_menu;
    Submenu* saved_menu;
    FileBrowser* browser;
    Widget* widget;
    VariableItemList* settings;
    View* radio_view;
    View* external_view;
    FuriString* path;
    FuriString* text;
    FuriThread* worker;
    FuriThread* log_worker;
    volatile bool cancel;
    volatile bool log_stop;
    AcfStatus status;
    AcfAnalysis analysis;
    char saved_result[512];
    AcfTask task;
    AcfViewId current_view;
    AcfViewId browser_return;
    AcfRadio* radio;
    AcfExternal* external;
    uint32_t external_baud;
    uint8_t external_baud_index;
    uint32_t external_channel;
    uint8_t external_channel_index;
    uint32_t frequency;
    uint8_t frequency_index;
    volatile bool logging;
    volatile bool resource_test_active;
    volatile uint8_t resource_test_cycles;
    uint32_t files_analyzed;
    uint32_t malformed_files;
    uint32_t total_radio_events;
    uint32_t last_logged_events;
    size_t worker_heap_before;
    size_t worker_heap_after;
    size_t minimum_free_heap;
    uint32_t worker_stack_free;
} AcfApp;

typedef struct {
    AcfApp* app;
    uint32_t revision;
} AcfRadioViewModel;

typedef struct {
    AcfApp* app;
    uint32_t revision;
} AcfExternalViewModel;

static const uint32_t acf_frequencies[] = {315000000, 433920000, 868350000, 915000000};
static const char* const acf_frequency_names[] = {"315.00", "433.92", "868.35", "915.00"};
static const uint32_t acf_external_bauds[] = {115200U, 230400U, 460800U};
static const char* const acf_external_baud_names[] = {"115200", "230400", "460800"};
static const uint32_t acf_external_channels[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};
static const char* const acf_external_channel_names[] = {
    "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13"};

static void acf_switch(AcfApp* app, AcfViewId view) {
    app->current_view = view;
    view_dispatcher_switch_to_view(app->dispatcher, view);
}

static void acf_set_text(AcfApp* app, const char* title, const char* body) {
    widget_reset(app->widget);
    furi_string_printf(app->text, "\e#%s\n%s", title, body);
    widget_add_text_scroll_element(app->widget, 0, 0, 128, 64, furi_string_get_cstr(app->text));
    acf_switch(app, AcfViewText);
}

static size_t acf_storage_read(void* context, void* data, size_t size) {
    return storage_file_read(context, data, size);
}
static bool acf_storage_seek(void* context, uint32_t offset) {
    return storage_file_seek(context, offset, true);
}
static uint64_t acf_storage_tell(void* context) {
    return storage_file_tell(context);
}
static uint64_t acf_storage_size(void* context) {
    return storage_file_size(context);
}

static void acf_hex_string(char* output, size_t output_size, const uint8_t* data, size_t size) {
    size_t used = 0;
    for(size_t i = 0; i < size && used + 2 < output_size; i++) {
        used += snprintf(output + used, output_size - used, "%02X", (unsigned)data[i]);
    }
}

static AcfStatus acf_load_saved_nfc(AcfApp* app) {
    NfcDevice* device = nfc_device_alloc();
    if(!device) return AcfStatusIo;
    bool loaded = nfc_device_load(device, furi_string_get_cstr(app->path));
    if(loaded) {
        NfcProtocol protocol = nfc_device_get_protocol(device);
        size_t uid_size = 0;
        const uint8_t* uid = nfc_device_get_uid(device, &uid_size);
        char uid_text[65] = "Unavailable";
        if(uid && uid_size) acf_hex_string(uid_text, sizeof(uid_text), uid, uid_size);
        snprintf(
            app->saved_result,
            sizeof(app->saved_result),
            "\e#Saved NFC file\nProtocol: %s\nUID: %s\nName: %s\n\nValues are read from the saved file.",
            nfc_device_get_protocol_name(protocol),
            uid_text,
            nfc_device_get_name(device, NfcDeviceNameTypeFull));
    }
    nfc_device_free(device);
    return loaded ? AcfStatusOk : AcfStatusMalformed;
}

static AcfStatus acf_load_saved_lf(AcfApp* app) {
    ProtocolDict* dict = protocol_dict_alloc(lfrfid_protocols, LFRFIDProtocolMax);
    if(!dict) return AcfStatusIo;
    ProtocolId protocol = lfrfid_dict_file_load(dict, furi_string_get_cstr(app->path));
    if(protocol >= 0 && protocol < LFRFIDProtocolMax) {
        size_t size = protocol_dict_get_data_size(dict, (size_t)protocol);
        uint8_t data[32];
        if(size > sizeof(data)) size = sizeof(data);
        protocol_dict_get_data(dict, (size_t)protocol, data, size);
        char id[65] = "";
        acf_hex_string(id, sizeof(id), data, size);
        snprintf(
            app->saved_result,
            sizeof(app->saved_result),
            "\e#Saved LF RFID file\nProtocol: %s\nData: %s\n\nDecoded with the official LF protocol dictionary.",
            protocol_dict_get_name(dict, (size_t)protocol),
            id);
    }
    protocol_dict_free(dict);
    return protocol >= 0 ? AcfStatusOk : AcfStatusMalformed;
}

static AcfStatus acf_load_saved_sub(AcfApp* app) {
    FlipperFormat* format = flipper_format_file_alloc(app->storage);
    if(!format) return AcfStatusIo;
    FuriString* file_type = furi_string_alloc();
    FuriString* protocol = furi_string_alloc();
    uint32_t version = 0;
    uint32_t frequency = 0;
    bool ok = flipper_format_file_open_existing(format, furi_string_get_cstr(app->path)) &&
              flipper_format_read_header(format, file_type, &version) &&
              furi_string_equal_str(file_type, "Flipper SubGhz Key File") &&
              flipper_format_read_uint32(format, "Frequency", &frequency, 1);
    if(ok) {
        if(!flipper_format_read_string(format, "Protocol", protocol))
            furi_string_set_str(protocol, "Not present");
        snprintf(
            app->saved_result,
            sizeof(app->saved_result),
            "\e#Saved Sub-GHz file\nFrequency: %" PRIu32 ".%03" PRIu32 " MHz\nProtocol: %s\nVersion: %" PRIu32 "\n\nNo transmission is performed.",
            frequency / 1000000U,
            (frequency / 1000U) % 1000U,
            furi_string_get_cstr(protocol),
            version);
    }
    flipper_format_file_close(format);
    flipper_format_free(format);
    furi_string_free(file_type);
    furi_string_free(protocol);
    return ok ? AcfStatusOk : AcfStatusMalformed;
}

static int32_t acf_analysis_worker(void* context) {
    AcfApp* app = context;
    app->worker_heap_before = memmgr_get_free_heap();
    if(app->task == AcfTaskCapture) {
        File* file = storage_file_alloc(app->storage);
        if(!file) {
            app->status = AcfStatusIo;
        } else if(!storage_file_open(
                      file, furi_string_get_cstr(app->path), FSAM_READ, FSOM_OPEN_EXISTING)) {
            app->status = AcfStatusIo;
        } else {
            AcfReader reader = {
                .context = file,
                .read = acf_storage_read,
                .seek = acf_storage_seek,
                .tell = acf_storage_tell,
                .size = acf_storage_size,
            };
            app->status = acf_analyze(&reader, &app->cancel, &app->analysis);
        }
        if(file) {
            if(storage_file_is_open(file)) storage_file_close(file);
            storage_file_free(file);
        }
    } else if(app->task == AcfTaskSavedNfc) {
        app->status = acf_load_saved_nfc(app);
    } else if(app->task == AcfTaskSavedLf) {
        app->status = acf_load_saved_lf(app);
    } else if(app->task == AcfTaskSavedSub) {
        app->status = acf_load_saved_sub(app);
    } else {
        app->status = AcfStatusOk;
        app->resource_test_active = true;
        app->resource_test_cycles = 0;
        for(uint8_t cycle = 0; cycle < 25 && app->status == AcfStatusOk; cycle++) {
            const AcfRadioMode modes[] = {AcfRadioSubGhz, AcfRadioNfc, AcfRadioLfRfid};
            for(size_t i = 0; i < COUNT_OF(modes); i++) {
                if(app->cancel) {
                    app->status = AcfStatusCancelled;
                    break;
                }
                if(!acf_radio_start(app->radio, modes[i], app->frequency)) {
                    app->status = AcfStatusIo;
                    break;
                }
                furi_delay_ms(100);
                acf_radio_stop(app->radio);
            }
            if(app->status == AcfStatusOk) app->resource_test_cycles = cycle + 1;
        }
        acf_radio_stop(app->radio);
        app->resource_test_active = false;
        if(app->status == AcfStatusOk) {
            snprintf(
                app->saved_result,
                sizeof(app->saved_result),
                "\e#Resource Self-Test PASS\n25/25 cycles completed.\n\nSub-GHz, NFC and LF RFID were acquired and released 25 times each using real hardware APIs.");
        }
    }
    app->worker_heap_after = memmgr_get_free_heap();
    app->minimum_free_heap = memmgr_get_minimum_free_heap();
    app->worker_stack_free = furi_thread_get_stack_space(furi_thread_get_current_id());
    view_dispatcher_send_custom_event(app->dispatcher, AcfEventAnalysisDone);
    return 0;
}

static void acf_join_worker(AcfApp* app) {
    if(app->worker) {
        app->cancel = true;
        furi_thread_join(app->worker);
        furi_thread_free(app->worker);
        app->worker = NULL;
    }
}

static void acf_append_worker_memory(AcfApp* app) {
    if(!app->worker_stack_free) return;
    furi_string_cat_printf(
        app->text,
        "\n\nHeap: %zu -> %zu free\nHeap minimum: %zu\nWorker stack free: %" PRIu32 "/3072",
        app->worker_heap_before,
        app->worker_heap_after,
        app->minimum_free_heap,
        app->worker_stack_free);
}

static void acf_show_analysis(AcfApp* app) {
    if(app->task == AcfTaskResourceTest) {
        if(app->status == AcfStatusOk) {
            furi_string_set_str(app->text, app->saved_result);
        } else {
            AcfRadioSnapshot snapshot;
            acf_radio_snapshot(app->radio, &snapshot);
            furi_string_printf(
                app->text,
                "\e#Resource Self-Test\n%s after %u/25 cycles.\n%s\n\nAll resources were released.",
                acf_status_name(app->status),
                (unsigned)app->resource_test_cycles,
                snapshot.error[0] ? snapshot.error : "Stopped safely");
        }
        acf_append_worker_memory(app);
        widget_reset(app->widget);
        widget_add_text_scroll_element(
            app->widget, 0, 0, 128, 64, furi_string_get_cstr(app->text));
        return;
    }
    if(app->status != AcfStatusOk) {
        if(app->status == AcfStatusMalformed) app->malformed_files++;
        furi_string_printf(
            app->text,
            "\e#Analysis failed\n%s\n\nInput rejected. No analysis result produced.",
            acf_status_name(app->status));
    } else if(app->task != AcfTaskCapture) {
        app->files_analyzed++;
        furi_string_set_str(app->text, app->saved_result);
    } else {
        app->files_analyzed++;
        const AcfAnalysis* a = &app->analysis;
        char bssid[18] = "Not present";
        if(a->has_bssid) {
            snprintf(
                bssid,
                sizeof(bssid),
                "%02X:%02X:%02X:%02X:%02X:%02X",
                (unsigned)a->first_bssid[0],
                (unsigned)a->first_bssid[1],
                (unsigned)a->first_bssid[2],
                (unsigned)a->first_bssid[3],
                (unsigned)a->first_bssid[4],
                (unsigned)a->first_bssid[5]);
        }
        furi_string_printf(
            app->text,
            "\e#Offline Aircrack\nFormat: %s  DLT: %" PRIu32 "\nPackets: %" PRIu32
            "  Bytes: %" PRIu64 "\nMgmt/Data/Ctrl: %" PRIu32 "/%" PRIu32 "/%" PRIu32
            "\nProtected: %" PRIu32 "  EAPOL: %" PRIu32 "\nIVS2/WPA records: %" PRIu32
            "/%" PRIu32 "\nSSID: %s\nBSSID: %s",
            acf_format_name(a->format),
            a->link_type,
            a->packets,
            a->captured_bytes,
            a->management_frames,
            a->data_frames,
            a->control_frames,
            a->protected_frames,
            a->eapol_frames,
            a->ivs2_records,
            a->ivs2_wpa_records,
            a->first_ssid[0] ? a->first_ssid : "Not present",
            bssid);
    }
    acf_append_worker_memory(app);
    widget_reset(app->widget);
    widget_add_text_scroll_element(app->widget, 0, 0, 128, 64, furi_string_get_cstr(app->text));
}

static void acf_browser_selected(void* context) {
    AcfApp* app = context;
    file_browser_stop(app->browser);
    acf_join_worker(app);
    app->cancel = false;
    memset(&app->analysis, 0, sizeof(app->analysis));
    memset(app->saved_result, 0, sizeof(app->saved_result));
    widget_reset(app->widget);
    furi_string_set_str(app->text, "\e#Analyzing...\nBack requests cancellation.");
    widget_add_text_scroll_element(app->widget, 0, 0, 128, 64, furi_string_get_cstr(app->text));
    acf_switch(app, AcfViewText);
    app->worker = furi_thread_alloc_ex("AcfAnalyze", 3072, acf_analysis_worker, app);
    if(app->worker) {
        furi_thread_start(app->worker);
    } else {
        app->status = AcfStatusIo;
        acf_show_analysis(app);
    }
}

static void acf_start_resource_test(AcfApp* app) {
    acf_join_worker(app);
    app->task = AcfTaskResourceTest;
    app->cancel = false;
    app->resource_test_cycles = 0;
    widget_reset(app->widget);
    furi_string_set_str(
        app->text,
        "\e#Resource Self-Test\nCycle 0/25\nSub-GHz + NFC + LF RFID\n\nBack cancels safely.");
    widget_add_text_scroll_element(
        app->widget, 0, 0, 128, 64, furi_string_get_cstr(app->text));
    acf_switch(app, AcfViewText);
    app->worker = furi_thread_alloc_ex("AcfHwTest", 3072, acf_analysis_worker, app);
    if(app->worker) {
        furi_thread_start(app->worker);
    } else {
        app->status = AcfStatusIo;
        acf_show_analysis(app);
    }
}

static void acf_open_browser(AcfApp* app, const char* extension, AcfTask task, AcfViewId return_to) {
    acf_join_worker(app);
    app->task = task;
    app->browser_return = return_to;
    file_browser_configure(app->browser, extension, "/ext", true, true, NULL, false);
    file_browser_start(app->browser, app->path);
    acf_switch(app, AcfViewBrowser);
}

static void acf_offline_selected(void* context, uint32_t index) {
    AcfApp* app = context;
    static const char* extensions[] = {".pcap", ".cap", ".pcapng", ".ivs"};
    if(index < 4) acf_open_browser(app, extensions[index], AcfTaskCapture, AcfViewOffline);
}

static void acf_saved_selected(void* context, uint32_t index) {
    AcfApp* app = context;
    if(index == 0) acf_open_browser(app, ".nfc", AcfTaskSavedNfc, AcfViewSaved);
    else if(index == 1) acf_open_browser(app, ".rfid", AcfTaskSavedLf, AcfViewSaved);
    else if(index == 2) acf_open_browser(app, ".sub", AcfTaskSavedSub, AcfViewSaved);
}

static void acf_log_radio(AcfApp* app) {
    AcfRadioSnapshot snapshot;
    acf_radio_snapshot(app->radio, &snapshot);
    if(!app->logging || !snapshot.running) return;
    if(snapshot.events == app->last_logged_events && snapshot.mode != AcfRadioSubGhz) return;
    storage_common_mkdir(app->storage, ACF_DATA_DIR);
    File* file = storage_file_alloc(app->storage);
    bool ok = false;
    if(file && storage_file_open(file, ACF_LOG_PATH, FSAM_WRITE, FSOM_OPEN_APPEND)) {
        char line[160];
        int length = snprintf(
            line,
            sizeof(line),
            "%" PRIu32 ",%u,%" PRIu32 ",%s,%.1f,%" PRIu32 ",%s\n",
            (uint32_t)furi_hal_rtc_get_timestamp(),
            (unsigned)snapshot.mode,
            snapshot.frequency,
            snapshot.protocol,
            (double)snapshot.rssi,
            snapshot.events,
            snapshot.identifier);
        if(length > 0 && (size_t)length < sizeof(line)) {
            ok = storage_file_write(file, line, (size_t)length) == (size_t)length;
        }
        storage_file_close(file);
    }
    if(file) storage_file_free(file);
    acf_radio_set_log_error(app->radio, !ok);
    if(ok) app->last_logged_events = snapshot.events;
}

static int32_t acf_log_worker(void* context) {
    AcfApp* app = context;
    while(!app->log_stop) {
        if(app->logging && !app->resource_test_active) acf_log_radio(app);
        for(uint8_t i = 0; i < 10 && !app->log_stop; i++) furi_delay_ms(100);
    }
    return 0;
}

static void acf_radio_draw(Canvas* canvas, void* model_context) {
    const AcfRadioViewModel* model = model_context;
    AcfApp* app = model->app;
    AcfRadioSnapshot snapshot;
    acf_radio_snapshot(app->radio, &snapshot);
    AcfRadioMode mode = snapshot.mode;
    const char* title = mode == AcfRadioSubGhz ? "SUB-GHZ ANALYZER" : mode == AcfRadioNfc ? "NFC 13.56 MHz" : "LF RFID 125 kHz";
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 2, 10, title);
    canvas_set_font(canvas, FontSecondary);
    char line[80];
    if(!snapshot.running) {
        snprintf(line, sizeof(line), "Unavailable: %s", snapshot.error);
        canvas_draw_str(canvas, 2, 23, line);
        canvas_draw_str(canvas, 2, 62, "Back");
        return;
    }
    if(mode == AcfRadioSubGhz) {
        canvas_set_font(canvas, FontPrimary);
        snprintf(
            line,
            sizeof(line),
            "%" PRIu32 ".%03" PRIu32 " MHz",
            snapshot.frequency / 1000000U,
            (snapshot.frequency / 1000U) % 1000U);
        canvas_draw_str(canvas, 2, 25, line);
        canvas_set_font(canvas, FontSecondary);
        snprintf(line, sizeof(line), "RSSI: %.1f dBm", (double)snapshot.rssi);
        canvas_draw_str(canvas, 2, 37, line);
        snprintf(line, sizeof(line), "Events: %" PRIu32, snapshot.events);
        canvas_draw_str(canvas, 2, 48, line);
        if(snapshot.log_error) {
            canvas_draw_str(canvas, 2, 60, "LOG ERROR: check SD");
        } else if(snapshot.last_timestamp) {
            snprintf(line, sizeof(line), "Last: %" PRIu32, snapshot.last_timestamp);
            canvas_draw_str(canvas, 2, 60, line);
        } else {
            canvas_draw_str(canvas, 2, 60, "Last: --");
        }
        uint8_t shown = snapshot.history_count < 38 ? snapshot.history_count : 38;
        uint8_t first = snapshot.history_count - shown;
        for(uint8_t i = 1; i < shown; i++) {
            int y1 = 48 - ((snapshot.history[first + i - 1] + 127) * 18 / 127);
            int y2 = 48 - ((snapshot.history[first + i] + 127) * 18 / 127);
            canvas_draw_line(canvas, 89 + i - 1, y1, 89 + i, y2);
        }
        return;
    }
    snprintf(
        line,
        sizeof(line),
        "Freq %" PRIu32 ".%03" PRIu32 " MHz",
        snapshot.frequency / 1000000U,
        (snapshot.frequency / 1000U) % 1000U);
    canvas_draw_str(canvas, 2, 21, line);
    snprintf(
        line,
        sizeof(line),
        "Events %" PRIu32 "  T %" PRIu32,
        snapshot.events,
        snapshot.last_timestamp);
    canvas_draw_str(canvas, 2, 31, line);
    snprintf(line, sizeof(line), "Protocol %s", snapshot.protocol);
    canvas_draw_str(canvas, 2, 41, line);
    if(snapshot.identifier[0]) {
        snprintf(line, sizeof(line), "ID %.20s", snapshot.identifier);
        canvas_draw_str(canvas, 2, 53, line);
    }
    canvas_draw_str(canvas, 2, 63, snapshot.log_error ? "LOG ERROR: check SD" : "Back stops safely");
}

static void acf_start_radio(AcfApp* app, AcfRadioMode mode) {
    app->last_logged_events = UINT32_MAX;
    acf_radio_start(app->radio, mode, app->frequency);
    acf_switch(app, AcfViewRadio);
    AcfRadioViewModel* model = view_get_model(app->radio_view);
    model->revision++;
    view_commit_model(app->radio_view, true);
}

static void acf_external_draw(Canvas* canvas, void* model_context) {
    const AcfExternalViewModel* model = model_context;
    AcfExternalSnapshot snapshot;
    acf_external_snapshot(model->app->external, &snapshot);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 2, 10, "EXTERNAL AIRCRACK");
    canvas_set_font(canvas, FontSecondary);
    char line[80];
    if(!snapshot.active) {
        canvas_draw_str(canvas, 2, 25, "UART is not active");
    } else if(!snapshot.connected) {
        snprintf(line, sizeof(line), "Waiting for Pi @ %" PRIu32, model->app->external_baud);
        canvas_draw_str(canvas, 2, 23, line);
        canvas_draw_str(canvas, 2, 35, "Protocol: ACF1");
        if(snapshot.error[0]) {
            snprintf(line, sizeof(line), "Error: %.18s", snapshot.error);
            canvas_draw_str(canvas, 2, 48, line);
        }
    } else {
        snprintf(line, sizeof(line), "Aircrack %.16s  %.12s", snapshot.aircrack_version, snapshot.interface_name);
        canvas_draw_str(canvas, 2, 21, line);
        snprintf(line, sizeof(line), "%.10s  Ch %" PRIu32, snapshot.state, snapshot.channel);
        canvas_draw_str(canvas, 2, 31, line);
        snprintf(line, sizeof(line), "Packets %" PRIu64 "  EAPOL %" PRIu64, snapshot.packets, snapshot.eapol);
        canvas_draw_str(canvas, 2, 41, line);
        snprintf(line, sizeof(line), "M/D/C %" PRIu64 "/%" PRIu64 "/%" PRIu64, snapshot.management, snapshot.data, snapshot.control);
        canvas_draw_str(canvas, 2, 51, line);
    }
    canvas_draw_str(canvas, 2, 63, snapshot.connected ? "OK start/stop   Back" : "Back");
}

static bool acf_external_input(InputEvent* event, void* context) {
    AcfApp* app = context;
    if(event->type != InputTypeShort || event->key != InputKeyOk) return false;
    AcfExternalSnapshot snapshot;
    acf_external_snapshot(app->external, &snapshot);
    if(snapshot.connected) {
        if(snapshot.capturing) acf_external_capture_stop(app->external);
        else acf_external_capture_start(app->external, app->external_channel);
    }
    AcfExternalViewModel* model = view_get_model(app->external_view);
    model->revision++;
    view_commit_model(app->external_view, true);
    return true;
}

static void acf_start_external(AcfApp* app) {
    acf_external_start(app->external, app->external_baud);
    acf_switch(app, AcfViewExternal);
    AcfExternalViewModel* model = view_get_model(app->external_view);
    model->revision++;
    view_commit_model(app->external_view, true);
}

static void acf_write_report(AcfApp* app) {
    storage_common_mkdir(app->storage, ACF_DATA_DIR);
    File* file = storage_file_alloc(app->storage);
    bool ok = file && storage_file_open(file, ACF_REPORT_PATH, FSAM_WRITE, FSOM_CREATE_ALWAYS);
    if(ok) {
        AcfExternalSnapshot external;
        acf_external_snapshot(app->external, &external);
        char report[768];
        int len = snprintf(
            report,
            sizeof(report),
            "Aircrack-ng FZ report\nGenerated: %" PRIu32 "\nFiles analyzed: %" PRIu32
            "\nMalformed files: %" PRIu32 "\nRadio events: %" PRIu32
            "\nLast capture format: %s\nLast packet count: %" PRIu32
            "\nLast EAPOL frames: %" PRIu32
            "\nNotice: EAPOL frames are not claimed as a valid WPA handshake."
            "\nExternal connected: %s\nExternal Aircrack: %s\nExternal interface: %s"
            "\nExternal state/channel: %s/%" PRIu32
            "\nExternal packets/EAPOL: %" PRIu64 "/%" PRIu64
            "\nExternal capture: %s\n",
            (uint32_t)furi_hal_rtc_get_timestamp(),
            app->files_analyzed,
            app->malformed_files,
            app->total_radio_events,
            acf_format_name(app->analysis.format),
            app->analysis.packets,
            app->analysis.eapol_frames,
            external.connected ? "yes" : "no",
            external.aircrack_version[0] ? external.aircrack_version : "not reported",
            external.interface_name[0] ? external.interface_name : "not reported",
            external.state,
            external.channel,
            external.packets,
            external.eapol,
            external.capture_path[0] ? external.capture_path : "not reported");
        ok = len > 0 && (size_t)len < sizeof(report) &&
             storage_file_write(file, report, (size_t)len) == (size_t)len;
        storage_file_close(file);
    }
    if(file) storage_file_free(file);
    acf_set_text(
        app,
        ok ? "Report saved" : "Report failed",
        ok ? ACF_REPORT_PATH "\nContains measured/parser results only." : "Check SD card and free space.");
}

static void acf_main_selected(void* context, uint32_t index) {
    AcfApp* app = context;
    switch(index) {
    case AcfMenuOffline:
        acf_switch(app, AcfViewOffline);
        break;
    case AcfMenuExternalWifi:
        acf_start_external(app);
        break;
    case AcfMenuSubGhz:
        acf_start_radio(app, AcfRadioSubGhz);
        break;
    case AcfMenuNfc:
        acf_start_radio(app, AcfRadioNfc);
        break;
    case AcfMenuLfRfid:
        acf_start_radio(app, AcfRadioLfRfid);
        break;
    case AcfMenuSaved:
        acf_switch(app, AcfViewSaved);
        break;
    case AcfMenuStatistics:
        {
        char statistics[192];
        snprintf(
            statistics,
            sizeof(statistics),
            "Files analyzed: %" PRIu32 "\nMalformed: %" PRIu32 "\nRadio events: %" PRIu32
            "\n\nCurrent session only. Saved reports and logs persist.",
            app->files_analyzed,
            app->malformed_files,
            app->total_radio_events);
        acf_set_text(app, "Session Statistics", statistics);
        }
        break;
    case AcfMenuReports:
        acf_write_report(app);
        break;
    case AcfMenuCompatibility:
        acf_set_text(
            app,
            "Compatibility",
            "Offline: PCAP, PCAPNG, CAP, IVS2\nLive: Sub-GHz, NFC, LF RFID\nExternal: Linux/Pi Aircrack-ng over UART\n\nThe Pi and a monitor-mode adapter provide the Wi-Fi hardware.");
        break;
    case AcfMenuResourceTest:
        acf_start_resource_test(app);
        break;
    case AcfMenuSettings:
        acf_switch(app, AcfViewSettings);
        break;
    }
}

static void acf_frequency_changed(VariableItem* item) {
    AcfApp* app = variable_item_get_context(item);
    app->frequency_index = variable_item_get_current_value_index(item);
    app->frequency = acf_frequencies[app->frequency_index];
    variable_item_set_current_value_text(item, acf_frequency_names[app->frequency_index]);
}

static void acf_logging_changed(VariableItem* item) {
    AcfApp* app = variable_item_get_context(item);
    app->logging = variable_item_get_current_value_index(item) != 0;
    if(!app->logging) acf_radio_set_log_error(app->radio, false);
    variable_item_set_current_value_text(item, app->logging ? "On" : "Off");
}

static void acf_external_baud_changed(VariableItem* item) {
    AcfApp* app = variable_item_get_context(item);
    app->external_baud_index = variable_item_get_current_value_index(item);
    app->external_baud = acf_external_bauds[app->external_baud_index];
    variable_item_set_current_value_text(item, acf_external_baud_names[app->external_baud_index]);
}

static void acf_external_channel_changed(VariableItem* item) {
    AcfApp* app = variable_item_get_context(item);
    app->external_channel_index = variable_item_get_current_value_index(item);
    app->external_channel = acf_external_channels[app->external_channel_index];
    variable_item_set_current_value_text(item, acf_external_channel_names[app->external_channel_index]);
}

static bool acf_custom_event(void* context, uint32_t event) {
    AcfApp* app = context;
    if(event == AcfEventAnalysisDone) {
        acf_join_worker(app);
        acf_show_analysis(app);
        return true;
    }
    return false;
}

static bool acf_back(void* context) {
    AcfApp* app = context;
    if(app->current_view == AcfViewMain) {
        view_dispatcher_stop(app->dispatcher);
    } else if(app->current_view == AcfViewRadio) {
        AcfRadioSnapshot snapshot;
        acf_radio_snapshot(app->radio, &snapshot);
        app->total_radio_events += snapshot.events;
        acf_radio_stop(app->radio);
        acf_switch(app, AcfViewMain);
    } else if(app->current_view == AcfViewExternal) {
        acf_external_stop(app->external);
        acf_switch(app, AcfViewMain);
    } else if(app->current_view == AcfViewBrowser) {
        file_browser_stop(app->browser);
        acf_switch(app, app->browser_return);
    } else if(app->current_view == AcfViewOffline || app->current_view == AcfViewSaved ||
              app->current_view == AcfViewSettings) {
        acf_switch(app, AcfViewMain);
    } else if(app->worker) {
        app->cancel = true;
        furi_string_set_str(app->text, "\e#Cancelling...\nWaiting for the bounded parser to release the file.");
        widget_reset(app->widget);
        widget_add_text_scroll_element(app->widget, 0, 0, 128, 64, furi_string_get_cstr(app->text));
    } else {
        acf_switch(app, AcfViewMain);
    }
    return true;
}

static void acf_tick(void* context) {
    AcfApp* app = context;
    AcfRadioSnapshot snapshot;
    acf_radio_snapshot(app->radio, &snapshot);
    if(app->current_view == AcfViewRadio && snapshot.running) {
        acf_radio_tick(app->radio);
        AcfRadioViewModel* model = view_get_model(app->radio_view);
        model->revision++;
        view_commit_model(app->radio_view, true);
    } else if(app->current_view == AcfViewExternal) {
        AcfExternalViewModel* model = view_get_model(app->external_view);
        model->revision++;
        view_commit_model(app->external_view, true);
    } else if(
        app->current_view == AcfViewText && app->worker && app->task == AcfTaskResourceTest &&
        !app->cancel) {
        furi_string_printf(
            app->text,
            "\e#Resource Self-Test\nCycle %u/25\nSub-GHz + NFC + LF RFID\n\nBack cancels safely.",
            (unsigned)app->resource_test_cycles);
        widget_reset(app->widget);
        widget_add_text_scroll_element(
            app->widget, 0, 0, 128, 64, furi_string_get_cstr(app->text));
    }
}

static AcfApp* acf_app_alloc(void) {
    AcfApp* app = calloc(1, sizeof(AcfApp));
    if(!app) return NULL;
    app->gui = furi_record_open(RECORD_GUI);
    app->storage = furi_record_open(RECORD_STORAGE);
    app->dispatcher = view_dispatcher_alloc();
    app->main_menu = submenu_alloc();
    app->offline_menu = submenu_alloc();
    app->saved_menu = submenu_alloc();
    app->path = furi_string_alloc_set("/ext");
    app->text = furi_string_alloc();
    app->browser = file_browser_alloc(app->path);
    app->widget = widget_alloc();
    app->settings = variable_item_list_alloc();
    app->radio_view = view_alloc();
    app->external_view = view_alloc();
    app->radio = acf_radio_alloc();
    app->external = acf_external_alloc();
    if(!app->dispatcher || !app->main_menu || !app->offline_menu || !app->saved_menu ||
       !app->path || !app->text || !app->browser || !app->widget || !app->settings ||
       !app->radio_view || !app->external_view || !app->radio || !app->external) {
        if(app->external) acf_external_free(app->external);
        if(app->radio) acf_radio_free(app->radio);
        if(app->external_view) view_free(app->external_view);
        if(app->radio_view) view_free(app->radio_view);
        if(app->settings) variable_item_list_free(app->settings);
        if(app->widget) widget_free(app->widget);
        if(app->browser) file_browser_free(app->browser);
        if(app->saved_menu) submenu_free(app->saved_menu);
        if(app->offline_menu) submenu_free(app->offline_menu);
        if(app->main_menu) submenu_free(app->main_menu);
        if(app->dispatcher) view_dispatcher_free(app->dispatcher);
        if(app->text) furi_string_free(app->text);
        if(app->path) furi_string_free(app->path);
        furi_record_close(RECORD_STORAGE);
        furi_record_close(RECORD_GUI);
        free(app);
        return NULL;
    }
    app->frequency_index = 1;
    app->frequency = acf_frequencies[app->frequency_index];
    app->external_baud_index = 0;
    app->external_baud = acf_external_bauds[app->external_baud_index];
    app->external_channel_index = 5;
    app->external_channel = acf_external_channels[app->external_channel_index];
    app->log_worker = furi_thread_alloc_ex("AcfLog", 2048, acf_log_worker, app);
    if(!app->log_worker) {
        acf_external_free(app->external);
        acf_radio_free(app->radio);
        view_free(app->external_view);
        view_free(app->radio_view);
        variable_item_list_free(app->settings);
        widget_free(app->widget);
        file_browser_free(app->browser);
        submenu_free(app->saved_menu);
        submenu_free(app->offline_menu);
        submenu_free(app->main_menu);
        view_dispatcher_free(app->dispatcher);
        furi_string_free(app->text);
        furi_string_free(app->path);
        furi_record_close(RECORD_STORAGE);
        furi_record_close(RECORD_GUI);
        free(app);
        return NULL;
    }
    furi_thread_start(app->log_worker);

    view_set_context(app->radio_view, app);
    view_set_draw_callback(app->radio_view, acf_radio_draw);
    view_allocate_model(app->radio_view, ViewModelTypeLocking, sizeof(AcfRadioViewModel));
    AcfRadioViewModel* radio_model = view_get_model(app->radio_view);
    radio_model->app = app;
    radio_model->revision = 0;
    view_commit_model(app->radio_view, false);
    view_set_context(app->external_view, app);
    view_set_draw_callback(app->external_view, acf_external_draw);
    view_set_input_callback(app->external_view, acf_external_input);
    view_allocate_model(app->external_view, ViewModelTypeLocking, sizeof(AcfExternalViewModel));
    AcfExternalViewModel* external_model = view_get_model(app->external_view);
    external_model->app = app;
    external_model->revision = 0;
    view_commit_model(app->external_view, false);
    file_browser_set_callback(app->browser, acf_browser_selected, app);

    submenu_set_header(app->main_menu, "Aircrack-ng FZ v" ACF_APP_VERSION);
    submenu_add_item(app->main_menu, "Offline Aircrack Analysis", AcfMenuOffline, acf_main_selected, app);
    submenu_add_item(app->main_menu, "External Aircrack-ng", AcfMenuExternalWifi, acf_main_selected, app);
    submenu_add_item(app->main_menu, "Sub-GHz Analyzer", AcfMenuSubGhz, acf_main_selected, app);
    submenu_add_item(app->main_menu, "NFC Analyzer", AcfMenuNfc, acf_main_selected, app);
    submenu_add_item(app->main_menu, "LF RFID Analyzer", AcfMenuLfRfid, acf_main_selected, app);
    submenu_add_item(app->main_menu, "Saved Files", AcfMenuSaved, acf_main_selected, app);
    submenu_add_item(app->main_menu, "Session Statistics", AcfMenuStatistics, acf_main_selected, app);
    submenu_add_item(app->main_menu, "Reports", AcfMenuReports, acf_main_selected, app);
    submenu_add_item(app->main_menu, "Compatibility", AcfMenuCompatibility, acf_main_selected, app);
    submenu_add_item(app->main_menu, "Resource Self-Test", AcfMenuResourceTest, acf_main_selected, app);
    submenu_add_item(app->main_menu, "Settings", AcfMenuSettings, acf_main_selected, app);

    submenu_set_header(app->offline_menu, "Choose real capture format");
    submenu_add_item(app->offline_menu, "PCAP (.pcap)", 0, acf_offline_selected, app);
    submenu_add_item(app->offline_menu, "CAP (.cap)", 1, acf_offline_selected, app);
    submenu_add_item(app->offline_menu, "PCAPNG (.pcapng)", 2, acf_offline_selected, app);
    submenu_add_item(app->offline_menu, "Aircrack IVS2 (.ivs)", 3, acf_offline_selected, app);

    submenu_set_header(app->saved_menu, "Analyze saved radio data");
    submenu_add_item(app->saved_menu, "NFC (.nfc)", 0, acf_saved_selected, app);
    submenu_add_item(app->saved_menu, "LF RFID (.rfid)", 1, acf_saved_selected, app);
    submenu_add_item(app->saved_menu, "Sub-GHz (.sub)", 2, acf_saved_selected, app);

    VariableItem* frequency = variable_item_list_add(
        app->settings, "Sub-GHz MHz", COUNT_OF(acf_frequencies), acf_frequency_changed, app);
    variable_item_set_current_value_index(frequency, app->frequency_index);
    variable_item_set_current_value_text(frequency, acf_frequency_names[app->frequency_index]);
    VariableItem* logging =
        variable_item_list_add(app->settings, "Hardware logging", 2, acf_logging_changed, app);
    variable_item_set_current_value_index(logging, 0);
    variable_item_set_current_value_text(logging, "Off");
    VariableItem* baud = variable_item_list_add(
        app->settings, "External baud", COUNT_OF(acf_external_bauds), acf_external_baud_changed, app);
    variable_item_set_current_value_index(baud, app->external_baud_index);
    variable_item_set_current_value_text(baud, acf_external_baud_names[app->external_baud_index]);
    VariableItem* channel = variable_item_list_add(
        app->settings, "Wi-Fi channel", COUNT_OF(acf_external_channels), acf_external_channel_changed, app);
    variable_item_set_current_value_index(channel, app->external_channel_index);
    variable_item_set_current_value_text(channel, acf_external_channel_names[app->external_channel_index]);
    VariableItem* version = variable_item_list_add(app->settings, "App version", 1, NULL, app);
    variable_item_set_current_value_text(version, ACF_APP_VERSION);
    VariableItem* protocol = variable_item_list_add(app->settings, "External protocol", 1, NULL, app);
    variable_item_set_current_value_text(protocol, "ACF1");

    view_dispatcher_set_event_callback_context(app->dispatcher, app);
    view_dispatcher_set_navigation_event_callback(app->dispatcher, acf_back);
    view_dispatcher_set_custom_event_callback(app->dispatcher, acf_custom_event);
    view_dispatcher_set_tick_event_callback(app->dispatcher, acf_tick, 500);
    view_dispatcher_add_view(app->dispatcher, AcfViewMain, submenu_get_view(app->main_menu));
    view_dispatcher_add_view(app->dispatcher, AcfViewOffline, submenu_get_view(app->offline_menu));
    view_dispatcher_add_view(app->dispatcher, AcfViewSaved, submenu_get_view(app->saved_menu));
    view_dispatcher_add_view(app->dispatcher, AcfViewBrowser, file_browser_get_view(app->browser));
    view_dispatcher_add_view(app->dispatcher, AcfViewText, widget_get_view(app->widget));
    view_dispatcher_add_view(app->dispatcher, AcfViewRadio, app->radio_view);
    view_dispatcher_add_view(app->dispatcher, AcfViewExternal, app->external_view);
    view_dispatcher_add_view(app->dispatcher, AcfViewSettings, variable_item_list_get_view(app->settings));
    view_dispatcher_attach_to_gui(app->dispatcher, app->gui, ViewDispatcherTypeFullscreen);
    return app;
}

static void acf_app_free(AcfApp* app) {
    if(!app) return;
    acf_join_worker(app);
    if(app->log_worker) {
        app->log_stop = true;
        furi_thread_join(app->log_worker);
        furi_thread_free(app->log_worker);
        app->log_worker = NULL;
    }
    acf_external_free(app->external);
    acf_radio_free(app->radio);
    view_dispatcher_remove_view(app->dispatcher, AcfViewMain);
    view_dispatcher_remove_view(app->dispatcher, AcfViewOffline);
    view_dispatcher_remove_view(app->dispatcher, AcfViewSaved);
    view_dispatcher_remove_view(app->dispatcher, AcfViewBrowser);
    view_dispatcher_remove_view(app->dispatcher, AcfViewText);
    view_dispatcher_remove_view(app->dispatcher, AcfViewRadio);
    view_dispatcher_remove_view(app->dispatcher, AcfViewExternal);
    view_dispatcher_remove_view(app->dispatcher, AcfViewSettings);
    view_free(app->radio_view);
    view_free(app->external_view);
    variable_item_list_free(app->settings);
    widget_free(app->widget);
    file_browser_free(app->browser);
    submenu_free(app->saved_menu);
    submenu_free(app->offline_menu);
    submenu_free(app->main_menu);
    view_dispatcher_free(app->dispatcher);
    furi_string_free(app->text);
    furi_string_free(app->path);
    furi_record_close(RECORD_STORAGE);
    furi_record_close(RECORD_GUI);
    free(app);
}

int32_t aircrack_ng_fz_app(void* p) {
    UNUSED(p);
    AcfApp* app = acf_app_alloc();
    if(!app) return -1;
    acf_switch(app, AcfViewMain);
    view_dispatcher_run(app->dispatcher);
    acf_app_free(app);
    return 0;
}
