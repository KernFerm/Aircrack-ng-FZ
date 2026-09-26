/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "acf_external_protocol.h"

#include <limits.h>
#include <string.h>

static bool acf_parse_u64(const char* text, uint64_t* value) {
    if(!text || !*text) return false;
    uint64_t result = 0;
    while(*text) {
        if(*text < '0' || *text > '9') return false;
        uint8_t digit = (uint8_t)(*text - '0');
        if(result > (UINT64_MAX - digit) / 10U) return false;
        result = result * 10U + digit;
        text++;
    }
    *value = result;
    return true;
}

static bool acf_parse_u32(const char* text, uint32_t* value) {
    uint64_t parsed = 0;
    if(!acf_parse_u64(text, &parsed) || parsed > UINT32_MAX) return false;
    *value = (uint32_t)parsed;
    return true;
}

static bool acf_copy_token(char* output, size_t output_size, const char* token) {
    size_t length = strlen(token);
    if(!length || length >= output_size) return false;
    memcpy(output, token, length + 1U);
    return true;
}

static size_t acf_tokenize(char* line, char** tokens, size_t capacity) {
    size_t count = 0;
    char* position = line;
    while(*position && count < capacity) {
        while(*position == ' ') position++;
        if(!*position) break;
        tokens[count++] = position;
        while(*position && *position != ' ') position++;
        if(*position) *position++ = 0;
    }
    return count;
}

bool acf_external_parse_line(const char* line, AcfExternalMessage* message) {
    if(!line || !message) return false;
    size_t length = strlen(line);
    if(!length || length >= ACF_EXTERNAL_LINE_MAX) return false;
    char copy[ACF_EXTERNAL_LINE_MAX];
    memcpy(copy, line, length + 1U);
    char* tokens[14];
    size_t count = acf_tokenize(copy, tokens, 14);
    if(count < 3 || strcmp(tokens[0], "ACF1")) return false;
    memset(message, 0, sizeof(*message));

    if(!strcmp(tokens[1], "INFO")) {
        if(count != 7 || !acf_parse_u32(tokens[2], &message->protocol_version) ||
           !acf_copy_token(message->backend_version, sizeof(message->backend_version), tokens[3]) ||
           !acf_copy_token(message->aircrack_version, sizeof(message->aircrack_version), tokens[4]) ||
           !acf_copy_token(message->interface_name, sizeof(message->interface_name), tokens[5]) ||
           !acf_copy_token(message->capture_path, sizeof(message->capture_path), tokens[6]))
            return false;
        message->type = AcfExternalMessageInfo;
        return true;
    }
    if(!strcmp(tokens[1], "STATUS")) {
        if(count != 12 || !acf_copy_token(message->state, sizeof(message->state), tokens[2]) ||
           !acf_parse_u32(tokens[3], &message->channel) || !acf_parse_u64(tokens[4], &message->packets) ||
           !acf_parse_u64(tokens[5], &message->bytes) || !acf_parse_u64(tokens[6], &message->management) ||
           !acf_parse_u64(tokens[7], &message->data) || !acf_parse_u64(tokens[8], &message->control) ||
           !acf_parse_u64(tokens[9], &message->eapol) || !acf_parse_u64(tokens[10], &message->dropped) ||
           strcmp(tokens[11], "END"))
            return false;
        message->type = AcfExternalMessageStatus;
        return true;
    }
    if(!strcmp(tokens[1], "ERROR")) {
        if(count != 3 || !acf_copy_token(message->error, sizeof(message->error), tokens[2])) return false;
        message->type = AcfExternalMessageError;
        return true;
    }
    return false;
}

void acf_external_decoder_reset(AcfExternalDecoder* decoder) {
    if(decoder) memset(decoder, 0, sizeof(*decoder));
}

void acf_external_decoder_feed(
    AcfExternalDecoder* decoder,
    const uint8_t* data,
    size_t length,
    AcfExternalMessageCallback callback,
    void* context) {
    if(!decoder || (!data && length)) return;
    for(size_t i = 0; i < length; i++) {
        uint8_t byte = data[i];
        if(byte == '\n') {
            if(!decoder->overflow && decoder->length) {
                if(decoder->line[decoder->length - 1U] == '\r') decoder->length--;
                decoder->line[decoder->length] = 0;
                AcfExternalMessage message;
                if(acf_external_parse_line(decoder->line, &message) && callback) callback(&message, context);
            }
            decoder->length = 0;
            decoder->overflow = false;
        } else if(!decoder->overflow) {
            if(decoder->length + 1U < sizeof(decoder->line)) decoder->line[decoder->length++] = (char)byte;
            else decoder->overflow = true;
        }
    }
}
