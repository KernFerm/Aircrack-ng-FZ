/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "acf_parser.h"

#include <string.h>

#define ACF_PACKET_PREFIX 512U
#define ACF_MAX_CAPTURE_RECORD (16U * 1024U * 1024U)
#define ACF_LINKTYPE_IEEE802_11 105U
#define ACF_LINKTYPE_PRISM 119U
#define ACF_LINKTYPE_RADIOTAP 127U
#define ACF_LINKTYPE_PPI 192U
#define ACF_IVS2_BSSID 0x0001U
#define ACF_IVS2_ESSID 0x0002U
#define ACF_IVS2_WPA 0x0004U
#define ACF_IVS2_XOR 0x0008U
#define ACF_IVS2_PTW 0x0010U
#define ACF_IVS2_CLR 0x0020U
#define ACF_IVS2_KNOWN_FLAGS 0x003FU
#define ACF_IVS2_WPA_SIZE 392U

static uint16_t acf_u16(const uint8_t* p, bool be) {
    return be ? ((uint16_t)p[0] << 8) | p[1] : ((uint16_t)p[1] << 8) | p[0];
}

static uint32_t acf_u32(const uint8_t* p, bool be) {
    if(be) {
        return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) |
               p[3];
    }
    return ((uint32_t)p[3] << 24) | ((uint32_t)p[2] << 16) | ((uint32_t)p[1] << 8) | p[0];
}

static bool acf_read_exact(AcfReader* r, void* data, size_t size) {
    return size == 0 || r->read(r->context, data, size) == size;
}

static bool acf_skip(AcfReader* r, uint32_t amount) {
    uint64_t position = r->tell(r->context);
    if(position > UINT32_MAX || amount > UINT32_MAX - (uint32_t)position) return false;
    return r->seek(r->context, (uint32_t)position + amount);
}

static bool acf_supported_link(uint32_t link) {
    return link == ACF_LINKTYPE_IEEE802_11 || link == ACF_LINKTYPE_PRISM ||
           link == ACF_LINKTYPE_RADIOTAP || link == ACF_LINKTYPE_PPI;
}

static void acf_parse_80211(const uint8_t* packet, size_t size, uint32_t link, AcfAnalysis* out) {
    size_t offset = 0;
    if(link == ACF_LINKTYPE_RADIOTAP) {
        if(size < 8) return;
        offset = acf_u16(packet + 2, false);
    } else if(link == ACF_LINKTYPE_PRISM) {
        if(size < 8) return;
        offset = acf_u32(packet + 4, false);
        if(offset < 8 || offset > 256) offset = 144;
    } else if(link == ACF_LINKTYPE_PPI) {
        if(size < 8) return;
        offset = acf_u16(packet + 2, false);
    }
    if(offset > size || size - offset < 2) return;

    const uint8_t* f = packet + offset;
    const size_t n = size - offset;
    uint16_t fc = acf_u16(f, false);
    uint8_t type = (fc >> 2) & 3U;
    uint8_t subtype = (fc >> 4) & 15U;
    if(type == 0) out->management_frames++;
    else if(type == 1) out->control_frames++;
    else if(type == 2) out->data_frames++;
    if(fc & 0x4000U) out->protected_frames++;

    /* Address fields below require a full management/data header. */
    if(n < 24) return;

    if(type == 0 && (subtype == 8 || subtype == 5) && n >= 36) {
        if(!out->has_bssid) {
            memcpy(out->first_bssid, f + 16, 6);
            out->has_bssid = true;
        }
        size_t pos = 36;
        while(pos + 2 <= n) {
            uint8_t id = f[pos++];
            uint8_t len = f[pos++];
            if(len > n - pos) break;
            if(id == 0 && len <= 32 && out->first_ssid[0] == '\0') {
                bool printable = true;
                for(uint8_t i = 0; i < len; i++) {
                    if(f[pos + i] < 0x20 || f[pos + i] > 0x7e) printable = false;
                }
                if(printable && len) {
                    memcpy(out->first_ssid, f + pos, len);
                    out->first_ssid[len] = '\0';
                }
            }
            pos += len;
        }
    }

    if(type == 2) {
        size_t header = 24;
        if((fc & 0x0300U) == 0x0300U) header += 6;
        if(subtype & 8U) {
            header += 2;
            if(fc & 0x8000U) header += 4;
        }
        static const uint8_t llc_eapol[8] = {0xaa, 0xaa, 0x03, 0, 0, 0, 0x88, 0x8e};
        if(header <= n && n - header >= sizeof(llc_eapol) &&
           memcmp(f + header, llc_eapol, sizeof(llc_eapol)) == 0) {
            out->eapol_frames++;
        }
    }
}

static AcfStatus acf_parse_pcap(AcfReader* r, volatile bool* cancel, AcfAnalysis* out) {
    uint8_t header[24];
    if(r->size(r->context) < sizeof(header)) return AcfStatusMalformed;
    if(!r->seek(r->context, 0) || !acf_read_exact(r, header, sizeof(header))) return AcfStatusIo;
    bool be;
    if((header[0] == 0xd4 && header[1] == 0xc3 && header[2] == 0xb2 && header[3] == 0xa1) ||
       (header[0] == 0x4d && header[1] == 0x3c && header[2] == 0xb2 && header[3] == 0xa1)) {
        be = false;
    } else if(
        (header[0] == 0xa1 && header[1] == 0xb2 && header[2] == 0xc3 && header[3] == 0xd4) ||
        (header[0] == 0xa1 && header[1] == 0xb2 && header[2] == 0x3c && header[3] == 0x4d)) {
        be = true;
    } else {
        return AcfStatusMalformed;
    }
    if(acf_u16(header + 4, be) != 2 || acf_u16(header + 6, be) != 4) return AcfStatusUnsupported;
    uint32_t snaplen = acf_u32(header + 16, be);
    out->link_type = acf_u32(header + 20, be);
    if(!acf_supported_link(out->link_type)) return AcfStatusUnsupported;
    if(snaplen == 0 || snaplen > ACF_MAX_CAPTURE_RECORD) return AcfStatusMalformed;

    uint8_t record[16];
    uint8_t packet[ACF_PACKET_PREFIX];
    const uint64_t file_size = r->size(r->context);
    while(r->tell(r->context) < file_size) {
        if(*cancel) return AcfStatusCancelled;
        uint64_t remaining = file_size - r->tell(r->context);
        if(remaining < sizeof(record)) return AcfStatusMalformed;
        if(!acf_read_exact(r, record, sizeof(record))) return AcfStatusIo;
        uint32_t captured = acf_u32(record + 8, be);
        uint32_t original = acf_u32(record + 12, be);
        if(captured > snaplen || captured > original || captured > ACF_MAX_CAPTURE_RECORD ||
           captured > file_size - r->tell(r->context)) {
            return AcfStatusMalformed;
        }
        size_t prefix = captured < sizeof(packet) ? captured : sizeof(packet);
        if(!acf_read_exact(r, packet, prefix)) return AcfStatusIo;
        if(captured > prefix && !acf_skip(r, captured - (uint32_t)prefix)) return AcfStatusIo;
        out->packets++;
        out->captured_bytes += captured;
        acf_parse_80211(packet, prefix, out->link_type, out);
    }
    return AcfStatusOk;
}

static AcfStatus acf_parse_ivs2(AcfReader* r, volatile bool* cancel, AcfAnalysis* out) {
    uint8_t file_header[6];
    if(r->size(r->context) < sizeof(file_header)) return AcfStatusMalformed;
    if(!r->seek(r->context, 0) || !acf_read_exact(r, file_header, sizeof(file_header)))
        return AcfStatusIo;
    if(acf_u16(file_header + 4, false) > 1) return AcfStatusUnsupported;
    const uint64_t file_size = r->size(r->context);
    uint8_t header[4];
    uint8_t prefix[40];
    while(r->tell(r->context) < file_size) {
        if(*cancel) return AcfStatusCancelled;
        if(file_size - r->tell(r->context) < sizeof(header) ||
           !acf_read_exact(r, header, sizeof(header)))
            return AcfStatusMalformed;
        uint16_t flags = acf_u16(header, false);
        uint16_t length = acf_u16(header + 2, false);
        uint16_t primary = flags & (ACF_IVS2_ESSID | ACF_IVS2_WPA | ACF_IVS2_XOR |
                                    ACF_IVS2_PTW | ACF_IVS2_CLR);
        if(!flags || (flags & ~ACF_IVS2_KNOWN_FLAGS) || (primary && (primary & (primary - 1U))))
            return AcfStatusMalformed;
        if(length > file_size - r->tell(r->context)) return AcfStatusMalformed;
        size_t payload_length = length;
        if(flags & ACF_IVS2_BSSID) {
            if(payload_length < 6U) return AcfStatusMalformed;
            payload_length -= 6U;
        }
        if((primary == 0 && payload_length != 0) ||
           (primary == ACF_IVS2_ESSID && (payload_length == 0 || payload_length > 32U)) ||
           (primary == ACF_IVS2_WPA && payload_length != ACF_IVS2_WPA_SIZE) ||
           (primary == ACF_IVS2_XOR && payload_length < 4U) ||
           ((primary == ACF_IVS2_PTW || primary == ACF_IVS2_CLR) && payload_length == 0))
            return AcfStatusMalformed;
        size_t take = length < sizeof(prefix) ? length : sizeof(prefix);
        if(!acf_read_exact(r, prefix, take)) return AcfStatusIo;
        if(length > take && !acf_skip(r, length - (uint32_t)take)) return AcfStatusIo;
        out->ivs2_records++;
        if(flags & ACF_IVS2_WPA) out->ivs2_wpa_records++;
        size_t pos = 0;
        if((flags & ACF_IVS2_BSSID) && length >= 6) {
            if(!out->has_bssid) memcpy(out->first_bssid, prefix, 6);
            out->has_bssid = true;
            pos = 6;
        }
        if((flags & ACF_IVS2_ESSID) && pos < take && out->first_ssid[0] == '\0') {
            size_t len = take - pos;
            if(len > 32) len = 32;
            bool printable = true;
            for(size_t i = 0; i < len; i++) {
                if(prefix[pos + i] < 0x20 || prefix[pos + i] > 0x7e) printable = false;
            }
            if(printable) {
                memcpy(out->first_ssid, prefix + pos, len);
                out->first_ssid[len] = '\0';
            }
        }
    }
    return AcfStatusOk;
}

static AcfStatus acf_parse_pcapng(AcfReader* r, volatile bool* cancel, AcfAnalysis* out) {
    uint8_t header[12];
    if(r->size(r->context) < sizeof(header)) return AcfStatusMalformed;
    if(!r->seek(r->context, 0) || !acf_read_exact(r, header, sizeof(header))) return AcfStatusIo;
    bool be;
    if(header[8] == 0x4d && header[9] == 0x3c && header[10] == 0x2b && header[11] == 0x1a)
        be = false;
    else if(header[8] == 0x1a && header[9] == 0x2b && header[10] == 0x3c && header[11] == 0x4d)
        be = true;
    else
        return AcfStatusMalformed;
    if(!r->seek(r->context, 0)) return AcfStatusIo;
    const uint64_t file_size = r->size(r->context);
    uint32_t interface_links[8] = {0};
    uint32_t interface_snaplens[8] = {0};
    uint8_t interface_count = 0;
    uint8_t block_header[8];
    uint8_t packet[ACF_PACKET_PREFIX];
    while(r->tell(r->context) < file_size) {
        if(*cancel) return AcfStatusCancelled;
        uint64_t block_start = r->tell(r->context);
        if(file_size - block_start < 12 || !acf_read_exact(r, block_header, 8))
            return AcfStatusMalformed;
        bool is_section = block_header[0] == 0x0a && block_header[1] == 0x0d &&
                          block_header[2] == 0x0d && block_header[3] == 0x0a;
        uint32_t type = is_section ? 0x0A0D0D0AU : acf_u32(block_header, be);
        uint32_t length;
        if(is_section) {
            uint8_t bom[4];
            if(!acf_read_exact(r, bom, 4)) return AcfStatusIo;
            if(bom[0] == 0x4d && bom[1] == 0x3c && bom[2] == 0x2b && bom[3] == 0x1a)
                be = false;
            else if(bom[0] == 0x1a && bom[1] == 0x2b && bom[2] == 0x3c && bom[3] == 0x4d)
                be = true;
            else
                return AcfStatusMalformed;
            length = acf_u32(block_header + 4, be);
        } else {
            length = acf_u32(block_header + 4, be);
        }
        if(length < 12 || (length & 3U) || length > ACF_MAX_CAPTURE_RECORD ||
           length > file_size - block_start)
            return AcfStatusMalformed;
        if(type == 0x0A0D0D0AU) {
            uint8_t version[4];
            if(length < 28U) return AcfStatusMalformed;
            if(!acf_read_exact(r, version, sizeof(version))) return AcfStatusIo;
            if(acf_u16(version, be) != 1U || acf_u16(version + 2, be) != 0U)
                return AcfStatusUnsupported;
            interface_count = 0;
        } else if(type == 1U && length >= 20) {
            uint8_t body[8];
            if(!acf_read_exact(r, body, sizeof(body))) return AcfStatusIo;
            uint32_t link = acf_u16(body, be);
            uint32_t snaplen = acf_u32(body + 4, be);
            if(body[2] || body[3] || !snaplen || snaplen > ACF_MAX_CAPTURE_RECORD)
                return AcfStatusMalformed;
            if(!acf_supported_link(link)) return AcfStatusUnsupported;
            if(interface_count >= 8) return AcfStatusUnsupported;
            interface_links[interface_count] = link;
            interface_snaplens[interface_count++] = snaplen;
        } else if(type == 6U && length >= 32) {
            uint8_t body[20];
            if(!acf_read_exact(r, body, sizeof(body))) return AcfStatusIo;
            uint32_t interface_id = acf_u32(body, be);
            uint32_t captured = acf_u32(body + 12, be);
            uint32_t original = acf_u32(body + 16, be);
            if(interface_id >= interface_count || captured > original ||
               captured > interface_snaplens[interface_id] ||
               captured > length - 32U)
                return AcfStatusMalformed;
            uint32_t link = interface_links[interface_id];
            if(!acf_supported_link(link)) return AcfStatusUnsupported;
            size_t prefix = captured < sizeof(packet) ? captured : sizeof(packet);
            if(!acf_read_exact(r, packet, prefix)) return AcfStatusIo;
            out->packets++;
            out->captured_bytes += captured;
            out->link_type = link;
            acf_parse_80211(packet, prefix, link, out);
        }
        uint64_t expected_end = block_start + length;
        if(expected_end > UINT32_MAX || !r->seek(r->context, (uint32_t)(expected_end - 4)))
            return AcfStatusIo;
        uint8_t trailer[4];
        if(!acf_read_exact(r, trailer, 4) || acf_u32(trailer, be) != length)
            return AcfStatusMalformed;
    }
    return interface_count || out->packets ? AcfStatusOk : AcfStatusMalformed;
}

AcfStatus acf_analyze(AcfReader* reader, volatile bool* cancel, AcfAnalysis* result) {
    if(!reader || !reader->read || !reader->seek || !reader->tell || !reader->size || !cancel ||
       !result)
        return AcfStatusMalformed;
    memset(result, 0, sizeof(*result));
    uint8_t magic[4];
    if(reader->size(reader->context) < 4) return AcfStatusMalformed;
    if(!reader->seek(reader->context, 0) || !acf_read_exact(reader, magic, sizeof(magic)))
        return AcfStatusIo;
    if(magic[0] == 0xae && magic[1] == 0x78 && magic[2] == 0xd1 && magic[3] == 0xff) {
        result->format = AcfFormatIvs2;
        return acf_parse_ivs2(reader, cancel, result);
    }
    if(magic[0] == 0x0a && magic[1] == 0x0d && magic[2] == 0x0d && magic[3] == 0x0a) {
        result->format = AcfFormatPcapNg;
        return acf_parse_pcapng(reader, cancel, result);
    }
    result->format = AcfFormatPcap;
    return acf_parse_pcap(reader, cancel, result);
}

const char* acf_status_name(AcfStatus status) {
    static const char* names[] = {"OK", "Cancelled", "I/O error", "Malformed", "Unsupported"};
    return status <= AcfStatusUnsupported ? names[status] : "Unknown";
}

const char* acf_format_name(AcfFormat format) {
    static const char* names[] = {"Unknown", "PCAP", "PCAPNG", "IVS2"};
    return format <= AcfFormatIvs2 ? names[format] : "Unknown";
}
