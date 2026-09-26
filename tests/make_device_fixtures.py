#!/usr/bin/env python3
"""Convert genuine PCAP packets to PCAPNG and IVS2 device-test containers."""

from pathlib import Path
import struct
import sys


def read_pcap(path: Path):
    data = path.read_bytes()
    if len(data) < 24:
        raise ValueError("truncated PCAP header")
    magic = data[:4]
    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", False),
        b"\xa1\xb2\xc3\xd4": (">", False),
        b"\x4d\x3c\xb2\xa1": ("<", True),
        b"\xa1\xb2\x3c\x4d": (">", True),
    }
    if magic not in formats:
        raise ValueError("unsupported PCAP magic")
    endian, nanoseconds = formats[magic]
    major, minor = struct.unpack_from(endian + "HH", data, 4)
    if (major, minor) != (2, 4):
        raise ValueError("unsupported PCAP version")
    snaplen, linktype = struct.unpack_from(endian + "II", data, 16)
    records = []
    offset = 24
    while offset < len(data):
        if len(data) - offset < 16:
            raise ValueError("truncated PCAP record")
        seconds, fraction, captured, original = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        if captured > snaplen or captured > original or captured > len(data) - offset:
            raise ValueError("invalid PCAP record length")
        records.append((seconds, fraction, original, data[offset : offset + captured]))
        offset += captured
    return linktype, snaplen, nanoseconds, records


def pcapng_block(block_type: int, body: bytes) -> bytes:
    padded = body + bytes((-len(body)) & 3)
    length = 12 + len(padded)
    return struct.pack("<II", block_type, length) + padded + struct.pack("<I", length)


def write_pcapng(path: Path, linktype: int, snaplen: int, nanoseconds: bool, records) -> None:
    section = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    interface = struct.pack("<HHI", linktype, 0, snaplen)
    output = bytearray(pcapng_block(0x0A0D0D0A, section))
    output += pcapng_block(1, interface)
    for seconds, fraction, original, packet in records:
        timestamp = seconds * 1_000_000 + (fraction // 1000 if nanoseconds else fraction)
        body = struct.pack(
            "<IIIII", 0, timestamp >> 32, timestamp & 0xFFFFFFFF, len(packet), original
        ) + packet
        output += pcapng_block(6, body)
    path.write_bytes(output)


def ieee80211_payload(packet: bytes, linktype: int) -> bytes:
    if linktype == 105:
        offset = 0
    elif linktype == 119:
        if len(packet) < 8:
            return b""
        offset = struct.unpack_from("<I", packet, 4)[0]
        if offset < 8 or offset > 256:
            offset = 144
    elif linktype in (127, 192):
        if len(packet) < 8:
            return b""
        offset = struct.unpack_from("<H", packet, 2)[0]
    else:
        raise ValueError(f"unsupported link type {linktype}")
    return packet[offset:] if offset <= len(packet) else b""


def find_network(linktype: int, records):
    for _seconds, _fraction, _original, packet in records:
        frame = ieee80211_payload(packet, linktype)
        if len(frame) < 36:
            continue
        frame_control = struct.unpack_from("<H", frame)[0]
        frame_type = (frame_control >> 2) & 3
        subtype = (frame_control >> 4) & 15
        if frame_type != 0 or subtype not in (5, 8):
            continue
        position = 36
        while position + 2 <= len(frame):
            element_id, length = frame[position], frame[position + 1]
            position += 2
            if length > len(frame) - position:
                break
            if element_id == 0 and 0 < length <= 32:
                ssid = frame[position : position + length]
                if all(0x20 <= value <= 0x7E for value in ssid):
                    return frame[16:22], ssid
            position += length
    raise ValueError("capture has no printable beacon/probe-response SSID")


def write_ivs2(path: Path, bssid: bytes, ssid: bytes) -> None:
    payload = bssid + ssid
    path.write_bytes(b"\xae\x78\xd1\xff" + struct.pack("<H", 1) + struct.pack("<HH", 3, len(payload)) + payload)


def write_stress_pcap(path: Path, linktype: int, snaplen: int, records) -> None:
    """Repeat genuine records to exercise streaming/cancellation; never a capture claim."""
    output = bytearray(b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, snaplen, linktype))
    for index in range(50_000):
        seconds, fraction, original, packet = records[index % len(records)]
        output += struct.pack("<IIII", seconds, fraction, len(packet), original)
        output += packet
    path.write_bytes(output)


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: make_device_fixtures.py INPUT.pcap OUTPUT_DIRECTORY")
    source = Path(sys.argv[1])
    output = Path(sys.argv[2])
    output.mkdir(parents=True, exist_ok=True)
    linktype, snaplen, nanoseconds, records = read_pcap(source)
    write_pcapng(output / "upstream_wpa.pcapng", linktype, snaplen, nanoseconds, records)
    bssid, ssid = find_network(linktype, records)
    write_ivs2(output / "upstream_wpa.ivs", bssid, ssid)
    write_stress_pcap(output / "upstream_wpa_stress.cap", linktype, snaplen, records)
    (output / "upstream_wpa_truncated.cap").write_bytes(source.read_bytes()[:30])
    print(f"Converted {len(records)} genuine packets; IVS2 SSID={ssid.decode('ascii')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
