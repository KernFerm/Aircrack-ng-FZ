#!/usr/bin/env python3
"""UART bridge between Aircrack-ng FZ and genuine Aircrack-ng on Linux."""

from __future__ import annotations

import argparse
import re
import shutil
import signal
import struct
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import serial

BRIDGE_VERSION = "1.0.5"
PROTOCOL_VERSION = 1
MAX_LINE = 192
MAX_PACKET = 16 * 1024 * 1024
INTERFACE_RE = re.compile(r"[A-Za-z0-9_.-]{1,32}\Z")
SERIAL_RE = re.compile(r"/dev/(serial[0-9]+|tty(?:AMA|USB|ACM|S)[0-9]+)\Z")


def token(value: object, limit: int) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_./:+-]", "_", str(value))
    return (cleaned or "-")[:limit]


@dataclass
class Counters:
    packets: int = 0
    byte_count: int = 0
    management: int = 0
    data: int = 0
    control: int = 0
    eapol: int = 0
    dropped: int = 0


def radiotap_offset(packet: bytes, dlt: int) -> int | None:
    if dlt == 105:
        return 0
    if dlt == 127 and len(packet) >= 4:
        length = struct.unpack_from("<H", packet, 2)[0]
        return length if 4 <= length <= len(packet) else None
    if dlt == 119 and len(packet) >= 8:
        length = struct.unpack_from("<I", packet, 4)[0]
        return length if 8 <= length <= len(packet) else None
    if dlt == 192 and len(packet) >= 8:
        length = struct.unpack_from("<H", packet, 2)[0]
        return length if 8 <= length <= len(packet) else None
    return None


def classify(packet: bytes, dlt: int, counters: Counters) -> None:
    offset = radiotap_offset(packet, dlt)
    if offset is None or len(packet) - offset < 2:
        return
    frame = packet[offset:]
    frame_control = struct.unpack_from("<H", frame, 0)[0]
    frame_type = (frame_control >> 2) & 3
    if frame_type == 0:
        counters.management += 1
    elif frame_type == 1:
        counters.control += 1
    elif frame_type == 2:
        counters.data += 1
        to_ds = bool(frame_control & 0x0100)
        from_ds = bool(frame_control & 0x0200)
        qos = bool(frame_control & 0x0080)
        header_length = 30 if to_ds and from_ds else 24
        if qos:
            header_length += 2
        if frame_control & 0x8000:
            header_length += 4
        if len(frame) >= header_length + 8:
            llc = frame[header_length : header_length + 8]
            if llc[:3] == b"\xaa\xaa\x03" and llc[6:8] == b"\x88\x8e":
                counters.eapol += 1


class CaptureReader(threading.Thread):
    def __init__(self, path: Path, stop_event: threading.Event, counters: Counters, lock: threading.Lock):
        super().__init__(name="pcap-reader", daemon=True)
        self.path = path
        self.stop_event = stop_event
        self.counters = counters
        self.lock = lock

    def run(self) -> None:
        while not self.stop_event.is_set() and not self.path.exists():
            self.stop_event.wait(0.1)
        while not self.stop_event.is_set():
            try:
                if self.path.stat().st_size >= 24:
                    break
            except OSError:
                pass
            self.stop_event.wait(0.1)
        if self.stop_event.is_set():
            return
        try:
            with self.path.open("rb") as capture:
                header = capture.read(24)
                if len(header) != 24:
                    return
                magic = header[:4]
                if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
                    endian = "<"
                elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
                    endian = ">"
                else:
                    return
                dlt = struct.unpack_from(endian + "I", header, 20)[0]
                while not self.stop_event.is_set():
                    position = capture.tell()
                    record = capture.read(16)
                    if len(record) != 16:
                        capture.seek(position)
                        self.stop_event.wait(0.1)
                        continue
                    captured_length = struct.unpack_from(endian + "I", record, 8)[0]
                    if captured_length > MAX_PACKET:
                        return
                    packet = capture.read(captured_length)
                    if len(packet) != captured_length:
                        capture.seek(position)
                        self.stop_event.wait(0.1)
                        continue
                    with self.lock:
                        self.counters.packets += 1
                        self.counters.byte_count += captured_length
                        classify(packet, dlt, self.counters)
        except OSError:
            return


class Bridge:
    def __init__(self, interface: str, port: str, baud: int, capture_dir: Path):
        self.interface = interface
        self.port = port
        self.baud = baud
        self.capture_dir = capture_dir
        self.airodump = shutil.which("airodump-ng")
        self.aircrack = shutil.which("aircrack-ng")
        self.aircrack_version = self._aircrack_version()
        self.process: subprocess.Popen[bytes] | None = None
        self.reader: CaptureReader | None = None
        self.reader_stop = threading.Event()
        self.lock = threading.Lock()
        self.counters = Counters()
        self.state = "IDLE"
        self.channel = 0
        self.capture_path = capture_dir

    def _aircrack_version(self) -> str:
        if not self.aircrack:
            return "missing"
        try:
            result = subprocess.run(
                [self.aircrack, "--help"],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired):
            return "unknown"
        match = re.search(r"Aircrack-ng\s+([0-9][A-Za-z0-9_.+-]*)", result.stdout)
        return match.group(1) if match else "unknown"

    def write(self, uart: serial.Serial, line: str) -> None:
        uart.write((line[: MAX_LINE - 2] + "\n").encode("ascii", "strict"))
        uart.flush()

    def info(self, uart: serial.Serial) -> None:
        self.write(
            uart,
            f"ACF1 INFO {PROTOCOL_VERSION} {BRIDGE_VERSION} "
            f"{token(self.aircrack_version, 31)} {token(self.interface, 23)} "
            f"{token(self.capture_path, 79)}",
        )

    def status(self, uart: serial.Serial) -> None:
        if self.process and self.process.poll() is not None and self.state == "CAPTURING":
            self.state = "ERROR"
        with self.lock:
            c = Counters(**vars(self.counters))
        self.write(
            uart,
            f"ACF1 STATUS {self.state} {self.channel} {c.packets} {c.byte_count} "
            f"{c.management} {c.data} {c.control} {c.eapol} {c.dropped} END",
        )

    def monitor_mode_ready(self) -> bool:
        iw = shutil.which("iw")
        if not iw:
            return False
        result = subprocess.run(
            [iw, "dev", self.interface, "info"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )
        return result.returncode == 0 and re.search(r"^\s*type\s+monitor\s*$", result.stdout, re.MULTILINE) is not None

    def start_capture(self, uart: serial.Serial, channel: int) -> None:
        if self.process and self.process.poll() is None:
            self.write(uart, "ACF1 ERROR ALREADY_CAPTURING")
            return
        if not self.airodump or not self.aircrack:
            self.write(uart, "ACF1 ERROR AIRCRACK_NOT_INSTALLED")
            return
        try:
            if not self.monitor_mode_ready():
                self.write(uart, "ACF1 ERROR INTERFACE_NOT_MONITOR")
                return
        except (OSError, subprocess.TimeoutExpired):
            self.write(uart, "ACF1 ERROR INTERFACE_CHECK_FAILED")
            return
        self.capture_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        prefix = self.capture_dir / f"acf-{stamp}"
        capture = Path(f"{prefix}-01.cap")
        with self.lock:
            self.counters = Counters()
        self.reader_stop.clear()
        self.channel = channel
        self.capture_path = capture
        self.state = "STARTING"
        try:
            self.process = subprocess.Popen(
                [
                    self.airodump,
                    "--channel",
                    str(channel),
                    "--write-interval",
                    "1",
                    "--output-format",
                    "pcap",
                    "--write",
                    str(prefix),
                    self.interface,
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError:
            self.state = "ERROR"
            self.write(uart, "ACF1 ERROR AIRODUMP_START_FAILED")
            return
        time.sleep(0.25)
        if self.process.poll() is not None:
            self.state = "ERROR"
            self.write(uart, "ACF1 ERROR AIRODUMP_EXITED")
            return
        self.reader = CaptureReader(capture, self.reader_stop, self.counters, self.lock)
        self.reader.start()
        self.state = "CAPTURING"
        self.info(uart)
        self.status(uart)

    def stop_capture(self) -> None:
        self.reader_stop.set()
        process = self.process
        if process and process.poll() is None:
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        if self.reader:
            self.reader.join(timeout=2)
        self.reader = None
        self.process = None
        self.state = "IDLE"
        self.channel = 0

    def handle(self, uart: serial.Serial, text: str) -> None:
        fields = text.split()
        if fields == ["ACF1", "HELLO"]:
            self.info(uart)
            self.status(uart)
        elif fields == ["ACF1", "STATUS"]:
            self.status(uart)
        elif fields == ["ACF1", "STOP"]:
            self.stop_capture()
            self.status(uart)
        elif len(fields) == 3 and fields[:2] == ["ACF1", "START"] and fields[2].isdigit():
            channel = int(fields[2])
            if 1 <= channel <= 13:
                self.start_capture(uart, channel)
            else:
                self.write(uart, "ACF1 ERROR INVALID_CHANNEL")
        else:
            self.write(uart, "ACF1 ERROR INVALID_COMMAND")

    def run(self) -> None:
        self.capture_dir.mkdir(parents=True, exist_ok=True)
        try:
            with serial.Serial(self.port, self.baud, timeout=0.5, write_timeout=2) as uart:
                while True:
                    raw = uart.readline(MAX_LINE)
                    if not raw:
                        continue
                    if len(raw) >= MAX_LINE and not raw.endswith(b"\n"):
                        uart.reset_input_buffer()
                        self.write(uart, "ACF1 ERROR LINE_TOO_LONG")
                        continue
                    try:
                        text = raw.decode("ascii").strip()
                    except UnicodeDecodeError:
                        self.write(uart, "ACF1 ERROR NON_ASCII")
                        continue
                    self.handle(uart, text)
        finally:
            self.stop_capture()


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", required=True, help="existing monitor-mode interface, e.g. wlan1mon")
    parser.add_argument("--serial", default="/dev/serial0", help="3.3 V UART device")
    parser.add_argument("--baud", type=int, choices=(115200, 230400, 460800), default=115200)
    parser.add_argument("--capture-dir", type=Path, default=Path("/var/lib/aircrack-fz/captures"))
    args = parser.parse_args()
    if not INTERFACE_RE.fullmatch(args.interface):
        parser.error("invalid interface name")
    if not SERIAL_RE.fullmatch(args.serial):
        parser.error("serial device must be a supported /dev UART")
    args.capture_dir = args.capture_dir.expanduser().resolve()
    if not args.capture_dir.is_absolute():
        parser.error("capture directory must be absolute")
    return args


def main() -> int:
    args = arguments()
    Bridge(args.interface, args.serial, args.baud, args.capture_dir).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
