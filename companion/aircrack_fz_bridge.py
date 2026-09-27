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

BRIDGE_VERSION = "1.0.6"
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


class StderrTail(threading.Thread):
    def __init__(self, stream, limit: int = 4096):
        super().__init__(name="airodump-stderr", daemon=True)
        self.stream = stream
        self.limit = limit
        self.buffer = bytearray()
        self.lock = threading.Lock()

    def run(self) -> None:
        try:
            while True:
                chunk = self.stream.read(256)
                if not chunk:
                    break
                with self.lock:
                    self.buffer.extend(chunk)
                    if len(self.buffer) > self.limit:
                        del self.buffer[: len(self.buffer) - self.limit]
        except (OSError, ValueError):
            pass

    def text(self) -> str:
        with self.lock:
            data = bytes(self.buffer)
        return data.decode("utf-8", "replace")

    def close(self) -> None:
        try:
            self.stream.close()
        except OSError:
            pass
        self.join(timeout=2)


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
        self.error: str | None = None

    def fail(self, message: object) -> None:
        self.error = token(message, 63)

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
                    self.fail("CAPTURE_HEADER_TRUNCATED")
                    return
                magic = header[:4]
                if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
                    endian = "<"
                elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
                    endian = ">"
                else:
                    self.fail("CAPTURE_FORMAT_INVALID")
                    return
                snaplen = struct.unpack_from(endian + "I", header, 16)[0]
                dlt = struct.unpack_from(endian + "I", header, 20)[0]
                if not snaplen or snaplen > MAX_PACKET:
                    self.fail("CAPTURE_SNAPLEN_INVALID")
                    return
                if dlt not in (105, 119, 127, 192):
                    self.fail("CAPTURE_LINKTYPE_UNSUPPORTED")
                    return
                while not self.stop_event.is_set():
                    position = capture.tell()
                    record = capture.read(16)
                    if len(record) != 16:
                        capture.seek(position)
                        self.stop_event.wait(0.1)
                        continue
                    captured_length = struct.unpack_from(endian + "I", record, 8)[0]
                    original_length = struct.unpack_from(endian + "I", record, 12)[0]
                    if captured_length > snaplen or captured_length > original_length:
                        self.fail("CAPTURE_PACKET_LENGTH_INVALID")
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
        except OSError as error:
            self.fail(f"CAPTURE_READ_{error.__class__.__name__}")


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
        self.stderr_reader: StderrTail | None = None
        self.reader: CaptureReader | None = None
        self.reader_stop = threading.Event()
        self.lock = threading.Lock()
        self.counters = Counters()
        self.state = "IDLE"
        self.error = ""
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
        self.refresh_capture_state()
        if self.error:
            self.write(uart, f"ACF1 ERROR {token(self.error, 63)}")
        with self.lock:
            c = Counters(**vars(self.counters))
        self.write(
            uart,
            f"ACF1 STATUS {self.state} {self.channel} {c.packets} {c.byte_count} "
            f"{c.management} {c.data} {c.control} {c.eapol} {c.dropped} END",
        )

    def stderr_tail(self) -> str:
        return token(self.stderr_reader.text(), 63) if self.stderr_reader else ""

    def close_stderr(self) -> None:
        if self.stderr_reader:
            self.stderr_reader.close()
            self.stderr_reader = None

    def refresh_capture_state(self) -> None:
        if self.reader and self.reader.error and self.state in ("STARTING", "CAPTURING"):
            self.error = self.reader.error
            self.state = "ERROR"
        if self.process and self.process.poll() is not None and self.state in ("STARTING", "CAPTURING"):
            code = self.process.returncode
            if self.stderr_reader:
                self.stderr_reader.join(timeout=1)
            detail = self.stderr_tail()
            self.error = detail or f"AIRODUMP_EXIT_{code}"
            self.state = "ERROR"
            self.reader_stop.set()

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
        self.refresh_capture_state()
        if self.process and self.process.poll() is None:
            if self.state in ("STARTING", "CAPTURING"):
                self.write(uart, "ACF1 ERROR ALREADY_CAPTURING")
                return
            if not self.stop_capture():
                self.write(uart, f"ACF1 ERROR {token(self.error or 'PREVIOUS_CAPTURE_STOP_FAILED', 63)}")
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
        if self.process or self.reader:
            if not self.stop_capture():
                self.write(uart, f"ACF1 ERROR {token(self.error or 'PREVIOUS_CAPTURE_STOP_FAILED', 63)}")
                return
        try:
            self.capture_dir.mkdir(parents=True, exist_ok=True)
        except OSError as error:
            self.error = f"CAPTURE_DIRECTORY_{error.__class__.__name__}"
            self.state = "ERROR"
            self.write(uart, f"ACF1 ERROR {token(self.error, 63)}")
            return
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        prefix = self.capture_dir / f"acf-{stamp}"
        suffix = 0
        while any(self.capture_dir.glob(f"{prefix.name}-*")):
            suffix += 1
            prefix = self.capture_dir / f"acf-{stamp}-{suffix}"
        capture = Path(f"{prefix}-01.cap")
        with self.lock:
            self.counters = Counters()
        self.reader_stop.clear()
        self.channel = channel
        self.capture_path = capture
        self.state = "STARTING"
        self.error = ""
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
                stderr=subprocess.PIPE,
            )
            if self.process.stderr:
                self.stderr_reader = StderrTail(self.process.stderr)
                self.stderr_reader.start()
        except OSError as error:
            self.close_stderr()
            self.state = "ERROR"
            self.error = f"AIRODUMP_START_{error.__class__.__name__}"
            self.write(uart, f"ACF1 ERROR {token(self.error, 63)}")
            return
        time.sleep(0.25)
        if self.process.poll() is not None:
            self.refresh_capture_state()
            self.write(uart, f"ACF1 ERROR {token(self.error or 'AIRODUMP_EXITED', 63)}")
            return
        self.reader = CaptureReader(capture, self.reader_stop, self.counters, self.lock)
        self.reader.start()
        self.state = "CAPTURING"
        self.info(uart)
        self.status(uart)

    def stop_capture(self) -> bool:
        self.reader_stop.set()
        process = self.process
        failed = False
        if process and process.poll() is None:
            try:
                process.send_signal(signal.SIGINT)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                failed = True
        if self.reader:
            self.reader.join(timeout=2)
            if self.reader.is_alive():
                failed = True
        if process and process.poll() is None:
            failed = True
        if not failed:
            self.reader = None
            self.process = None
            self.close_stderr()
            self.state = "IDLE"
            self.error = ""
            self.channel = 0
        else:
            self.state = "ERROR"
            self.error = "CAPTURE_STOP_FAILED"
        return not failed

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
        try:
            self.capture_dir.mkdir(parents=True, exist_ok=True)
        except OSError as error:
            raise RuntimeError(
                f"cannot create capture directory {self.capture_dir}: {error}"
            ) from error
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
