#!/usr/bin/env python3
"""Host checks for real capture counter extraction in the Linux bridge."""

import importlib.util
import io
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "companion" / "aircrack_fz_bridge.py"
SPEC = importlib.util.spec_from_file_location("aircrack_fz_bridge", MODULE_PATH)
assert SPEC and SPEC.loader
BRIDGE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BRIDGE
SPEC.loader.exec_module(BRIDGE)


class BridgeParserTests(unittest.TestCase):
    def test_raw_80211_eapol_is_counted(self) -> None:
        frame = bytearray(24)
        frame[0] = 0x08
        frame.extend(b"\xaa\xaa\x03\x00\x00\x00\x88\x8e")
        counters = BRIDGE.Counters()
        BRIDGE.classify(bytes(frame), 105, counters)
        self.assertEqual(counters.data, 1)
        self.assertEqual(counters.eapol, 1)

    def test_radiotap_management_is_counted(self) -> None:
        radiotap = b"\x00\x00\x08\x00\x00\x00\x00\x00"
        beacon = b"\x80\x00" + bytes(22)
        counters = BRIDGE.Counters()
        BRIDGE.classify(radiotap + beacon, 127, counters)
        self.assertEqual(counters.management, 1)
        self.assertEqual(counters.data, 0)

    def test_unknown_link_type_is_not_invented(self) -> None:
        counters = BRIDGE.Counters()
        BRIDGE.classify(bytes(64), 1, counters)
        self.assertEqual(counters, BRIDGE.Counters())

    def test_protocol_token_is_ascii_and_bounded(self) -> None:
        self.assertEqual(BRIDGE.token("Aircrack ng!", 20), "Aircrack_ng_")
        self.assertEqual(len(BRIDGE.token("x" * 100, 12)), 12)

    def test_capture_reader_reports_invalid_header(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.cap"
            path.write_bytes(bytes(24))
            reader = BRIDGE.CaptureReader(
                path, threading.Event(), BRIDGE.Counters(), threading.Lock()
            )
            reader.start()
            reader.join(timeout=2)
            self.assertFalse(reader.is_alive())
            self.assertEqual(reader.error, "CAPTURE_FORMAT_INVALID")

    def test_status_propagates_airodump_stderr(self) -> None:
        class ExitedProcess:
            returncode = 2

            @staticmethod
            def poll() -> int:
                return 2

        class Uart:
            def __init__(self) -> None:
                self.data = bytearray()

            def write(self, data: bytes) -> int:
                self.data.extend(data)
                return len(data)

            @staticmethod
            def flush() -> None:
                return None

        bridge = BRIDGE.Bridge("wlan1mon", "/dev/serial0", 115200, Path("/tmp/captures"))
        bridge.process = ExitedProcess()
        bridge.stderr_reader = BRIDGE.StderrTail(io.BytesIO(b"permission denied by wireless driver"))
        bridge.stderr_reader.start()
        bridge.stderr_reader.join(timeout=2)
        bridge.state = "CAPTURING"
        uart = Uart()
        bridge.status(uart)
        output = uart.data.decode("ascii")
        self.assertIn("ACF1 ERROR permission_denied_by_wireless_driver", output)
        self.assertIn("ACF1 STATUS ERROR", output)
        bridge.close_stderr()

    def test_stderr_tail_is_memory_bounded(self) -> None:
        reader = BRIDGE.StderrTail(io.BytesIO(b"x" * 10000), limit=4096)
        reader.start()
        reader.join(timeout=2)
        self.assertFalse(reader.is_alive())
        self.assertEqual(len(reader.buffer), 4096)

    def test_capture_directory_failure_is_bounded(self) -> None:
        class Uart:
            def __init__(self) -> None:
                self.data = bytearray()

            def write(self, data: bytes) -> int:
                self.data.extend(data)
                return len(data)

            @staticmethod
            def flush() -> None:
                return None

        bridge = BRIDGE.Bridge("wlan1mon", "/dev/serial0", 115200, Path("/blocked"))
        bridge.airodump = "/usr/bin/airodump-ng"
        bridge.aircrack = "/usr/bin/aircrack-ng"
        uart = Uart()
        with mock.patch.object(bridge, "monitor_mode_ready", return_value=True), mock.patch.object(
            BRIDGE.Path, "mkdir", side_effect=PermissionError("blocked")
        ):
            bridge.start_capture(uart, 6)
        self.assertEqual(bridge.state, "ERROR")
        self.assertIn(b"ACF1 ERROR CAPTURE_DIRECTORY_PermissionError", uart.data)

    def test_failed_process_stop_is_reported(self) -> None:
        class StubbornProcess:
            returncode = None

            @staticmethod
            def poll() -> None:
                return None

            @staticmethod
            def send_signal(_signal: int) -> None:
                return None

            @staticmethod
            def kill() -> None:
                return None

            @staticmethod
            def wait(timeout: int) -> None:
                raise BRIDGE.subprocess.TimeoutExpired("airodump-ng", timeout)

        bridge = BRIDGE.Bridge("wlan1mon", "/dev/serial0", 115200, Path("/tmp/captures"))
        bridge.process = StubbornProcess()
        self.assertFalse(bridge.stop_capture())
        self.assertEqual(bridge.state, "ERROR")
        self.assertEqual(bridge.error, "CAPTURE_STOP_FAILED")


if __name__ == "__main__":
    unittest.main()
