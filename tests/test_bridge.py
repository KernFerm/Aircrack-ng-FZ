#!/usr/bin/env python3
"""Host checks for real capture counter extraction in the Linux bridge."""

import importlib.util
from pathlib import Path
import sys
import unittest

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


if __name__ == "__main__":
    unittest.main()
