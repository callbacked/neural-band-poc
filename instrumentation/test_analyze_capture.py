"""CLI checks using synthetic public setup fields, never captured device secrets."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


class CaptureAnalysisTests(unittest.TestCase):
    def run_capture(self, chunks, sequence_gap=False):
        peer = {"name": "Meta Band test", "identifier": "synthetic"}
        events = [{"event": "recorder_ready", "sequence": 0},
                  {"event": "channel_open", "sequence": 1, "peer": peer, "channel": "1"}]
        for direction in ("tx", "rx"):
            for chunk in chunks:
                events.append({"event": "stream_bytes", "sequence": len(events), "timestamp": "test",
                               "peer": peer, "channel": "1", "direction": direction,
                               "count": len(chunk), "hex": chunk.hex()})
        if sequence_gap:
            events[-1]["sequence"] += 1
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.log"
            path.write_text("\n".join(json.dumps(event) for event in events))
            result = subprocess.run([sys.executable, str(Path(__file__).with_name("analyze_capture.py")), str(path)],
                                    capture_output=True, text=True, check=False)
            return result.returncode, json.loads(result.stdout)

    @staticmethod
    def frames():
        key = ec.derive_private_key(1, ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)[1:]
        request = b"\x0a\x40" + key + b"\x12\x10" + bytes(16) + b"\x18\x00\x20\x03\x38\x10"
        enable = b"\x0a\x40" + key + b"\x12\x20" + bytes(32) + b"\x1a\x10" + bytes(16) + b"\x20\xac\x02\x28\x03"
        def frame(payload, header):
            body = header + payload
            return (0x8000 | len(body)).to_bytes(2, "big") + b"\x00\x01" + body
        return frame(request, b"\x02\x00\x00\x01"), frame(enable, b"\x02\x00\x00\x02")

    def test_fragmented_and_coalesced_setup(self):
        request, enable = self.frames()
        data = request + enable + b"\x40\x80encrypted-placeholder"
        status, result = self.run_capture([data[:1], data[1:5], data[5:79], data[79:]])
        self.assertEqual((status, result["errors"]), (0, []))
        self.assertEqual([row["message"] for row in result["setup"]],
                         ["RequestEncryption", "EnableEncryption"] * 2)
        self.assertIn({"number": 7, "wire": 0, "value": 16}, result["setup"][0]["fields"])
        self.assertIn({"number": 4, "wire": 0, "value": 300}, result["setup"][1]["fields"])

    def test_sequence_gap_fails(self):
        status, result = self.run_capture(list(self.frames()), sequence_gap=True)
        self.assertEqual(status, 1)
        self.assertTrue(any("sequence" in error for error in result["errors"]))

    def test_truncated_exchange_fails(self):
        request, enable = self.frames()
        status, result = self.run_capture([request, enable[:-1]])
        self.assertEqual(status, 1)
        self.assertTrue(any("incomplete initial exchange" in error for error in result["errors"]))

    def test_enable_without_request_fails(self):
        status, result = self.run_capture([self.frames()[1]])
        self.assertEqual(status, 1)
        self.assertTrue(any("without RequestEncryption" in error for error in result["errors"]))


if __name__ == "__main__":
    unittest.main()
