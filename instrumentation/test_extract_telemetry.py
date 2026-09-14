"""Exercise the telemetry CLI using synthetic, non-secret wire-format fixtures."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zlib


def varint(value):
    encoded = bytearray()
    while value >= 128:
        encoded.append((value & 127) | 128)
        value >>= 7
    return bytes(encoded + bytes([value]))


def field(number, value):
    if isinstance(value, int):
        return varint(number << 3) + varint(value)
    return varint((number << 3) | 2) + varint(len(value)) + value


def frame(payload, words=()):
    body = b"".join(word.to_bytes(4, "big") for word in words) + payload
    # The channel high bit stays set even when the length high bit is clear.
    return (len(body) | (0x8000 if words else 0)).to_bytes(2, "big") + b"\x81\x80" + body


def fixture(*, bad_checksum=False, incomplete_transfer=False, truncated_zlib=False, transport_error=False):
    records = []
    for step, action, identifier, timestamp in (
        ("interaction_emg_sdk", "INDEX_PRESS", "press-example", 1789354285357),
        ("interaction_system_receive", "INDEX_PRESS", "press-example", 1789354285357),
        ("interaction_emg_sdk", "INDEX_SINGLE_TAP", "tap-example", 1789354285465),
    ):
        event = {"step_name": step, "timestamp_ms": timestamp, "interaction_id": identifier,
                 "input_metadata": {"source": "EMG", "action": action}}
        entry = field(1, timestamp) + field(2, b"constellation_step_event") + field(3, json.dumps(event).encode())
        records.append(field(1, entry))
    packed = zlib.compress(field(1, b"".join(records)))
    if truncated_zlib:
        packed = packed[:-3]
    split = len(packed) // 2
    metadata = field(1, bytes(16)) + field(2, len(packed)) + field(3, b"telemetry") + field(4, b"synthetic_compressed_high")
    progress = field(1, split) + field(2, zlib.adler32(packed[:split]))
    finish = field(1, len(packed)) + field(2, zlib.adler32(packed) ^ int(bad_checksum))
    stream = (
        frame(metadata, (0x81000014, 0x02000001))
        + frame(packed[:7], (0x02000004,))
        + frame(packed[7:split])
        + frame(progress, (0x02000005,))
        + frame(packed[split:split + 9], (0x02000004,))
        + frame(packed[split + 9:])
    )
    if not incomplete_transfer:
        stream += frame(finish, (0x02000006,))
    packets = []
    # Split DataX frames across AirShield records and pad each encrypted record.
    for offset in range(0, len(stream), 47):
        plain = stream[offset:offset + 47]
        pad = (-len(plain)) % 16
        plain += bytes([0xc0 + pad]) * pad
        packets.append({"plaintext": plain.hex(), "observed_complete": {
            "sequence": len(packets) + 1, "timestamp": "2026-09-14T02:53:53.756Z"}})
    capture = {"directions": [{"peer": "Synthetic glasses", "direction": "rx", "opening_sequence": 1,
                               "packets": packets}], "errors": ["truncated transport tail"] if transport_error else []}
    return capture, packed


class TelemetryCliTests(unittest.TestCase):
    def run_capture(self, **options):
        capture, packed = fixture(**options)
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / "decrypted.json", Path(directory) / "events.json"
            source.write_text(json.dumps(capture))
            run = subprocess.run([sys.executable, str(Path(__file__).with_name("extract_telemetry.py")),
                                  str(source), "--output", str(output)], capture_output=True, text=True)
            self.assertTrue(output.exists(), run.stderr)
            return run, json.loads(output.read_text()), packed

    def test_fragmented_transfer_preserves_raw_bytes_and_filters_pipeline_stages(self):
        run, result, packed = self.run_capture()
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertEqual(result["errors"], [])
        self.assertEqual(len(result["transfers"]), 1)
        transfer = result["transfers"][0]
        self.assertEqual(transfer["adler32"], zlib.adler32(packed))
        self.assertEqual(transfer["compressed_bytes"], len(packed))
        self.assertEqual(transfer["record_count"], 3)
        self.assertEqual([(event["action"], event["timestamp_ms"], event["interaction_id"]) for event in transfer["events"]],
                         [("INDEX_PRESS", 1789354285357, "press-example"),
                          ("INDEX_SINGLE_TAP", 1789354285465, "tap-example")])
        self.assertEqual(transfer["events"][0]["timestamp_utc"], "2026-09-14T02:51:25.357+00:00")

    def test_bad_checksum_releases_no_events(self):
        run, result, _ = self.run_capture(bad_checksum=True)
        self.assertEqual(run.returncode, 1)
        self.assertEqual(result["transfers"], [])
        self.assertIn("Adler-32 mismatch", result["errors"][0])

    def test_missing_finish_is_reported_even_when_all_file_bytes_arrived(self):
        run, result, _ = self.run_capture(incomplete_transfer=True)
        self.assertEqual(run.returncode, 1)
        self.assertEqual(result["transfers"], [])
        self.assertIn("incomplete telemetry file", result["errors"][0])

    def test_matching_transfer_checksum_does_not_hide_truncated_zlib(self):
        run, result, _ = self.run_capture(truncated_zlib=True)
        self.assertEqual(run.returncode, 1)
        self.assertEqual(result["transfers"], [])
        self.assertIn("incomplete or trailing zlib", result["errors"][0])

    def test_completed_files_survive_an_explicit_transport_tail_error(self):
        run, result, _ = self.run_capture(transport_error=True)
        self.assertEqual(run.returncode, 1)
        self.assertEqual(result["errors"], ["transport: truncated transport tail"])
        self.assertEqual(result["transfers"][0]["events"][0]["action"], "INDEX_PRESS")


if __name__ == "__main__":
    unittest.main()
