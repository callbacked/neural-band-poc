"""Offline analyzer checks against a synthetic authenticated capture."""

import json
import struct
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from analyze_inference import NATIVE_LABELS, analyze
from mac_band_probe import field, typed_frame


def sample(sequence, at, hot=None):
    scores = [-12.0] * 9
    if hot is not None:
        scores[hot] = 5.0
    payload = (field(1, sequence) + field(2, 1_000_000 + sequence * 15625)
               + field(3, struct.pack("<9f", *scores)) + field(10, 2))
    return at, typed_frame(5, [0x0200020c], payload)


def gesture(sequence, at, finger, action, synthetic=0):
    payload = (field(1, sequence) + field(2, 5_000_000 + sequence)
               + field(3, finger) + field(4, action) + field(12, synthetic))
    return at, typed_frame(5, [0x0200020d], payload)


class AnalyzeInferenceTests(unittest.TestCase):
    def write_capture(self, frames):
        # Fragments mimic authenticated records: block-aligned with trailing padding.
        start = datetime(2026, 9, 14, 16, 45, tzinfo=timezone.utc)
        rows = []
        for at, frame in frames:
            for offset in range(0, len(frame), 13):
                fragment = frame[offset:offset + 13]
                padding = (-len(fragment)) % 16
                rows.append({"event": "authenticated_packet",
                             "timestamp": (start + timedelta(seconds=at)).isoformat(),
                             "plaintext": (fragment + bytes([0xc0 + padding]) * padding).hex()})
        capture = Path(self.directory.name) / "inference.jsonl"
        capture.write_text("".join(json.dumps(row) + "\n" for row in rows))
        return capture

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.config = typed_frame(7, [0x02000315], field(1, 5) + field(2, 1)
                                  + field(6, field(46, bytes.fromhex("0800102018022809"))))

    def test_report_names_native_labels_beside_measured_channels(self):
        frames = [(0.0, self.config)]
        frames += [sample(n, 0.1 + n * 0.015625) for n in range(20)]
        frames += [sample(20, 0.50, hot=0), gesture(1, 0.52, 2, 1)]
        frames += [sample(21, 0.95, hot=4), gesture(2, 1.00, 1, 5)]
        frames += [sample(22, 1.40, hot=4), gesture(3, 1.45, 1, 5, synthetic=1)]
        report, samples, comparisons = analyze(self.write_capture(frames))
        self.assertEqual(report["native_labels"], list(NATIVE_LABELS))
        self.assertEqual(len(samples), 23)
        self.assertEqual([row["gesture"] for row in comparisons], ["index_press", "thumb_click"])
        index = report["associations"]["index_press"]
        self.assertEqual((index["channel"], index["native_label"], index["events"], index["matching_peaks"]),
                         (0, "index_press", 1, 1))
        thumb = report["associations"]["thumb_click"]
        self.assertEqual((thumb["channel"], thumb["native_label"]), (4, "thumb_tap"))
        self.assertEqual(report["unassigned_channels"], [1, 2, 3, 5, 6, 7, 8])
        self.assertEqual(report["inference_config"]["num_logits"], 9)

    def test_capture_without_interpreted_samples_is_rejected(self):
        frames = [(0.0, self.config), gesture(1, 0.5, 2, 1)]
        with self.assertRaisesRegex(ValueError, "No supported inference samples"):
            analyze(self.write_capture(frames))


if __name__ == "__main__":
    unittest.main()
