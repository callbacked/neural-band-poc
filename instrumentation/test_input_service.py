"""Fragmented wire-message checks for the experimental ADC reader."""

import struct
import unittest

from input_service import InputService
from mac_band_probe import field, typed_frame


class InputServiceTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.reader = InputService(lambda event, **values: self.events.append((event, values)))

    def feed(self, frame):
        # Each authenticated record can split a protobuf message arbitrarily.
        for start in range(0, len(frame), 13):
            fragment = frame[start:start + 13]
            padding = (-len(fragment)) % 16
            self.reader.feed(fragment + bytes([0xc0 + padding]) * padding)

    def config(self, encoding=0):
        config = b"".join(field(n, v) for n, v in [(1, 2048), (2, 8), (4, 16), (5, 16), (10, encoding)])
        rpc = field(1, 5) + field(2, 1) + field(6, field(42, config))
        self.feed(typed_frame(7, [0x02000315], rpc))

    def sample(self, sequence, data=None):
        data = struct.pack("<128H", *range(32768, 32896)) if data is None else data
        rpc = field(1, sequence) + field(2, 1000000 + sequence * 7812) + field(3, data)
        self.feed(typed_frame(5, [0x0200020a], rpc))

    def test_config_and_fragmented_samples_preserve_values_and_gaps(self):
        self.config()
        self.sample(100)
        self.sample(103)
        self.reader.finish()
        batches = [values for event, values in self.events if event == "emg_batch"]
        self.assertEqual(batches[0]["samples"][0], list(range(32768, 32776)))
        self.assertEqual(batches[0]["samples"][-1], list(range(32888, 32896)))
        self.assertEqual(batches[1]["missing_before"], 2)
        self.assertEqual(self.reader.sample_frames, 32)
        self.assertEqual(self.reader.missing_batches, 2)

    def test_unknown_encoding_or_shape_is_not_interpreted(self):
        self.sample(1)
        self.config(encoding=1)
        self.sample(2)
        self.config()
        self.sample(3, bytes(255))
        self.assertEqual(self.reader.raw_messages, 3)
        self.assertEqual(self.reader.sample_frames, 0)
        self.assertEqual([v["interpreted"] for e, v in self.events if e == "raw_emg_payload"], [False] * 3)

    def test_stop_response_after_interleaved_raw_data(self):
        self.config()
        self.feed(typed_frame(5, [0x02000315], field(1, 3) + field(2, 1) + field(5, field(2, 1))))
        self.assertTrue(self.reader.raw_enabled)
        self.sample(0)
        self.feed(typed_frame(5, [0x02000315], field(1, 4) + field(2, 1) + field(5, field(2, 0))))
        self.reader.finish()
        self.assertFalse(self.reader.raw_enabled)
        self.assertTrue(self.reader.disable_acknowledged)

    def test_motion_and_gesture_wire_values(self):
        # Captured index-press shape: the optional derived action is absent.
        gesture = field(1, 833) + field(2, 1789360341123456) + field(3, 2) + field(4, 1) + field(12, 0)
        self.feed(typed_frame(5, [0x0200020d], gesture))
        self.feed(typed_frame(5, [0x0200020f], field(1, 55669) + field(2, 11153454497) + field(3, bytes.fromhex('eafffdff1900'))))
        self.feed(typed_frame(5, [0x02000212], field(1, 4268) + field(2, 11153470122) + field(3, bytes.fromhex('2b627e3f84f5743b9aa9e53da5d39eb8'))))
        self.reader.finish()
        self.assertEqual(self.events[0], ('gesture', {'sequence': 833, 'timestamp_us': 1789360341123456,
            'finger': 'index', 'action': 'press', 'derived_action': 'unknown', 'synthetic': False}))
        self.assertEqual(self.events[1][1]['values'], [-22, -3, 25])
        self.assertAlmostEqual(self.events[2][1]['values'][0], .9936854, places=5)

    def test_invalid_motion_is_rejected(self):
        for kind, data in [(0x0200020f, bytes(5)), (0x02000212, struct.pack('<4f', float('nan'), 0, 0, 0))]:
            reader = InputService(lambda *args, **kw: None)
            with self.assertRaises(ValueError):
                frame = typed_frame(5, [kind], field(1, 1)+field(2, 1)+field(3, data))
                padding = -len(frame) % 16
                reader.feed(frame+bytes([0xc0+padding])*padding)

    def test_dial_disable_requires_all_requested_flags(self):
        reader = InputService(lambda *args, **kw: None, requested_fields=(3, 6, 8))
        for flags, expected in [([(3, 0)], False), ([(3, 0), (6, 0), (8, 0)], True)]:
            frame = typed_frame(5, [0x02000315], field(1,4)+field(2,1)+field(5,b''.join(field(n,v) for n,v in flags)))
            padding = -len(frame) % 16
            reader.feed(frame+bytes([0xc0+padding])*padding)
            self.assertEqual(reader.streams_disabled_acknowledged, expected)

    def test_inference_acknowledgement_requires_both_flags_and_success(self):
        self.reader = InputService(lambda *args, **kw: None, requested_fields=(3, 4))
        self.feed(typed_frame(7, [0x02000315], field(1, 3) + field(2, 1) + field(5, field(3, 1) + field(4, 1))))
        self.assertFalse(self.reader.streams_enabled_acknowledged)
        for request, status, flags, expected in [
            (3, 1, [(3, 1)], (False, False)),
            (3, 2, [(3, 1), (4, 1)], (False, False)),
            (3, 1, [(3, 1), (4, 1)], (True, False)),
            (4, 1, [(3, 0)], (True, False)),
            (4, 1, [(3, 0), (4, 0)], (True, True)),
        ]:
            self.feed(typed_frame(5, [0x02000315], field(1, request) + field(2, status)
                                 + field(5, b''.join(field(n, v) for n, v in flags))))
            self.assertEqual((self.reader.streams_enabled_acknowledged,
                              self.reader.streams_disabled_acknowledged), expected)

    def test_captured_inference_floats_require_matching_config(self):
        payload = bytes.fromhex('08d2bd021092d5e997ca011a24b9eed4c0cd34a5c06746dcc0c32d8fc0'
                                '15ba35c19ad912c133071cc190b62ac115ba35c15002')
        self.feed(typed_frame(5, [0x0200020c], payload))
        self.assertEqual(self.events[-1][0], 'raw_inference_payload')
        self.assertEqual(self.events[-1][1]['payload'], payload.hex())
        config = bytes.fromhex('0800102018022809')
        self.feed(typed_frame(7, [0x02000315], field(1, 5) + field(2, 1) + field(6, field(46, config))))
        self.assertEqual(self.reader.inference_config, {'pipeline_type': 2, 'downsample_window': 0,
                                                      'model_stride': 32, 'normalized': None, 'num_logits': 9})
        self.feed(typed_frame(5, [0x0200020c], payload))
        event, sample = self.events[-1]
        self.assertEqual(event, 'inference_sample')
        self.assertEqual((sample['sequence'], sample['timestamp_us'], sample['pipeline_type']), (40658, 54273927826, 2))
        self.assertEqual(sample['scores'], [-6.654140949249268, -5.162695407867432, -6.883594036102295,
                                           -4.47433614730835, -11.357930183410645, -9.178125381469727,
                                           -9.751757621765137, -10.669570922851562, -11.357930183410645])

    def test_inference_does_not_interpret_changed_shape_or_nonfinite_scores(self):
        self.feed(typed_frame(7, [0x02000315], field(1, 5) + field(2, 1) + field(6, field(46, field(5, 9)))))
        self.feed(typed_frame(5, [0x0200020c], field(1, 1) + field(2, 100) + field(3, bytes(32)) + field(10, 2)))
        self.assertEqual(self.events[-1][0], 'raw_inference_payload')
        with self.assertRaisesRegex(ValueError, 'non-finite'):
            self.feed(typed_frame(5, [0x0200020c], field(1, 2) + field(2, 200)
                                 + field(3, struct.pack('<9f', *([float('nan')] * 9))) + field(10, 2)))



if __name__ == "__main__":
    unittest.main()
