"""Observed input RPCs and experimental uncompressed EMG interpretation.

The installed app's EmgConfig name map supplies the sample dimensions. ADC
conversion to volts and physical channel placement are deliberately omitted.
"""

import struct
import math

from extract_telemetry import checked_fields, DataXStream
from pinch_dial import PinchDial


class InputService:
    def __init__(self, emit, requested_fields=(2,)):
        self.output = emit
        self.interaction = PinchDial(emit) if 3 in requested_fields and 6 in requested_fields else None
        self.datax = DataXStream()
        self.types = {}
        self.config = None
        self.raw_messages = self.sample_frames = self.missing_batches = 0
        self.previous_sequence = None
        self.raw_enabled = False
        self.disable_acknowledged = False
        self.requested_fields = requested_fields
        self.streams_disabled_acknowledged = False
        self.other_messages = {}
        self.motion_messages = 0
        self.gesture_messages = 0

    def emit(self, event, **data):
        self.output(event, **data)
        if self.interaction:
            self.interaction.feed(event, **data)

    def tick(self):
        if self.interaction:
            self.interaction.tick()

    def feed(self, plaintext):
        for channel, words, payload, observed in self.datax.feed(plaintext, None):
            if words:
                self.types[channel] = words[-1]
            kind = self.types.get(channel)
            if kind == 0x02000315:
                fields = checked_fields(payload)
                request_id, status = fields.get((1, 0)), fields.get((2, 0))
                if (4, 2) in fields:
                    self.emit("device_info_received", request_id=request_id, status=status)
                if (5, 2) in fields:
                    control = checked_fields(fields[5, 2])
                    enabled = control.get((2, 0))
                    flags = {str(n): control[n, 0] for n in self.requested_fields if (n, 0) in control}
                    self.emit("stream_control_received", request_id=request_id, status=status, raw_emg=enabled, flags=flags)
                    if status == 1 and request_id == 4 and all(control.get((n, 0)) == 0 for n in self.requested_fields):
                        self.streams_disabled_acknowledged = True
                    if status == 1 and request_id == 3 and enabled == 1:
                        self.raw_enabled = True
                    if status == 1 and request_id == 4 and enabled == 0:
                        self.raw_enabled = False
                        self.disable_acknowledged = True
                if (6, 2) in fields:
                    config = checked_fields(fields[6, 2])
                    if status == 1 and (42, 2) in config:
                        emg = checked_fields(config[42, 2])
                        self.config = {"sample_rate": emg.get((1, 0)), "channels": emg.get((2, 0)),
                                       "adc_bits": emg.get((4, 0)), "samples_per_batch": emg.get((5, 0)),
                                       "encoding": emg.get((10, 0))}
                        self.emit("emg_config_received", **self.config)
            elif kind == 0x0200020a:
                fields = checked_fields(payload)
                sequence, timestamp, data = fields.get((1, 0)), fields.get((2, 0)), fields.get((3, 2))
                if sequence is None or timestamp is None or data is None:
                    raise ValueError("raw EMG message lacks sequence, timestamp or sample bytes")
                self.raw_messages += 1
                missing = 0 if self.previous_sequence is None else max(0, sequence - self.previous_sequence - 1)
                self.missing_batches += missing
                self.previous_sequence = sequence
                # Restrict interpretation to the one verified configuration;
                # never interpret compressed or differently shaped bytes as u16.
                if self.config != {"sample_rate": 2048, "channels": 8, "adc_bits": 16,
                                   "samples_per_batch": 16, "encoding": 0} or len(data) != 256:
                    self.emit("raw_emg_payload", sequence=sequence, timestamp_us=timestamp,
                              bytes=len(data), interpreted=False)
                    continue
                values = struct.unpack("<128H", data)
                self.sample_frames += 16
                self.emit("emg_batch", sequence=sequence, timestamp_us=timestamp, missing_before=missing,
                          samples=[list(values[i:i + 8]) for i in range(0, 128, 8)])
            elif kind == 0x0200020d:
                fields = checked_fields(payload)
                if (1, 0) not in fields or (2, 0) not in fields:
                    raise ValueError("gesture lacks sequence or timestamp")
                fingers = ("unknown", "thumb", "index", "middle", "notApplicable")
                actions = ("unknown", "press", "release", "tap", "doubletap", "click", "up", "down", "left", "right", "wake", "swipeIn", "swipeOut", "ia", "partialPress", "partialRelease", "partialClick", "partialUp", "partialDown", "partialLeft", "partialRight")
                derived = ("unknown", "singleTap", "doubleTap", "buttonHold", "buttonRelease", "buttonUp", "buttonDown", "buttonLeft", "buttonRight", "buttonPress", "buttonHoldRelease")
                def name(number, names):
                    value = fields.get((number, 0), 0)
                    return names[value] if value < len(names) else f"unrecognized:{value}"
                self.gesture_messages += 1
                self.emit("gesture", sequence=fields[1, 0], timestamp_us=fields[2, 0],
                          finger=name(3, fingers), action=name(4, actions), derived_action=name(5, derived),
                          synthetic=bool(fields.get((12, 0), 0)))
            elif kind in (0x0200020f, 0x02000212):
                fields = checked_fields(payload)
                sequence, timestamp, data = fields.get((1, 0)), fields.get((2, 0)), fields.get((3, 2))
                expected = 6 if kind == 0x0200020f else 16
                if sequence is None or timestamp is None or data is None or len(data) != expected:
                    raise ValueError("unsupported motion message shape")
                values = list(struct.unpack("<3h" if expected == 6 else "<4f", data))
                if expected == 16 and (not all(math.isfinite(v) for v in values) or not .9 < sum(v*v for v in values) < 1.1):
                    raise ValueError("invalid orientation quaternion")
                self.motion_messages += 1
                self.emit("gyro_sample" if expected == 6 else "orientation_sample", sequence=sequence,
                          timestamp_us=timestamp, values=values)
            elif kind is not None and 0x02000200 <= kind <= 0x02000316:
                key = hex(kind)
                self.other_messages[key] = self.other_messages.get(key, 0) + 1
                self.emit("input_message", message_type=key, payload=payload.hex())

    def finish(self):
        if self.interaction:
            self.interaction.finish()
        self.datax.finish()
