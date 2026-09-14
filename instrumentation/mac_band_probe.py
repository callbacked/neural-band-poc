"""Direct macOS band connection and bounded AirShield/input-service experiments.

Uses fresh P-256 keys and the locally verified parameter-3 derivation. After
setup, sends the empty identity query observed in Starcruiser's Datax.swift
(commit 1bc6f9418ad85a10991817c74e15a84f85078f53, service 0x24 / type 0x3000).
Certificate replies and raw-stream activation are verified on the tested band;
full owner identity authentication is not established.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import signal
import time

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from airshield import AuthenticatedPacket, StreamDecryptor, derive_keys
from analyze_capture import protobuf_fields, setup_summary
from band_access import band_connection
from input_service import InputService


def varint(value):
    encoded = bytearray()
    while value >= 128:
        encoded.append((value & 127) | 128)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def field(number, value):
    if isinstance(value, int):
        return varint(number << 3) + varint(value)
    return varint((number << 3) | 2) + varint(len(value)) + value


def typed_frame(channel, words, payload=b""):
    body = b"".join(word.to_bytes(4, "big") for word in words) + payload
    if len(body) > 0x7fff:
        raise ValueError("DataX frame too large")
    return (0x8000 | len(body)).to_bytes(2, "big") + channel.to_bytes(2, "big") + body


class BandHandshake:
    def __init__(self, emit, query_device_info=False, end_link_setup=False, stream_control=None, query_config=False,
                 hand=None, clock=time.monotonic):
        if hand not in (None, "left", "right"):
            raise ValueError("Hand must be left or right")
        self.emit = emit
        self.clock = clock
        self.requested_hand = hand
        self.hand = self.hand_error = None
        self.config_request = None
        self.config_id = 4
        self.config_outgoing = bytearray()
        self.private = ec.generate_private_key(ec.SECP256R1())
        self.public = self.private.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)[1:]
        self.challenge, self.seed, self.iv = os.urandom(16), os.urandom(32), os.urandom(16)
        self.base = int.from_bytes(os.urandom(4), "little")
        self.pending = bytearray()
        self.peer_request = None
        self.decoder = None
        self.authenticated_packets = 0
        self.query_sent = False
        self.query_device_info = query_device_info
        self.end_link_setup = end_link_setup or stream_control is not None or query_config or hand is not None
        self.stream_control = stream_control
        self.query_config = query_config or stream_control == "dial" or hand is not None
        self.rpc_channels = set()
        self.tx_keys = None
        self.stream_fields = (3, 6, 8) if stream_control == "dial" else (2,)
        self.input_service = InputService(self.receive_input, requested_fields=self.stream_fields)

    def request_config(self, stage):
        self.config_id += 1
        self.config_request = (self.config_id, stage, self.clock() + 5)
        # ConfigReq field 10 is is_left_handed. Leave all other settings absent.
        config = field(10, int(self.requested_hand == "left")) if stage == "write" else b""
        payload = field(1, self.config_id) + field(5, config)
        channel = 0x8007
        if channel in self.rpc_channels:
            frame = len(payload).to_bytes(2, "big") + channel.to_bytes(2, "big") + payload
        else:
            self.rpc_channels.add(channel)
            frame = typed_frame(channel, [0x8100ce56, 0x02000314], payload)
        self.emit("config_request_queued", request_id=self.config_id, stage=stage,
                  hand=self.requested_hand if stage == "write" else None)
        return self.encrypt_frame(frame)

    def fail_hand(self, message):
        self.config_request = None
        self.hand, self.hand_error = None, message
        if self.input_service.interaction:
            self.input_service.interaction.set_hand(None, message)
        self.emit("handedness_failed", message=message)

    def tick(self):
        if self.config_request and self.clock() >= self.config_request[2]:
            self.fail_hand("Band hand confirmation timed out")
        self.input_service.tick()

    def receive_input(self, event, **data):
        self.emit(event, **data)
        if event != "input_rpc_response" or not self.config_request:
            return
        request_id, stage, deadline = self.config_request
        if data["channel"] & 0x7fff != 7 or data["request_id"] != request_id:
            return
        if self.clock() >= deadline:
            self.fail_hand("Band hand confirmation timed out")
        elif data["status"] != 1:
            self.fail_hand("Band rejected the hand configuration request")
        elif stage == "write":
            # An acknowledgement is not evidence that the setting stuck.
            self.config_outgoing.extend(self.request_config("verify"))
        elif data["is_left_handed"] not in (0, 1):
            self.fail_hand("Band did not report a valid hand setting")
        else:
            actual = "left" if data["is_left_handed"] else "right"
            if stage == "read" and self.requested_hand is not None and actual != self.requested_hand:
                self.config_outgoing.extend(self.request_config("write"))
            elif stage == "verify" and actual != self.requested_hand:
                self.fail_hand(f"Band still reports {actual} hand after the change")
            else:
                self.config_request = None
                self.hand = actual
                if self.input_service.interaction:
                    self.input_service.interaction.set_hand(actual)
                self.emit("handedness_confirmed", hand=actual)

    def encrypt_frame(self, frame):
        if self.tx_keys is None:
            raise ValueError("encryption keys not negotiated")
        count = (-len(frame)) % 16
        padded = frame + bytes([0xc0 + count]) * count
        if not padded or len(padded) > 4096:
            raise ValueError("encrypted record must contain 1–256 blocks")
        cipher = Cipher(algorithms.AES(self.tx_keys.encryption), modes.CBC(self.iv)).encryptor()
        ciphertext = cipher.update(padded) + cipher.finalize()
        body = bytes([len(ciphertext) // 16 - 1]) + ciphertext
        mac = hmac.new(self.tx_keys.mac, self.base.to_bytes(4, "little") + body, hashlib.sha256).digest()[:8]
        self.iv = ciphertext[-16:]
        self.base = (self.base + 1) & 0xffffffff
        return b"\x40" + mac + body

    def request(self):
        payload = field(1, self.public) + field(2, self.challenge) + field(3, 0) + field(4, 31) + field(7, 16)
        return typed_frame(0x8001, [0x81000005, 0x02000001], payload)

    def stream_request(self, channel, request_id, enabled=None):
        # Native name maps: RPC field 4; EMG=2, gestures=3, gyro=6, quat=8.
        control = b"" if enabled is None else b"".join(field(n, int(enabled)) for n in self.stream_fields)
        payload = field(1, request_id) + field(4, control)
        self.emit("stream_control_queued", request_id=request_id, raw_emg=enabled if 2 in self.stream_fields else None,
                  flags={str(n): enabled for n in self.stream_fields})
        if channel in self.rpc_channels:
            # Follow-up RPCs use the original channel and its retained type.
            # A new channel creates a separate stream subscription on the band.
            frame = len(payload).to_bytes(2, "big") + channel.to_bytes(2, "big") + payload
        else:
            self.rpc_channels.add(channel)
            frame = typed_frame(channel, [0x8100ce56, 0x02000314], payload)
        return self.encrypt_frame(frame)

    def feed(self, data):
        """Return ordered outgoing bytes; completed receive records go to emit."""
        self.pending.extend(data)
        outgoing = bytearray()
        while self.decoder is None and len(self.pending) >= 4:
            if not self.pending[0] & 0x80:
                raise ValueError("non-setup bytes before peer EnableEncryption")
            size = (int.from_bytes(self.pending[:2], "big") & 0x7fff) + 4
            if size < 8:
                raise ValueError("invalid setup length")
            if len(self.pending) < size:
                break
            frame = bytes(self.pending[:size])
            del self.pending[:size]
            summary = setup_summary(frame)
            self.emit("peer_setup", **summary)
            offset = 12 if summary["message"] == "RequestEncryption" else 8
            fields = {n: v for n, wire, v in protobuf_fields(frame[offset:])}
            if summary["message"] == "RequestEncryption":
                if self.peer_request is not None:
                    raise ValueError("duplicate peer request")
                if fields.get(3, 0) != 0 or fields.get(4, 0) != 3:
                    raise ValueError("probe supports only the observed band curve/parameters 0/3")
                self.peer_request = fields
                payload = (field(1, self.public) + field(2, self.seed) + field(3, self.iv)
                           + field(4, self.base) + field(5, 3))
                outgoing.extend(typed_frame(1, [0x02000002], payload))
            else:
                if self.peer_request is None or fields.get(5, 0) != 3:
                    raise ValueError("unexpected peer enable or parameters")
                if fields[1] != self.peer_request[1]:
                    raise ValueError("peer changed public key between request and enable")
                peer_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + fields[1])
                secret = self.private.exchange(ec.ECDH(), peer_key)
                self.tx_keys = derive_keys(secret, self.peer_request[2], self.seed, 3)
                rx_keys = derive_keys(secret, self.challenge, fields[2], 3)
                self.decoder = StreamDecryptor(rx_keys, fields[3], fields.get(4, 0), 3)
                # Keep session material in the caller's local capture for replay.
                self.emit("session_material", shared_secret=secret.hex(), challenge=self.challenge.hex(),
                          seed=self.seed.hex(), iv=self.iv.hex(), base=self.base)
                self.emit("encryption_negotiated", parameters=3, peer_authenticated=False)
                outgoing.extend(self.encrypt_frame(typed_frame(0x8002, [0x81000024, 0x02003000])))
                self.query_sent = True
                self.emit("identity_query_queued", service=36, message_type=0x3000)
                if self.end_link_setup:
                    # Observed EndLinkSetup shape, with a fresh local link UUID.
                    # Required for the successful direct device-info exchange.
                    end = typed_frame(0x8001, [0x02001000], field(1, 1) + field(2, os.urandom(16)))
                    outgoing.extend(self.encrypt_frame(end))
                    self.emit("link_setup_end_queued", state=1)
                if self.query_device_info:
                    # Empty device-info RPC observed in the official band session.
                    query = typed_frame(0x8003, [0x8100ce56, 0x02000314], field(1, 1) + field(3, b""))
                    outgoing.extend(self.encrypt_frame(query))
                    self.emit("device_info_query_queued", service=0xce56, message_type=0x314)
                if self.query_config:
                    outgoing.extend(self.request_config("read"))
                if self.stream_control:
                    outgoing.extend(self.stream_request(0x8005, 2))
                    if self.stream_control in ("raw-emg", "dial"):
                        outgoing.extend(self.stream_request(0x8005, 3, True))
        if self.decoder is not None:
            data = bytes(self.pending)
            self.pending.clear()
            for record in self.decoder.feed(data):
                if isinstance(record, AuthenticatedPacket):
                    self.authenticated_packets += 1
                    self.emit("authenticated_packet", counter=record.counter, plaintext=record.plaintext.hex())
                    self.input_service.feed(record.plaintext)
                else:
                    self.emit("unauthenticated_record", kind=record.kind, channel=record.channel, payload=record.payload.hex())
        outgoing.extend(self.config_outgoing)
        self.config_outgoing.clear()
        return bytes(outgoing)

    def finish(self):
        if self.decoder is None:
            raise ValueError(f"initial encryption exchange incomplete; {len(self.pending)} buffered bytes")
        self.decoder.finish()


def run_probe(args, emit):
    # CoreBluetooth stays on the main thread. Keeping these imports here also
    # permits deterministic protocol tests without a macOS Bluetooth runtime.
    from Foundation import (NSObject, NSRunLoop, NSDate, NSUUID, NSDefaultRunLoopMode,
                            NSProcessInfo, NSActivityUserInitiatedAllowingIdleSystemSleep)
    from CoreBluetooth import CBCentralManager, CBUUID

    class MacBandDelegate(NSObject):
        def centralManagerDidUpdateState_(self, central):
            emit("bluetooth_state", state=int(central.state()))
            if central.state() != 5:
                return
            known = central.retrievePeripheralsWithIdentifiers_([NSUUID.alloc().initWithUUIDString_(args.identifier)])
            if known:
                self.peripheral = known[0]
                central.connectPeripheral_options_(self.peripheral, None)
            else:
                central.scanForPeripheralsWithServices_options_(None, None)

        def centralManager_didDiscoverPeripheral_advertisementData_RSSI_(self, central, peripheral, advertisement, rssi):
            if str(peripheral.identifier().UUIDString()) == args.identifier:
                self.peripheral = peripheral
                central.stopScan()
                central.connectPeripheral_options_(peripheral, None)

        def centralManager_didConnectPeripheral_(self, central, peripheral):
            emit("connected", name=str(peripheral.name()))
            peripheral.setDelegate_(self)
            peripheral.discoverServices_([CBUUID.UUIDWithString_("FEB8")])

        def centralManager_didFailToConnectPeripheral_error_(self, central, peripheral, error):
            self.failure = f"connection failed: {error}"

        def centralManager_didDisconnectPeripheral_error_(self, central, peripheral, error):
            emit("disconnected", error=str(error) if error else None)
            self.disconnected = True

        def peripheral_didDiscoverServices_(self, peripheral, error):
            if error:
                self.failure = str(error)
                return
            for service in peripheral.services():
                peripheral.discoverCharacteristics_forService_([CBUUID.UUIDWithString_("2d41da7c-82b6-42aa-b34e-e2e01df8cc1a")], service)

        def peripheral_didDiscoverCharacteristicsForService_error_(self, peripheral, service, error):
            if error:
                self.failure = str(error)
                return
            for characteristic in service.characteristics():
                peripheral.readValueForCharacteristic_(characteristic)

        def peripheral_didUpdateValueForCharacteristic_error_(self, peripheral, characteristic, error):
            if error:
                self.failure = str(error)
                return
            value = bytes(characteristic.value())
            if len(value) != 2 or int.from_bytes(value, "little") != 255:
                self.failure = "unexpected PSM characteristic"
                return
            emit("psm_discovered", psm=255)
            peripheral.openL2CAPChannel_(255)

        def peripheral_didOpenL2CAPChannel_error_(self, peripheral, channel, error):
            if error:
                self.failure = f"L2CAP open failed: {error}"
                return
            self.channel = channel
            for stream in (channel.inputStream(), channel.outputStream()):
                stream.scheduleInRunLoop_forMode_(NSRunLoop.currentRunLoop(), NSDefaultRunLoopMode)
                stream.open()
            self.outgoing.extend(self.handshake.request())
            emit("l2cap_open", psm=int(channel.PSM()))

    delegate = MacBandDelegate.alloc().init()
    delegate.peripheral = delegate.channel = delegate.failure = None
    delegate.disconnected = False
    delegate.outgoing = bytearray()
    delegate.handshake = BandHandshake(emit, query_device_info=args.query_device_info,
                                       end_link_setup=args.end_link_setup, stream_control=args.stream_control,
                                       query_config=args.query_config, hand=args.hand)
    central = CBCentralManager.alloc().initWithDelegate_queue_(delegate, None)
    deadline = time.monotonic() + args.seconds
    stop_queued = False
    recording_started = False
    stop_requested = False
    stopping = False
    def stop_signal(signum, frame):
        nonlocal stop_requested, stopping
        stop_requested = True
        stopping = True
    previous_signal = signal.signal(signal.SIGINT, stop_signal)
    # Active sensor recording is user work; opt out of App Nap for this session.
    process_info = NSProcessInfo.processInfo()
    activity = process_info.beginActivityWithOptions_reason_(NSActivityUserInitiatedAllowingIdleSystemSleep,
                                                            "Record Neural Band sensor input")
    last_loop = time.monotonic()
    settings_checked = 0.
    try:
        while time.monotonic() < deadline:
            now = time.monotonic()
            if now-last_loop > .1:
                emit("host_loop_delay", seconds=now-last_loop)
            last_loop = now
            if args.dial_settings and delegate.handshake.input_service.interaction and now-settings_checked > .25:
                settings_checked = now
                try:
                    settings = json.loads(args.dial_settings.read_text())
                    delegate.handshake.input_service.interaction.configure(**settings)
                except (OSError, ValueError, TypeError) as error:
                    raise ValueError(f"Invalid local dial settings: {error}") from error
            delegate.handshake.tick()
            if stop_requested:
                deadline = min(deadline, time.monotonic() + 3)
                stop_requested = False
            NSRunLoop.currentRunLoop().runUntilDate_(NSDate.dateWithTimeIntervalSinceNow_(0.002))
            if delegate.failure:
                raise ValueError(delegate.failure)
            if delegate.disconnected:
                break
            if delegate.channel is None:
                continue
            incoming, outgoing = delegate.channel.inputStream(), delegate.channel.outputStream()
            if (args.stream_control in ("raw-emg", "dial") and delegate.handshake.tx_keys is not None
                    and not stop_queued and time.monotonic() >= deadline - 3):
                delegate.outgoing.extend(delegate.handshake.stream_request(0x8005, 4, False))
                stop_queued = True
            if incoming.hasBytesAvailable():
                count, data = incoming.read_maxLength_(None, 65536)
                if count < 0:
                    raise ValueError(f"stream read failed: {incoming.streamError()}")
                if count:
                    emit("stream_bytes", direction="rx", hex=data.hex(), count=count)
                    delegate.outgoing.extend(delegate.handshake.feed(data))
                    if (args.stream_control in ("raw-emg", "dial") and not recording_started and not stop_queued and not stopping
                            and (delegate.handshake.input_service.sample_frames or delegate.handshake.input_service.motion_messages)):
                        recording_started = True
                        deadline = time.monotonic() + args.seconds
                        emit("recording_started", duration_seconds=args.seconds, mode=args.stream_control)
            if delegate.outgoing and outgoing.hasSpaceAvailable():
                data = bytes(delegate.outgoing)
                count = outgoing.write_maxLength_(data, len(data))
                if count < 0:
                    raise ValueError(f"stream write failed: {outgoing.streamError()}")
                if count > len(data):
                    raise ValueError("invalid stream write count")
                if count:
                    emit("stream_bytes", direction="tx", hex=data[:count].hex(), count=count)
                    del delegate.outgoing[:count]
            for stream in (incoming, outgoing):
                if stream.streamStatus() == 7:
                    raise ValueError(f"stream error: {stream.streamError()}")
            if incoming.streamStatus() in (5, 6):
                emit("stream_ended")
                break
        delegate.handshake.finish()
        if delegate.outgoing:
            raise ValueError(f"{len(delegate.outgoing)} outgoing bytes not accepted by stream")
        emit("probe_result", authenticated_packets=delegate.handshake.authenticated_packets,
             identity_authenticated=False, semg_samples_identified=bool(delegate.handshake.input_service.sample_frames),
             raw_emg_messages=delegate.handshake.input_service.raw_messages,
             sample_frames=delegate.handshake.input_service.sample_frames,
             missing_batches=delegate.handshake.input_service.missing_batches,
             raw_emg_disable_acknowledged=delegate.handshake.input_service.disable_acknowledged,
             streams_disabled_acknowledged=delegate.handshake.input_service.streams_disabled_acknowledged,
             motion_messages=delegate.handshake.input_service.motion_messages,
             gesture_messages=delegate.handshake.input_service.gesture_messages,
             other_messages=delegate.handshake.input_service.other_messages,
             hand=delegate.handshake.hand, hand_error=delegate.handshake.hand_error)
        delegate.handshake.input_service.finish()
        if args.hand is not None and delegate.handshake.hand != args.hand:
            raise ValueError(delegate.handshake.hand_error or "Requested band hand was not confirmed")
        if args.stream_control in ("raw-emg", "dial") and not delegate.handshake.input_service.streams_disabled_acknowledged:
            raise ValueError("Disconnected without confirmation that all requested streams stopped")
        return bool(delegate.handshake.authenticated_packets)
    finally:
        process_info.endActivity_(activity)
        signal.signal(signal.SIGINT, previous_signal)
        central.stopScan()
        if delegate.channel:
            for stream in (delegate.channel.inputStream(), delegate.channel.outputStream()):
                stream.close()
                stream.removeFromRunLoop_forMode_(NSRunLoop.currentRunLoop(), NSDefaultRunLoopMode)
        if delegate.peripheral:
            central.cancelPeripheralConnection_(delegate.peripheral)
        NSRunLoop.currentRunLoop().runUntilDate_(NSDate.dateWithTimeIntervalSinceNow_(0.1))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("identifier", help="macOS CoreBluetooth UUID from a fresh band scan")
    parser.add_argument("--seconds", type=float, default=35, help="time limit; sensor modes start a fresh interval when samples arrive")
    parser.add_argument("--dial-settings", type=Path, help="local JSON response/sensitivity settings, watched during gesture modes")
    parser.add_argument("--query-device-info", action="store_true", help="read input-service metadata; pair with --end-link-setup")
    parser.add_argument("--end-link-setup", action="store_true", help="complete link setup before input-service requests")
    parser.add_argument("--stream-control", choices=("query", "raw-emg", "dial"),
                        help="query flags, raw EMG, or gestures/motion (dial); disables requested streams before the deadline")
    parser.add_argument("--query-config", action="store_true", help="read current input-service configuration; includes EndLinkSetup")
    parser.add_argument("--hand", choices=("left", "right"), help="set the band hand and verify it with a separate read; omitted keeps the band setting")
    parser.add_argument("--output", type=Path, required=True, help="new local JSONL capture; includes session material")
    args = parser.parse_args()
    if not 1 <= args.seconds <= 300:
        parser.error("duration must be 1–300 seconds")
    if args.stream_control in ("raw-emg", "dial") and args.seconds < 10:
        parser.error("stream experiments need at least 10 seconds for setup and cleanup")
    if args.stream_control in ("raw-emg", "dial"):
        args.query_config = True
    args.identifier = args.identifier.upper()
    with args.output.open("x") as capture:
        def emit(event, **details):
            row = {"event": event, "timestamp": datetime.now(timezone.utc).isoformat(), **details}
            capture.write(json.dumps(row) + "\n")
            capture.flush()
            if event == "interaction_state":
                live = args.output.with_suffix(".live.json")
                temporary = live.with_suffix(".tmp")
                temporary.write_text(json.dumps(row))
                temporary.replace(live)
            if event not in ("session_material", "stream_bytes", "authenticated_packet", "unauthenticated_record", "emg_batch", "raw_emg_payload", "gyro_sample", "orientation_sample", "input_message", "gesture", "interaction_state"):
                print(json.dumps(row), flush=True)
        try:
            with band_connection():
                success = run_probe(args, emit)
        except (ValueError, OSError, RuntimeError) as error:
            emit("probe_error", message=str(error))
            success = False
    raise SystemExit(0 if success else 1)
