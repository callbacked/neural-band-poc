"""Synthetic peer checks for the live probe's protocol state machine."""

import hashlib
import hmac
import unittest

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from airshield import StreamDecryptor, derive_keys
from analyze_capture import protobuf_fields
from extract_telemetry import datax_frames
from mac_band_probe import BandHandshake, typed_frame
from test_extract_telemetry import field


class MacBandProbeTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.probe = BandHandshake(lambda event, **values: self.events.append((event, values)))
        self.peer_private = ec.derive_private_key(1, ec.SECP256R1())
        self.peer_public = self.peer_private.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)[1:]
        self.peer_challenge, self.peer_seed, self.peer_iv = bytes(range(16)), bytes(range(32)), bytes(range(16, 32))
        payload = field(1, self.peer_public) + field(2, self.peer_challenge) + field(3, 0) + field(4, 3)
        self.request = (0x8000 | (8 + len(payload))).to_bytes(2, "big") + bytes.fromhex("80018100000502000001") + payload
        payload = field(1, self.peer_public) + field(2, self.peer_seed) + field(3, self.peer_iv) + field(4, 42) + field(5, 3)
        self.enable = (0x8000 | (4 + len(payload))).to_bytes(2, "big") + bytes.fromhex("000102000002") + payload

    def start_hand_session(self, hand=None):
        self.now = 0.
        self.probe = BandHandshake(lambda event, **values: self.events.append((event, values)),
                                   stream_control="dial", hand=hand, clock=lambda: self.now)
        outgoing = self.probe.feed(self.request + self.enable)
        size = (int.from_bytes(outgoing[:2], "big") & 0x7fff) + 4
        local = {n: v for n, w, v in protobuf_fields(outgoing[8:size])}
        public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + local[1])
        secret = self.peer_private.exchange(ec.ECDH(), public)
        self.peer_decoder = StreamDecryptor(derive_keys(secret, self.peer_challenge, local[2], 3), local[3], local[4], 3)
        self.peer_keys = derive_keys(secret, self.probe.challenge, self.peer_seed, 3)
        self.peer_counter = 42
        return self.read_requests(outgoing[size:])

    def read_requests(self, outgoing):
        packets = self.peer_decoder.feed(outgoing)
        frames = datax_frames([{"plaintext": p.plaintext.hex(), "observed_complete": {}} for p in packets])
        return [(channel, {n: v for n, w, v in protobuf_fields(payload)})
                for channel, words, payload, at in frames if channel == 0x8007]

    def config_reply(self, request_id, hand=None, status=1, channel=7):
        payload = field(1, request_id) + field(2, status)
        if hand is not None:
            payload += field(6, field(10, hand))
        frame = typed_frame(channel, [0x02000315], payload)
        count = -len(frame) % 16
        cipher = Cipher(algorithms.AES(self.peer_keys.encryption), modes.CBC(self.peer_iv)).encryptor()
        ciphertext = cipher.update(frame + bytes([0xc0 + count])*count) + cipher.finalize()
        body = bytes([len(ciphertext)//16 - 1]) + ciphertext
        mac = hmac.new(self.peer_keys.mac, self.peer_counter.to_bytes(4, "little") + body, hashlib.sha256).digest()[:8]
        self.peer_iv = ciphertext[-16:]
        self.peer_counter += 1
        outgoing = b''.join(self.probe.feed(bytes([b])) for b in b'\x40' + mac + body)
        return self.read_requests(outgoing)

    def test_both_hand_changes_write_only_the_boolean_then_read_back(self):
        for hand, value in [('left', 1), ('right', 0)]:
            with self.subTest(hand=hand):
                self.setUp()
                self.assertEqual(self.start_hand_session(hand), [(0x8007, {1: 5, 5: b''})])
                self.assertEqual(self.config_reply(5, 1-value), [(0x8007, {1: 6, 5: bytes([0x50, value])})])
                self.assertIsNone(self.probe.hand)
                # Even an echo of the desired value still requires a new read.
                self.assertEqual(self.config_reply(6, value), [(0x8007, {1: 7, 5: b''})])
                self.assertIsNone(self.probe.input_service.interaction.hand)
                self.assertEqual(self.config_reply(7, value), [])
                states = [data for event, data in self.events if event == 'interaction_state']
                self.assertEqual(states[-1]['hand'], hand)
                self.assertEqual(self.probe.hand, hand)
                self.assertIsNone(self.probe.hand_error)

    def test_no_preference_reads_existing_hand_without_a_write(self):
        self.start_hand_session()
        self.assertEqual(self.config_reply(5, 1), [])
        self.assertEqual(self.probe.hand, 'left')
        self.assertEqual(self.config_reply(5, 0), [])
        self.assertEqual(self.probe.hand, 'left')

    def test_matching_preference_needs_no_write(self):
        self.start_hand_session('right')
        self.assertEqual(self.config_reply(5, 0), [])
        self.assertEqual(self.probe.hand, 'right')

    def test_wrong_channel_stale_id_and_late_reply_cannot_confirm_hand(self):
        self.start_hand_session('left')
        self.assertEqual(self.config_reply(5, 1, channel=5), [])
        self.assertEqual(self.config_reply(4, 1), [])
        self.assertIsNone(self.probe.hand)
        self.now = 5
        self.assertEqual(self.config_reply(5, 1), [])
        self.assertIsNone(self.probe.hand)
        self.assertIn('timed out', self.probe.hand_error)

    def test_missing_invalid_rejected_and_mismatched_hand_are_not_success(self):
        for failure in ('missing', 'invalid', 'rejected_read', 'rejected_write', 'mismatch', 'timeout'):
            with self.subTest(failure=failure):
                self.setUp()
                self.start_hand_session('left')
                if failure == 'missing':
                    self.config_reply(5)
                elif failure == 'invalid':
                    self.config_reply(5, 2)
                elif failure == 'rejected_read':
                    self.config_reply(5, 1, status=2)
                else:
                    self.config_reply(5, 0)
                    if failure == 'rejected_write':
                        self.config_reply(6, status=2)
                    else:
                        self.config_reply(6)
                        if failure == 'mismatch':
                            self.config_reply(7, 0)
                        else:
                            self.now = 5
                            self.probe.tick()
                            self.config_reply(7, 1)
                self.assertIsNone(self.probe.hand)
                self.assertIsNotNone(self.probe.hand_error)
                states = [data for event, data in self.events if event == 'interaction_state']
                self.assertIsNone(states[-1]['hand'])
                self.assertFalse(states[-1]['engaged'])

    def test_fragmented_exchange_and_independently_encrypted_peer_reply(self):
        request = self.probe.request()
        self.assertEqual(request[:12].hex(), "806280018100000502000001")
        our = {n: v for n, w, v in protobuf_fields(request[12:])}
        outgoing = b"".join(self.probe.feed(bytes([byte])) for byte in self.request + self.enable)
        enable_size = (int.from_bytes(outgoing[:2], "big") & 0x7fff) + 4
        local_enable = {n: v for n, w, v in protobuf_fields(outgoing[8:enable_size])}
        local_public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + our[1])
        secret = self.peer_private.exchange(ec.ECDH(), local_public)
        keys = derive_keys(secret, self.peer_challenge, local_enable[2], 3)
        decoder = StreamDecryptor(keys, local_enable[3], local_enable[4], 3)
        decoded = list(decoder.feed(outgoing[enable_size:]))
        decoder.finish()
        self.assertEqual(decoded[0].plaintext.hex(), "800880028100002402003000c4c4c4c4")
        self.assertEqual(local_enable[1], our[1])
        self.assertEqual(local_enable[5], 3)

        peer_keys = derive_keys(secret, our[2], self.peer_seed, 3)
        expected = bytes.fromhex("8004800203003000") + bytes([0xc8]) * 8
        cipher = Cipher(algorithms.AES(peer_keys.encryption), modes.CBC(self.peer_iv)).encryptor()
        ciphertext = cipher.update(expected) + cipher.finalize()
        body = b"\x00" + ciphertext
        mac = hmac.new(peer_keys.mac, (42).to_bytes(4, "little") + body, hashlib.sha256).digest()[:8]
        self.assertEqual(self.probe.feed(b"\x40" + mac + body), b"")
        self.probe.finish()
        self.assertEqual(self.probe.authenticated_packets, 1)
        received = [values for event, values in self.events if event == "authenticated_packet"]
        self.assertEqual(received, [{"counter": 42, "plaintext": expected.hex()}])

    def test_enable_before_request_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unexpected peer enable"):
            self.probe.feed(self.enable)
        self.assertFalse(self.probe.query_sent)

    def test_optional_device_info_query_uses_next_iv_and_counter(self):
        self.probe.query_device_info = True
        outgoing = self.probe.feed(self.request + self.enable)
        enable_size = (int.from_bytes(outgoing[:2], "big") & 0x7fff) + 4
        local = {n: v for n, w, v in protobuf_fields(outgoing[8:enable_size])}
        public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + local[1])
        secret = self.peer_private.exchange(ec.ECDH(), public)
        decoder = StreamDecryptor(derive_keys(secret, self.peer_challenge, local[2], 3), local[3], local[4], 3)
        packets = list(decoder.feed(outgoing[enable_size:]))
        decoder.finish()
        self.assertEqual([p.plaintext.hex() for p in packets], [
            "800880028100002402003000c4c4c4c4", "800c80038100ce560200031408011a00"])
        self.assertEqual(packets[1].counter, (packets[0].counter + 1) & 0xffffffff)

    def test_failed_mac_does_not_release_plaintext(self):
        self.probe.feed(self.request + self.enable)
        with self.assertRaisesRegex(ValueError, "MAC failed"):
            self.probe.feed(bytes([0x40]) + bytes(25))
        self.assertEqual(self.probe.authenticated_packets, 0)
        self.assertFalse(any(event == "authenticated_packet" for event, values in self.events))

    def test_end_link_setup_has_fresh_uuid_and_precedes_device_info(self):
        self.probe.query_device_info = self.probe.end_link_setup = True
        outgoing = self.probe.feed(self.request + self.enable)
        size = (int.from_bytes(outgoing[:2], "big") & 0x7fff) + 4
        local = {n: v for n, w, v in protobuf_fields(outgoing[8:size])}
        public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + local[1])
        secret = self.peer_private.exchange(ec.ECDH(), public)
        decoder = StreamDecryptor(derive_keys(secret, self.peer_challenge, local[2], 3), local[3], local[4], 3)
        packets = list(decoder.feed(outgoing[size:]))
        decoder.finish()
        self.assertEqual(len(packets), 3)
        self.assertEqual(packets[1].plaintext[:8].hex(), "8018800102001000")
        fields = {n: v for n, w, v in protobuf_fields(packets[1].plaintext[8:28])}
        self.assertEqual(fields[1], 1)
        self.assertEqual(len(fields[2]), 16)
        self.assertNotEqual(fields[2], bytes(16))
        self.assertEqual(packets[2].plaintext.hex(), "800c80038100ce560200031408011a00")

    def test_incomplete_exchange_is_not_success(self):
        self.probe.feed(self.request + self.enable[:15])
        with self.assertRaisesRegex(ValueError, "exchange incomplete"):
            self.probe.finish()
        self.assertFalse(self.probe.query_sent)

    def test_raw_emg_exchange_and_disable_are_readable_by_peer(self):
        self.probe = BandHandshake(lambda *args, **kwargs: None, stream_control="raw-emg")
        outgoing = self.probe.feed(self.request + self.enable)
        size = (int.from_bytes(outgoing[:2], "big") & 0x7fff) + 4
        local = {n: v for n, w, v in protobuf_fields(outgoing[8:size])}
        public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + local[1])
        secret = self.peer_private.exchange(ec.ECDH(), public)
        decoder = StreamDecryptor(derive_keys(secret, self.peer_challenge, local[2], 3), local[3], local[4], 3)
        wire = outgoing[size:] + self.probe.stream_request(0x8005, 4, False)
        packets = list(decoder.feed(wire))
        decoder.finish()
        frames = list(datax_frames([{"plaintext": p.plaintext.hex(), "observed_complete": {}} for p in packets]))
        self.assertEqual(frames[1][1], [0x02001000])
        requests = [{n: v for n, w, v in protobuf_fields(payload)}
                    for ch, words, payload, at in frames if words == [0x8100ce56, 0x02000314] or (ch == 0x8005 and not words)]
        self.assertEqual(requests, [{1: 2, 4: b""}, {1: 3, 4: b"\x10\x01"}, {1: 4, 4: b"\x10\x00"}])
        self.assertEqual(frames[-1][:2], (0x8005, []))


if __name__ == "__main__":
    unittest.main()
