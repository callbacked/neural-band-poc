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
from mac_band_probe import BandHandshake
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
