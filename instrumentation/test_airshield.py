"""Public reference vectors and fixed synthetic stream fixtures; no device keys."""

import hashlib
import hmac
import unittest

from airshield import AuthenticatedPacket, DirectionalKeys, StreamDecryptor, UnauthenticatedRecord, derive_keys


class AirShieldTests(unittest.TestCase):
    # Generated independently with cryptography AES-CBC and stdlib HMAC, using
    # key=00..1f, IV=00..0f, counters ffffffff then 00000000, parameters 3.
    first = bytes.fromhex("40c9f748fb0f0ae8e0018675352ee743a1e58ccd288d25d27f6e72551887e4aad6fc68175e7287a1eee1")
    second = bytes.fromhex("4038cb0decaa0692b900d5962230f8734c8a3de4d262936261f1")

    @staticmethod
    def decoder():
        return StreamDecryptor(DirectionalKeys(bytes(range(32)), bytes(range(32))), bytes(range(16)), 0xffffffff, 3)

    def test_public_parameter_31_vectors(self):
        # https://github.com/zhuowei/Starcruiser-mac/blob/1bc6f9418ad85a10991817c74e15a84f85078f53/key_derivation_test.swift
        secret = bytes.fromhex("f2f6f1f1a56fb52122ec338ed887338b42b976290253dbd6f48f3cc0b15b2ba8")
        rx = derive_keys(secret, bytes.fromhex("c75051fb3e50142ba10c15a023777c6b"), b"A" * 32, 31)
        self.assertEqual(rx.encryption.hex(), "d70b81653601bbc46f13c6749324fa2b680af0064592a2c663a0891d7a43875d")
        tx = derive_keys(secret, b"0123456789abcdef", bytes.fromhex(
            "c58e0f4bf291a0b2f50a40955b0bd53c9c7fd5a9f5fdbf7b14272efed585ca14"), 31)
        self.assertEqual(tx.encryption.hex(), "2f72596312c1120bf869dd69b0c6b4aa6cc05981723a45a4bb294343a11793cc")
        packet = bytes.fromhex("40f4d00bc5a22d9ecd0055ff7a63ea6ac9f1723721ffa9d7f4a7")
        tag = hmac.new(tx.mac, bytes.fromhex("02020000808b8dba") + packet[9:], hashlib.sha256).digest()[:8]
        self.assertEqual(tag, packet[1:9])

    def test_fragmentation_relay_and_counter_wrap(self):
        relay_payload = bytes(range(134))
        relay = b"\x01\x85" + relay_payload
        opaque = b"\x41" + bytes(8) + b"\x00" + bytes(16)
        data = self.first + b"\x81\x00" + relay + opaque + b"\x81\x01\x82\x00" + self.second
        decoder = self.decoder()
        records = []
        for start in range(0, len(data), 7):
            records.extend(decoder.feed(data[start:start + 7]))
        decoder.finish()
        packets = [row for row in records if isinstance(row, AuthenticatedPacket)]
        self.assertEqual([row.plaintext for row in packets],
                         [b"first block.....second block....", b"last block......"])
        self.assertEqual([row.counter for row in packets], [0xffffffff, 0])
        self.assertEqual([row.block_count for row in packets], [2, 1])
        clear = [row for row in records if isinstance(row, UnauthenticatedRecord)]
        self.assertEqual([(row.kind, row.channel) for row in clear],
                         [("control", 1), ("relay_plaintext", 1), ("relay_encrypted", 1), ("control", 1), ("control", 2)])
        self.assertEqual([row.payload for row in clear if row.kind == "control"], [b"\x00", b"\x01", b"\x00"])
        self.assertEqual(clear[1].payload, relay_payload)
        self.assertEqual(clear[2].payload, opaque[1:])

    def test_coalesced_frames(self):
        decoder = self.decoder()
        records = list(decoder.feed(self.first + self.second))
        decoder.finish()
        self.assertEqual([row.plaintext for row in records],
                         [b"first block.....second block....", b"last block......"])

    def test_bad_mac_releases_no_plaintext(self):
        for index in (1, 12):  # Both tag corruption and ciphertext corruption.
            with self.subTest(index=index):
                data = bytearray(self.first)
                data[index] ^= 1
                released = []
                with self.assertRaisesRegex(ValueError, "MAC failed"):
                    for record in self.decoder().feed(data):
                        released.append(record)
                self.assertEqual(released, [])

    def test_incorrect_counter_fails(self):
        decoder = StreamDecryptor(DirectionalKeys(bytes(range(32)), bytes(range(32))), bytes(range(16)), 0, 3)
        with self.assertRaisesRegex(ValueError, "MAC failed"):
            list(decoder.feed(self.first))

    def test_truncated_ciphertext_releases_no_plaintext(self):
        decoder = self.decoder()
        self.assertEqual(list(decoder.feed(self.first[:-1])), [])
        with self.assertRaisesRegex(ValueError, "bytes remain"):
            decoder.finish()

    def test_unverified_parameters_rejected(self):
        with self.assertRaisesRegex(ValueError, "unverified"):
            derive_keys(bytes(32), bytes(16), bytes(32), 7)


if __name__ == "__main__":
    unittest.main()
