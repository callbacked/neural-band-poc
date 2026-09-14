"""AirShield parameters 3/31, verified against companion-app keys and packet MACs.

This module authenticates transport packets. It does not implement device identity
authentication, the complete DataX grammar, or a gesture subscription.
"""

import hashlib
import hmac
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


@dataclass(frozen=True)
class DirectionalKeys:
    encryption: bytes
    mac: bytes


def derive_keys(shared_secret, receiver_challenge, sender_seed, parameters):
    """Derive one direction's keys from the raw 32-byte P-256 shared secret."""
    if (len(shared_secret), len(receiver_challenge), len(sender_seed)) != (32, 16, 32):
        raise ValueError("expected a 32-byte secret, 16-byte challenge, and 32-byte seed")
    if parameters not in (3, 31):
        raise ValueError(f"unverified AirShield parameters: {parameters}")

    def sha(data):
        return hashlib.sha256(data).digest()

    def expand(ikm, salt):
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"AirShield").derive(ikm)

    if parameters == 3:
        hashed_secret = sha(shared_secret)
        encryption = expand(hashed_secret, sha(hashed_secret + receiver_challenge + sender_seed))
        return DirectionalKeys(encryption, encryption)
    encryption = expand(shared_secret, sha(receiver_challenge + sender_seed))
    mac = expand(shared_secret, sha(sender_seed + receiver_challenge + b"hmac_derive"))
    return DirectionalKeys(encryption, mac)


@dataclass(frozen=True)
class AuthenticatedPacket:
    counter: int
    block_count: int
    wire_bytes: int
    plaintext: bytes


@dataclass(frozen=True)
class UnauthenticatedRecord:
    kind: str
    channel: int
    wire_bytes: int
    payload: bytes


class StreamDecryptor:
    """Decode the observed relay framing, authenticating channel zero before CBC.

    In 0x40/0x41 records, byte 9 is the ciphertext block count minus one.
    Relay channels one and two remain unauthenticated by this decoder.
    Unknown framing and bad MACs fail without resynchronization or key-state
    advancement. Plaintext retains DataX padding.
    """

    def __init__(self, keys, iv, base, parameters):
        if parameters not in (3, 31):
            raise ValueError(f"unverified AirShield parameters: {parameters}")
        if len(keys.encryption) != 32 or len(keys.mac) != 32 or len(iv) != 16:
            raise ValueError("invalid key or IV length")
        if not 0 <= base <= 0xffffffff:
            raise ValueError("base must be uint32")
        self.keys = keys
        self.iv = iv
        self.counter = base
        self.prefix = b"\x02\x02\x00\x00" if parameters == 31 else b""
        self.buffer = bytearray()

    def feed(self, data):
        """Yield completed records; never yield plaintext from a failed MAC."""
        self.buffer.extend(data)
        while self.buffer:
            marker = self.buffer[0]
            if marker in (0x01, 0x02, 0x81, 0x82):
                if len(self.buffer) < 2:
                    return
                if marker in (0x81, 0x82) and self.buffer[1] in (0, 1):
                    code = bytes(self.buffer[1:2])
                    del self.buffer[:2]
                    yield UnauthenticatedRecord("control", marker & 0x3f, 2, code)
                    continue
                if marker in (0x01, 0x02):
                    size = 3 + self.buffer[1]
                    if len(self.buffer) < size:
                        return
                    payload = bytes(self.buffer[2:size])
                    del self.buffer[:size]
                    yield UnauthenticatedRecord("relay_plaintext", marker, size, payload)
                    continue
            if marker not in (0x40, 0x41, 0x42):
                raise ValueError(f"unsupported transport marker 0x{marker:02x}; refusing to resynchronize")
            if len(self.buffer) < 10:
                return
            blocks = self.buffer[9] + 1
            size = 10 + blocks * 16
            if len(self.buffer) < size:
                return
            if marker in (0x41, 0x42):
                payload = bytes(self.buffer[1:size])
                del self.buffer[:size]
                yield UnauthenticatedRecord("relay_encrypted", marker & 0x3f, size, payload)
                continue
            authenticated_data = self.prefix + self.counter.to_bytes(4, "little") + self.buffer[9:size]
            expected = hmac.new(self.keys.mac, authenticated_data, hashlib.sha256).digest()[:8]
            if not hmac.compare_digest(expected, self.buffer[1:9]):
                raise ValueError(f"packet MAC failed at counter {self.counter}; no plaintext released")
            ciphertext = bytes(self.buffer[10:size])
            decryptor = Cipher(algorithms.AES(self.keys.encryption), modes.CBC(self.iv)).decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            packet = AuthenticatedPacket(self.counter, blocks, size, plaintext)
            self.iv = ciphertext[-16:]
            self.counter = (self.counter + 1) & 0xffffffff
            del self.buffer[:size]
            yield packet

    def finish(self):
        if self.buffer:
            raise ValueError(f"{len(self.buffer)} bytes remain: truncated or unsupported transport frame")
