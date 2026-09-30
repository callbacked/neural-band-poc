"""Observed legacy owner trust, opt-in with an already enrolled P-256 identity.

The acknowledgement proves the peer accepted our identity; it does not verify
peer identity. No enrollment, reset, or Constellation manifest installation.
"""
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from extract_telemetry import DataXStream, checked_fields


class OwnerTrust:
    def __init__(self, private_key, emit):
        if not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(private_key.curve, ec.SECP256R1):
            raise ValueError('Owner identity must be a P-256 private key')
        self.key, self.emit = private_key, emit
        self.frames = DataXStream()
        self.accepted = self.peer_setup = False

    def proof(self, peer_challenge, peer_public, local_seed, local_public):
        from cryptography.hazmat.primitives import serialization
        if tuple(map(len, (peer_challenge, peer_public, local_seed, local_public))) != (16, 64, 32, 64):
            raise ValueError('Invalid owner trust transcript lengths')
        sha = lambda b: hashlib.sha256(b).digest()
        digest = sha(sha(peer_challenge + peer_public) + sha(local_seed + local_public))
        r, s = utils.decode_dss_signature(self.key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256()))))
        public = self.key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)[1:]
        return b'\x0a\x20' + sha(public) + b'\x12\x40' + r.to_bytes(32, 'big') + s.to_bytes(32, 'big') + b'\x18\x02'

    @property
    def ready(self):
        return self.accepted and self.peer_setup

    def feed(self, plaintext):
        for channel, words, payload, _ in self.frames.feed(plaintext, {}):
            if words == [0x81000024, 0x02001001]:
                fields = checked_fields(payload)
                if not channel & 0x8000 or len(fields.get((2, 2), b'')) != 64:
                    raise ValueError('Malformed peer trust offer')
                self.emit('peer_trust_offer', peer_identity_verified=False)
                yield channel & 0x7fff, [0x03001000], b''
            elif words == [0x8100004f, 0x02000001]:
                yield channel & 0x7fff, [0x0300c001], b''
            elif channel == 2 and words == [0x03001000]:
                self.accepted = True
                self.emit('owner_trust_accepted', peer_identity_verified=False)
            elif channel == 2 and words and words[0] >> 24 == 3:
                raise ValueError(f'Owner identity rejected: 0x{words[0]:08x}')
            elif words == [0x02001000]:
                fields = checked_fields(payload)
                if fields.get((1, 0), 0) not in (0, 1) or len(fields.get((2, 2), b'')) != 16:
                    raise ValueError('Malformed peer EndLinkSetup')
                self.peer_setup = True
                self.emit('peer_link_setup_received')
