import hashlib
import hmac
import unittest
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from analyze_capture import protobuf_fields
from owner_auth import OwnerTrust
from mac_band_probe import typed_frame, field, BandHandshake
from airshield import derive_keys, StreamDecryptor


def padded(frame):
    n=(-len(frame))%16
    return frame+bytes([0xc0+n])*n


class OwnerTrustTests(unittest.TestCase):
    def setUp(self):
        self.key=ec.generate_private_key(ec.SECP256R1())
        self.auth=OwnerTrust(self.key,lambda *a,**k:None)

    def test_proof_binds_both_handshake_halves_and_role(self):
        challenge=bytes(range(16));seed=bytes(range(32));peer=b'p'*64;local=b'l'*64
        f={n:v for n,w,v in protobuf_fields(self.auth.proof(challenge,peer,seed,local))}
        public=self.key.public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint)[1:]
        self.assertEqual(f[1],hashlib.sha256(public).digest());self.assertEqual(f[3],2)
        digest=hashlib.sha256(hashlib.sha256(challenge+peer).digest()+hashlib.sha256(seed+local).digest()).digest()
        sig=utils.encode_dss_signature(int.from_bytes(f[2][:32],'big'),int.from_bytes(f[2][32:],'big'))
        self.key.public_key().verify(sig,digest,ec.ECDSA(utils.Prehashed(hashes.SHA256())))

    def test_requires_ack_and_peer_setup_in_either_order(self):
        ack=padded(typed_frame(2,[0x03001000]))
        end=padded(typed_frame(0x9001,[0x02001000],field(1,1)+field(2,b'x'*16)))
        for inputs in [(ack,end),(end,ack)]:
            a=OwnerTrust(self.key,lambda *a,**k:None)
            list(a.feed(inputs[0]));self.assertFalse(a.ready)
            list(a.feed(inputs[1]));self.assertTrue(a.ready)

    def test_rejection_fails_closed(self):
        with self.assertRaisesRegex(ValueError,'rejected'):
            list(self.auth.feed(padded(typed_frame(2,[0x03001043]))))
        self.assertFalse(self.auth.ready)

    def test_wrong_channel_does_not_authenticate(self):
        list(self.auth.feed(padded(typed_frame(3,[0x03001000]))))
        self.assertFalse(self.auth.accepted)

    def test_wrong_curve_rejected(self):
        with self.assertRaises(ValueError):OwnerTrust(ec.generate_private_key(ec.SECP384R1()),lambda *a,**k:None)

    def test_owner_startup_waits_for_auth(self):
        peer=ec.generate_private_key(ec.SECP256R1());pub=peer.public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint)[1:]
        p=BandHandshake(lambda *a,**k:None,query_device_info=True,identity_key=self.key)
        request=typed_frame(0x8001,[0x81000005,0x02000001],field(1,pub)+field(2,b'c'*16)+field(4,27))
        enable=typed_frame(1,[0x02000002],field(1,pub)+field(2,b's'*32)+field(3,b'i'*16)+field(4,10)+field(5,26))
        out=p.feed(request+enable);size=(int.from_bytes(out[:2],'big')&0x7fff)+4
        self.assertEqual(p.tx_parameters,27);self.assertFalse(p.startup_sent)
        secret=peer.exchange(ec.ECDH(),p.private.public_key())
        # Only the trust proof may be sent before acknowledgement, no RPC/end-setup.
        tx_fields={n:v for n,w,v in protobuf_fields(out[8:size])}
        d=StreamDecryptor(derive_keys(secret,b'c'*16,tx_fields[2],27),tx_fields[3],tx_fields[4],27)
        packets=list(d.feed(out[size:]));self.assertEqual(len(packets),1)
        self.assertIn(bytes.fromhex('8100002402001000'),packets[0].plaintext)
        with self.assertRaisesRegex(ValueError,'incomplete'):p.finish()
        # Simulate the band's parameter-26 reply and decrypt subsequent host RPCs.
        rx = derive_keys(secret, p.challenge, b's'*32, 26)
        plaintext = padded(typed_frame(2, [0x03001000]) +
            typed_frame(0x9001, [0x02001000], field(2, b'x'*16)))
        cipher = Cipher(algorithms.AES(rx.encryption), modes.CBC(b'i'*16)).encryptor()
        ciphertext = cipher.update(plaintext) + cipher.finalize()
        body = bytes([len(ciphertext)//16-1]) + ciphertext
        tag = hmac.new(rx.mac, bytes.fromhex('02020000') + (10).to_bytes(4, 'little') + body,
                       hashlib.sha256).digest()[:8]
        outgoing = p.feed(b'\x40' + tag + body)
        self.assertTrue(p.owner.ready)
        self.assertTrue(p.startup_sent)
        requests = list(d.feed(outgoing))
        self.assertEqual(len(requests), 2)  # EndLinkSetup, then device info.
        self.assertIn(bytes.fromhex('8100ce5602000314'), requests[1].plaintext)
        self.assertEqual(p.start_services(), b'')
        p.finish()
        d.finish()

    def test_peer_setup_omitted_state_means_zero(self):
        list(self.auth.feed(padded(typed_frame(0x9001,[0x02001000],field(2,b'x'*16)))))
        self.assertTrue(self.auth.peer_setup)
        self.assertFalse(self.auth.ready)
