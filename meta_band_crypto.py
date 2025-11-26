#!/usr/bin/env python3
"""
Meta Neural Band Crypto Experiments

Try common crypto patterns to see if we can generate valid responses.
"""

import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import os

# From the Wireshark capture - pairing data
BAND_IRK = bytes.fromhex("e05d0d10a6cbee7f48449ff16c3c6c9b")
IOS_IRK = bytes.fromhex("1a3148b262585b8cbe9ea9bb1b7ac7ed")

# Public keys from pairing (P-256 curve points)
IOS_PUBLIC_KEY_X = bytes.fromhex("511462e79815baeec959f2efc6d8f4ef048d7971e57bb0b8e8747f5a1056d275")
IOS_PUBLIC_KEY_Y = bytes.fromhex("a2053d8e4ccfabc742bbe001c7938f3cc144168925eebfbc70ddf0c20907f5a8")
BAND_PUBLIC_KEY_X = bytes.fromhex("b19964cd7eb298c6d06392e40c23699f819c26adf6b7d71b096c26d9b5dd626d")
BAND_PUBLIC_KEY_Y = bytes.fromhex("17eee0175625339fae33ae1dcf7ca2b9af4018cb1dd71526cf659603a995bc83")

# Random values from pairing
IOS_RANDOM = bytes.fromhex("7bcba138ab55140e1736b6f32d426a55")
BAND_RANDOM = bytes.fromhex("bf0bcedc2b939e6728ea8e508c709e74")

# DHKey checks from pairing
IOS_DHKEY_CHECK = bytes.fromhex("e37cc906e7d2e97a6c44034b270e917b")
BAND_DHKEY_CHECK = bytes.fromhex("a6d84d2bd34e7d974531d0de6cce016d")

# Example band init message (the 64-byte blob + other fields)
EXAMPLE_BAND_INIT = bytes.fromhex(
    "8060800181000005020000010a40"
    "6a738f4560fc0348bdf27628ac2daacc494081194b20f76456df53b003997cc0"
    "1ab3a97c0ed4061faf95dee4d3881c73361af1ff84e6071245c075260c6f0ef6"
    "1210441e7e13fc27650fcdb4ffea25738be018002003"
)

def extract_fields(data):
    """Extract protobuf-like fields from message."""
    if len(data) < 14:
        return None

    # Skip 12-byte header
    payload = data[12:]

    fields = {}
    i = 0
    while i < len(payload):
        if i >= len(payload):
            break
        tag = payload[i]

        if tag == 0x0a:  # Field 1 (length-delimited)
            length = payload[i+1]
            fields['field1'] = payload[i+2:i+2+length]
            i += 2 + length
        elif tag == 0x12:  # Field 2 (length-delimited)
            length = payload[i+1]
            fields['field2'] = payload[i+2:i+2+length]
            i += 2 + length
        elif tag == 0x1a:  # Field 3 (length-delimited)
            length = payload[i+1]
            fields['field3'] = payload[i+2:i+2+length]
            i += 2 + length
        elif tag == 0x18:  # Field 3 (varint)
            fields['field3_varint'] = payload[i+1]
            i += 2
        elif tag == 0x20:  # Field 4 (varint)
            fields['field4_varint'] = payload[i+1]
            i += 2
        else:
            i += 1

    return fields


def try_aes_gcm_decrypt(key, nonce, ciphertext, aad=b''):
    """Try AES-GCM decryption."""
    try:
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
        return plaintext
    except Exception as e:
        return None


def try_chacha_decrypt(key, nonce, ciphertext, aad=b''):
    """Try ChaCha20-Poly1305 decryption."""
    try:
        chacha = ChaCha20Poly1305(key)
        plaintext = chacha.decrypt(nonce, ciphertext, aad)
        return plaintext
    except Exception as e:
        return None


def derive_key_hkdf(ikm, salt, info, length=32):
    """Derive key using HKDF."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
        backend=default_backend()
    )
    return hkdf.derive(ikm)


def try_common_keys():
    """Try various key derivation approaches."""

    print("="*60)
    print("Attempting to crack Meta Band crypto")
    print("="*60)

    fields = extract_fields(EXAMPLE_BAND_INIT)
    if not fields:
        print("Failed to extract fields")
        return

    blob_64 = fields.get('field1', b'')
    field2 = fields.get('field2', b'')

    print(f"\n64-byte blob: {blob_64.hex()}")
    print(f"Field 2 (16 bytes): {field2.hex()}")

    # Possible key sources
    key_sources = [
        ("BAND_IRK", BAND_IRK),
        ("IOS_IRK", IOS_IRK),
        ("IRK XOR", bytes(a ^ b for a, b in zip(BAND_IRK, IOS_IRK))),
        ("IOS_RANDOM", IOS_RANDOM),
        ("BAND_RANDOM", BAND_RANDOM),
        ("Random XOR", bytes(a ^ b for a, b in zip(IOS_RANDOM, BAND_RANDOM))),
        ("DHKey Check iOS", IOS_DHKEY_CHECK),
        ("DHKey Check Band", BAND_DHKEY_CHECK),
    ]

    # Possible nonces
    nonce_sources = [
        ("field2", field2),
        ("field2[:12]", field2[:12] if len(field2) >= 12 else field2),
        ("zeros", b'\x00' * 12),
        ("zeros_16", b'\x00' * 16),
    ]

    # Try different interpretations of the 64-byte blob
    blob_interpretations = [
        ("full_64", blob_64),  # Full blob as ciphertext+tag
        ("48+16", blob_64[:48], blob_64[48:]),  # 48 bytes cipher, 16 tag
        ("32+32", blob_64[:32], blob_64[32:]),  # Two 32-byte halves
    ]

    print("\n" + "-"*60)
    print("Trying AES-GCM with various key/nonce combinations...")
    print("-"*60)

    for key_name, key_base in key_sources:
        # Extend key to 32 bytes if needed
        if len(key_base) == 16:
            key_32 = key_base + key_base  # Simple doubling
            key_32_hash = hashlib.sha256(key_base).digest()
        else:
            key_32 = key_base[:32]
            key_32_hash = key_base[:32]

        for nonce_name, nonce in nonce_sources:
            # AES-GCM needs 12-byte nonce typically
            if len(nonce) > 12:
                nonce = nonce[:12]
            elif len(nonce) < 12:
                nonce = nonce + b'\x00' * (12 - len(nonce))

            # Try with 48-byte ciphertext + 16-byte tag
            ciphertext_with_tag = blob_64  # GCM tag is usually appended

            # Try raw key
            result = try_aes_gcm_decrypt(key_32, nonce, ciphertext_with_tag)
            if result:
                print(f"\n*** SUCCESS with {key_name} (doubled) + {nonce_name}! ***")
                print(f"Plaintext: {result.hex()}")
                return

            # Try hashed key
            result = try_aes_gcm_decrypt(key_32_hash, nonce, ciphertext_with_tag)
            if result:
                print(f"\n*** SUCCESS with SHA256({key_name}) + {nonce_name}! ***")
                print(f"Plaintext: {result.hex()}")
                return

    print("\n" + "-"*60)
    print("Trying HKDF-derived keys...")
    print("-"*60)

    # Common HKDF patterns
    hkdf_attempts = [
        (BAND_IRK, IOS_RANDOM, b"meta"),
        (BAND_IRK, BAND_RANDOM, b"meta"),
        (IOS_IRK, IOS_RANDOM, b"meta"),
        (BAND_IRK + IOS_IRK, None, b"session"),
        (IOS_RANDOM + BAND_RANDOM, None, b"key"),
        (BAND_IRK, field2, b""),
        (IOS_IRK, field2, b""),
    ]

    for ikm, salt, info in hkdf_attempts:
        try:
            derived_key = derive_key_hkdf(ikm, salt, info)

            for nonce_name, nonce in nonce_sources:
                if len(nonce) > 12:
                    nonce = nonce[:12]
                elif len(nonce) < 12:
                    nonce = nonce + b'\x00' * (12 - len(nonce))

                result = try_aes_gcm_decrypt(derived_key, nonce, blob_64)
                if result:
                    print(f"\n*** SUCCESS with HKDF({ikm[:8].hex()}..., {salt[:8].hex() if salt else 'None'}..., {info}) + {nonce_name}! ***")
                    print(f"Plaintext: {result.hex()}")
                    return
        except Exception as e:
            pass

    print("\n" + "-"*60)
    print("Trying ChaCha20-Poly1305...")
    print("-"*60)

    for key_name, key_base in key_sources:
        if len(key_base) == 16:
            key_32 = key_base + key_base
        else:
            key_32 = key_base[:32]

        for nonce_name, nonce in nonce_sources:
            if len(nonce) > 12:
                nonce = nonce[:12]
            elif len(nonce) < 12:
                nonce = nonce + b'\x00' * (12 - len(nonce))

            result = try_chacha_decrypt(key_32, nonce, blob_64)
            if result:
                print(f"\n*** SUCCESS with ChaCha20 {key_name} + {nonce_name}! ***")
                print(f"Plaintext: {result.hex()}")
                return

    print("\n" + "-"*60)
    print("Checking if blob might be raw ECDH public key...")
    print("-"*60)

    # Check if the 64 bytes could be an uncompressed EC point (without 0x04 prefix)
    # P-256 points are 32 bytes X + 32 bytes Y
    x = int.from_bytes(blob_64[:32], 'big')
    y = int.from_bytes(blob_64[32:], 'big')

    # P-256 curve parameters
    p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff

    # Check if point is on curve: y^2 = x^3 - 3x + b (mod p)
    b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b

    left = (y * y) % p
    right = (pow(x, 3, p) - 3 * x + b) % p

    if left == right:
        print(f"*** The 64-byte blob IS a valid P-256 point! ***")
        print(f"X: {blob_64[:32].hex()}")
        print(f"Y: {blob_64[32:].hex()}")
        print("\nThis suggests ephemeral ECDH key exchange per session!")
    else:
        print("64-byte blob is NOT a valid P-256 point")
        print("Likely encrypted data, not a public key")

    print("\n" + "-"*60)
    print("Trying simple XOR patterns...")
    print("-"*60)

    # Maybe it's just XOR'd with something?
    for key_name, key in key_sources:
        if len(key) == 16:
            # Repeat key to match blob length
            expanded_key = (key * 4)[:64]
            xored = bytes(a ^ b for a, b in zip(blob_64, expanded_key))

            # Check if result looks like plaintext (printable ASCII or structured)
            printable = sum(1 for b in xored if 32 <= b <= 126)
            if printable > 40:  # More than 60% printable
                print(f"XOR with {key_name} gives {printable}/64 printable chars:")
                print(f"  {xored}")

    print("\n" + "="*60)
    print("No luck with common patterns.")
    print("The crypto is likely using session-derived keys from ECDH.")
    print("="*60)


if __name__ == "__main__":
    try_common_keys()
