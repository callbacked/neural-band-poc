#!/usr/bin/env python3
"""
Analyze the captured handshake to determine what the phone encrypts.

Using exact values from Wireshark capture:
- Frame 670: Band's 0x60 (band pubkey + nonce)
- Frame 672: Phone's 0x60 (phone pubkey + nonce)
- Frame 673: Phone's 0x82 (phone pubkey + encrypted data)
"""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hashlib

# LTK from macOS Keychain
LTK = bytes.fromhex("87a04e3bf1fe379251ed6cd050109707")

# Band's data (Frame 670)
BAND_PUBKEY_X = bytes.fromhex("eba5bea8f33ea98056878f517c0caba0a66a82963121aa3af383fbeac955b7cb")
BAND_PUBKEY_Y = bytes.fromhex("8a5d209da273537063b5ea520b32cd18acb56dd9b1a8f1b6a6138d2e9548f353")
BAND_NONCE = bytes.fromhex("ab47d22141c5283edf48f37f2f692096")

# Phone's data (Frame 672)
PHONE_PUBKEY_X = bytes.fromhex("34548dace628eb6add2c0417a16ee02c4d196a987879f2e895c4ecd13affa519")
PHONE_PUBKEY_Y = bytes.fromhex("c9de7223137b49e492005b6946e85ad1d80294782c1b3e079b39861345059c6b")
PHONE_NONCE = bytes.fromhex("62a8ecef32ab848a7b12ad22303d0c7c")

# Phone's 0x82 encrypted data (Frame 673)
PHONE_CIPHERTEXT = bytes.fromhex("d9b41921dbfaa688cd7be94c4046c064645d78e04508e8cd0ac742cebf67f944")
PHONE_AUTH_TAG = bytes.fromhex("b7f64972200cc27c35f7fe3a441cb7f6")


def bytes_to_public_key(x_bytes, y_bytes):
    """Convert raw bytes to EC public key object."""
    point_bytes = b'\x04' + x_bytes + y_bytes
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point_bytes)


def main():
    print("=" * 60)
    print("Analyzing Phone's Encrypted Response")
    print("=" * 60)

    # We need to derive the same shared secret the phone used
    # The phone has its private key + band's public key
    # We don't have phone's private key, but we can try to figure out what was encrypted

    print("\nCaptured Data:")
    print(f"  Band pubkey X:    {BAND_PUBKEY_X.hex()}")
    print(f"  Band pubkey Y:    {BAND_PUBKEY_Y.hex()}")
    print(f"  Band nonce:       {BAND_NONCE.hex()}")
    print(f"  Phone pubkey X:   {PHONE_PUBKEY_X.hex()}")
    print(f"  Phone pubkey Y:   {PHONE_PUBKEY_Y.hex()}")
    print(f"  Phone nonce:      {PHONE_NONCE.hex()}")
    print(f"  Ciphertext:       {PHONE_CIPHERTEXT.hex()}")
    print(f"  Auth tag:         {PHONE_AUTH_TAG.hex()}")
    print(f"  LTK:              {LTK.hex()}")

    # Ciphertext is 32 bytes + 16-byte tag = 48 bytes total
    # AES-GCM ciphertext length = plaintext length
    # So plaintext is 32 bytes

    print(f"\nPlaintext length: 32 bytes (based on ciphertext size)")

    # What could 32 bytes be?
    print("\nPossible 32-byte plaintext candidates:")

    # 1. Hash of shared secret
    print("  1. SHA256(shared_secret) - most likely")

    # 2. Hash of combined nonces
    combined_nonces = BAND_NONCE + PHONE_NONCE
    hash_nonces = hashlib.sha256(combined_nonces).digest()
    print(f"  2. SHA256(band_nonce + phone_nonce) = {hash_nonces.hex()}")

    # 3. Hash of public keys
    phone_pubkey = PHONE_PUBKEY_X + PHONE_PUBKEY_Y
    band_pubkey = BAND_PUBKEY_X + BAND_PUBKEY_Y
    hash_pubkeys = hashlib.sha256(band_pubkey + phone_pubkey).digest()
    print(f"  3. SHA256(band_pubkey + phone_pubkey) = {hash_pubkeys.hex()}")

    # 4. Raw shared secret (32 bytes from ECDH)
    print("  4. Raw ECDH shared secret")

    # 5. Nonces concatenated (only 32 bytes if both nonces)
    print(f"  5. band_nonce + phone_nonce = {combined_nonces.hex()}")

    # 6. Hash with LTK
    hash_with_ltk = hashlib.sha256(BAND_NONCE + PHONE_NONCE + LTK).digest()
    print(f"  6. SHA256(band_nonce + phone_nonce + LTK) = {hash_with_ltk.hex()}")

    # Now, since we have the actual ciphertext and tag, we can work backwards
    # if we can somehow compute or guess the key

    print("\n" + "=" * 60)
    print("Trying to reverse-engineer the encryption")
    print("=" * 60)

    # The phone and band both know:
    # - Their shared secret (from ECDH)
    # - Both public keys
    # - Both nonces
    # - The LTK (from prior BLE pairing)

    # Key derivation possibilities:
    # We can't compute the actual shared secret without phone's private key
    # BUT we can see patterns by checking what the nonce might be

    print("\nAnalyzing nonce patterns:")

    # Check if ciphertext XOR with potential plaintext gives us hints
    # If plaintext = zeros, ciphertext = AES_key_stream

    # Check if first 12 bytes of anything match what could be a nonce
    potential_nonces = [
        ("Zero nonce", b'\x00' * 12),
        ("Band nonce truncated", BAND_NONCE[:12]),
        ("Phone nonce truncated", PHONE_NONCE[:12]),
        ("Counter = 1", bytes(11) + b'\x01'),
        ("Counter = 2", bytes(11) + b'\x02'),
    ]

    for name, nonce in potential_nonces:
        print(f"  {name}: {nonce.hex()}")

    # Check structure of the encrypted data
    print("\n" + "=" * 60)
    print("Encryption structure analysis")
    print("=" * 60)

    # In the 0x82 message, the ciphertext is 32 bytes
    # The standard confirmation in many protocols is:
    # - Hash of transcript
    # - Encrypted public key hash
    # - Encrypted nonce combination

    # Let's check if field2 (32 bytes) might actually be split:
    # - 16 bytes encrypted data
    # - 16 bytes that relate to field3

    ct_first_half = PHONE_CIPHERTEXT[:16]
    ct_second_half = PHONE_CIPHERTEXT[16:]

    print(f"\nCiphertext split analysis:")
    print(f"  First 16 bytes:  {ct_first_half.hex()}")
    print(f"  Second 16 bytes: {ct_second_half.hex()}")
    print(f"  Auth tag:        {PHONE_AUTH_TAG.hex()}")

    # Check if second half matches auth tag pattern
    if ct_second_half == PHONE_AUTH_TAG:
        print("  -> Second half equals auth tag! Field2 might be 16-byte CT + 16-byte tag")

    # Check for patterns
    print("\nLooking for patterns in ciphertext...")

    # XOR analysis between parts
    xor_halves = bytes(a ^ b for a, b in zip(ct_first_half, ct_second_half))
    print(f"  XOR of halves: {xor_halves.hex()}")

    xor_with_tag = bytes(a ^ b for a, b in zip(ct_second_half, PHONE_AUTH_TAG))
    print(f"  XOR ct2 with tag: {xor_with_tag.hex()}")

    # The important insight: we need to replicate what the phone does
    # Since we'll have our OWN shared secret with the band, we need to know:
    # 1. What plaintext to encrypt (probably transcript hash or nonce combination)
    # 2. What key derivation to use (HKDF with LTK?)
    # 3. What nonce to use

    print("\n" + "=" * 60)
    print("Recommendation for implementation")
    print("=" * 60)

    print("""
Based on analysis, the phone likely encrypts:

PLAINTEXT (32 bytes): One of:
  - SHA256(shared_secret)
  - SHA256(band_nonce || phone_nonce)
  - SHA256(shared_secret || band_pubkey || phone_pubkey)
  - The combined nonces directly (band_nonce || phone_nonce)

KEY (32 bytes): Derived via:
  - HKDF(shared_secret, salt=LTK, info="")
  - Or SHA256(shared_secret || LTK)

NONCE (12 bytes): Likely:
  - All zeros (0x00 * 12)
  - Or band_nonce[:12]
  - Or counter-based

To test, modify build_response_message() to try each combination.
The band will only respond with its 0x82 when we get it right.
""")

    # Generate test cases
    print("\n" + "=" * 60)
    print("Test cases for build_response_message()")
    print("=" * 60)

    print("""
Try these plaintexts in order:

1. Combined nonces:
   plaintext = band_nonce + our_nonce  # 32 bytes

2. Hash of shared secret:
   plaintext = hashlib.sha256(shared_secret).digest()

3. Hash of transcript:
   plaintext = hashlib.sha256(shared_secret + band_pubkey + our_pubkey).digest()

4. Hash of nonces + shared secret:
   plaintext = hashlib.sha256(band_nonce + our_nonce + shared_secret).digest()

5. Simple confirmation (current):
   plaintext = b'\\x00' * 32

Key derivation - try these:
1. HKDF(shared_secret, salt=LTK)  [current]
2. SHA256(shared_secret + LTK)
3. SHA256(LTK + shared_secret)

Nonce - try these:
1. b'\\x00' * 12  [current]
2. band_nonce[:12]
3. bytes(11) + b'\\x01'
""")


if __name__ == "__main__":
    main()
