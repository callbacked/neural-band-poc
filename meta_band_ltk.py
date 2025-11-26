#!/usr/bin/env python3
"""
Calculate LTK from BLE Secure Connections pairing data.

Uses the captured pairing exchange to derive the Long Term Key.
"""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import hashlib
import hmac

# From Wireshark capture - pairing public keys
IOS_PUBLIC_KEY_X = bytes.fromhex("511462e79815baeec959f2efc6d8f4ef048d7971e57bb0b8e8747f5a1056d275")
IOS_PUBLIC_KEY_Y = bytes.fromhex("a2053d8e4ccfabc742bbe001c7938f3cc144168925eebfbc70ddf0c20907f5a8")
BAND_PUBLIC_KEY_X = bytes.fromhex("b19964cd7eb298c6d06392e40c23699f819c26adf6b7d71b096c26d9b5dd626d")
BAND_PUBLIC_KEY_Y = bytes.fromhex("17eee0175625339fae33ae1dcf7ca2b9af4018cb1dd71526cf659603a995bc83")

# Random values from pairing
IOS_RANDOM = bytes.fromhex("7bcba138ab55140e1736b6f32d426a55")
BAND_RANDOM = bytes.fromhex("bf0bcedc2b939e6728ea8e508c709e74")

# DHKey checks
IOS_DHKEY_CHECK = bytes.fromhex("e37cc906e7d2e97a6c44034b270e917b")
BAND_DHKEY_CHECK = bytes.fromhex("a6d84d2bd34e7d974531d0de6cce016d")

# IRKs
BAND_IRK = bytes.fromhex("e05d0d10a6cbee7f48449ff16c3c6c9b")
IOS_IRK = bytes.fromhex("1a3148b262585b8cbe9ea9bb1b7ac7ed")

# Bluetooth addresses
BAND_ADDRESS = bytes.fromhex("cdac8f2b0ea4")  # a4:0e:2b:8f:ac:cd reversed
IOS_ADDRESS = bytes.fromhex("d9668f90b790")   # 90:b7:90:8f:66:d9 reversed


def aes_cmac(key, message):
    """AES-CMAC as used in BLE crypto functions."""
    # Simplified CMAC for 16-byte messages
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    # For full CMAC we need subkey generation, but for BLE f4/f5/f6
    # the message is always padded to block size

    # Generate subkeys
    L = encryptor.update(b'\x00' * 16)

    # Derive K1
    if L[0] & 0x80:
        K1 = bytes((b << 1) & 0xff for b in L)
        K1 = bytes([K1[0] ^ 0x00, *K1[1:-1], K1[-1] ^ 0x87])
    else:
        K1 = bytes((b << 1) & 0xff for b in L)

    # XOR last block with K1
    if len(message) == 16:
        last_block = bytes(a ^ b for a, b in zip(message, K1))
    else:
        # Pad and use K2
        padded = message + b'\x80' + b'\x00' * (15 - len(message))
        if K1[0] & 0x80:
            K2 = bytes((b << 1) & 0xff for b in K1)
            K2 = bytes([K2[0] ^ 0x00, *K2[1:-1], K2[-1] ^ 0x87])
        else:
            K2 = bytes((b << 1) & 0xff for b in K1)
        last_block = bytes(a ^ b for a, b in zip(padded, K2))

    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(last_block)


def f5(dhkey, n1, n2, a1, a2):
    """
    BLE f5 function for LTK derivation.

    Returns (MacKey, LTK) tuple.

    f5(DHKey, N1, N2, A1, A2) generates:
    - MacKey (for DHKey check)
    - LTK (Long Term Key)
    """
    # Salt for f5
    salt = bytes.fromhex("6C888391AAF5A53860370BDB5A6083BE")

    # T = AES-CMAC_salt(DHKey)
    T = aes_cmac(salt, dhkey)

    # Counter 0 -> MacKey
    # Counter 1 -> LTK

    keyID = b"btle"

    # MacKey = AES-CMAC_T(0 || keyID || N1 || N2 || A1 || A2 || 256)
    m0 = bytes([0]) + keyID + n1 + n2 + a1 + a2 + bytes([1, 0])  # 256 in little endian
    MacKey = aes_cmac(T, m0)

    # LTK = AES-CMAC_T(1 || keyID || N1 || N2 || A1 || A2 || 256)
    m1 = bytes([1]) + keyID + n1 + n2 + a1 + a2 + bytes([1, 0])
    LTK = aes_cmac(T, m1)

    return MacKey, LTK


def compute_dhkey():
    """
    We can't compute DHKey without the private key.
    But we can verify our calculation by checking against DHKey checks.

    For now, let's see if we can work backwards or find another way.
    """
    print("="*60)
    print("BLE Secure Connections LTK Derivation")
    print("="*60)

    print("\nCaptured pairing data:")
    print(f"  iOS Public Key X:  {IOS_PUBLIC_KEY_X.hex()}")
    print(f"  iOS Public Key Y:  {IOS_PUBLIC_KEY_Y.hex()}")
    print(f"  Band Public Key X: {BAND_PUBLIC_KEY_X.hex()}")
    print(f"  Band Public Key Y: {BAND_PUBLIC_KEY_Y.hex()}")
    print(f"  iOS Random (N_i):  {IOS_RANDOM.hex()}")
    print(f"  Band Random (N_r): {BAND_RANDOM.hex()}")
    print(f"  iOS DHKey Check:   {IOS_DHKEY_CHECK.hex()}")
    print(f"  Band DHKey Check:  {BAND_DHKEY_CHECK.hex()}")

    print("\n" + "-"*60)
    print("Problem: We don't have the ECDH private keys")
    print("-"*60)

    print("""
The DHKey (shared secret) was computed during pairing:
  DHKey = P256(PrivKey_iOS, PubKey_Band)
        = P256(PrivKey_Band, PubKey_iOS)

Without either private key, we can't compute the DHKey.
The DHKey checks are computed as:
  E_a = f6(MacKey, N_a, N_b, r, IOcap_a, A_a, A_b)

We have the checks but can't reverse them to get DHKey.
""")

    print("-"*60)
    print("Alternative: The LTK might be stored in iOS Keychain")
    print("-"*60)

    print("""
When you paired with PacketLogger running, iOS stored the LTK.
It's in the Keychain but requires special entitlements to access.

Options:
1. Use 'keychain-dumper' on jailbroken iOS
2. Use macOS Keychain Access (if synced via iCloud)
3. Check if macOS stored it when you paired with the Mac

Let's check if macOS has the pairing info...
""")

    # The IRK is useful though - we can use it to resolve RPAs
    print("-"*60)
    print("IRK (Identity Resolving Key) - We have this!")
    print("-"*60)
    print(f"  Band IRK: {BAND_IRK.hex()}")
    print(f"  iOS IRK:  {IOS_IRK.hex()}")

    print("""
The IRK lets us identify the band even when it uses random addresses.
But we need the LTK or DHKey for the session encryption.
""")

    # Let's try to see if the session key might just use IRK
    print("-"*60)
    print("Testing if session uses IRK instead of LTK...")
    print("-"*60)

    # Various combinations
    test_keys = {
        "BAND_IRK": BAND_IRK,
        "IOS_IRK": IOS_IRK,
        "IRK XOR": bytes(a ^ b for a, b in zip(BAND_IRK, IOS_IRK)),
        "IRK concat hash": hashlib.sha256(BAND_IRK + IOS_IRK).digest(),
        "Randoms hash": hashlib.sha256(IOS_RANDOM + BAND_RANDOM).digest(),
    }

    for name, key in test_keys.items():
        if len(key) == 16:
            key = key + key  # Extend to 32 bytes
        print(f"  {name}: {key.hex()[:32]}...")

    return test_keys


if __name__ == "__main__":
    keys = compute_dhkey()

    print("\n" + "="*60)
    print("Possible session keys to try:")
    print("="*60)
    for name, key in keys.items():
        if len(key) == 16:
            key = key + key
        print(f"{name}:")
        print(f"  {key.hex()}")
