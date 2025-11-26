#!/usr/bin/env python3
"""
Extract LTK from BLE Secure Connections pairing capture.

Parses PacketLogger/Wireshark capture to find the pairing data
and computes the LTK using the BLE f5 function.

Usage:
    python extract_ltk.py <capture.pcapng>

Or paste the pairing data manually when prompted.
"""

import sys
import re
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def aes_cmac(key, message):
    """
    AES-CMAC implementation for BLE crypto functions.
    """
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())

    # Generate subkey L
    encryptor = cipher.encryptor()
    L = encryptor.update(b'\x00' * 16)

    # Generate K1
    carry = (L[0] >> 7) & 1
    K1 = bytearray(16)
    for i in range(15, 0, -1):
        K1[i] = ((L[i] << 1) | ((L[i-1] >> 7) & 1)) & 0xff
    K1[0] = (L[0] << 1) & 0xff
    if carry:
        K1[15] ^= 0x87
    K1 = bytes(K1)

    # Generate K2
    carry = (K1[0] >> 7) & 1
    K2 = bytearray(16)
    for i in range(15, 0, -1):
        K2[i] = ((K1[i] << 1) | ((K1[i-1] >> 7) & 1)) & 0xff
    K2[0] = (K1[0] << 1) & 0xff
    if carry:
        K2[15] ^= 0x87
    K2 = bytes(K2)

    # Process message
    n_blocks = (len(message) + 15) // 16
    if n_blocks == 0:
        n_blocks = 1

    # Pad if necessary
    if len(message) % 16 != 0 or len(message) == 0:
        padded = message + b'\x80' + b'\x00' * (16 - 1 - (len(message) % 16))
        last_block = bytes(a ^ b for a, b in zip(padded[-16:], K2))
    else:
        last_block = bytes(a ^ b for a, b in zip(message[-16:], K1))

    # CBC-MAC
    X = b'\x00' * 16
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    for i in range(n_blocks - 1):
        block = message[i*16:(i+1)*16]
        Y = bytes(a ^ b for a, b in zip(X, block))
        X = encryptor.update(Y)

    Y = bytes(a ^ b for a, b in zip(X, last_block))
    return encryptor.update(Y)


def f5(W, N1, N2, A1, A2):
    """
    BLE f5 function - generates MacKey and LTK from DHKey.

    W = DHKey (32 bytes)
    N1 = Initiator nonce (16 bytes)
    N2 = Responder nonce (16 bytes)
    A1 = Initiator address (7 bytes: type + address)
    A2 = Responder address (7 bytes: type + address)

    Returns (MacKey, LTK)
    """
    # Salt is fixed for BLE
    SALT = bytes.fromhex("6C888391AAF5A53860370BDB5A6083BE")

    # T = AES-CMAC_SALT(W)
    T = aes_cmac(SALT, W)

    # keyID = "btle"
    keyID = b"btle"

    # Length = 256 (in bits, little endian)
    Length = bytes([0x01, 0x00])  # 256 in little endian

    # MacKey = AES-CMAC_T(Counter=0 || keyID || N1 || N2 || A1 || A2 || Length)
    m0 = bytes([0x00]) + keyID + N1 + N2 + A1 + A2 + Length
    MacKey = aes_cmac(T, m0)

    # LTK = AES-CMAC_T(Counter=1 || keyID || N1 || N2 || A1 || A2 || Length)
    m1 = bytes([0x01]) + keyID + N1 + N2 + A1 + A2 + Length
    LTK = aes_cmac(T, m1)

    return MacKey, LTK


def f6(W, N1, N2, R, IOcap, A1, A2):
    """
    BLE f6 function - generates check values Ea and Eb.

    Used to verify the DHKey check values from the capture.
    """
    m = N1 + N2 + R + IOcap + A1 + A2
    return aes_cmac(W, m)


def reverse_address(addr_hex):
    """Reverse byte order of Bluetooth address."""
    addr_bytes = bytes.fromhex(addr_hex.replace(":", ""))
    return bytes(reversed(addr_bytes))


def compute_ltk_from_inputs():
    """Interactive mode to compute LTK from manually entered data."""

    print("="*60)
    print("BLE Secure Connections LTK Calculator")
    print("="*60)
    print("\nEnter the pairing data from your capture:\n")

    # Get DHKey - this is the ECDH shared secret
    print("DHKey (ECDH shared secret, 32 bytes hex):")
    print("  This is computed from the public keys - you need to calculate it")
    print("  or find it in the HCI logs if the controller logged it.")
    dhkey_hex = input("DHKey: ").strip()

    if not dhkey_hex:
        print("\nWithout the DHKey, we need the private key to compute it.")
        print("Checking if you have the public keys to compute ECDH...\n")

        print("Initiator (Mac) Public Key X (32 bytes hex):")
        init_pub_x = input("Init PubKey X: ").strip()
        print("Initiator (Mac) Public Key Y (32 bytes hex):")
        init_pub_y = input("Init PubKey Y: ").strip()

        print("Responder (Band) Public Key X (32 bytes hex):")
        resp_pub_x = input("Resp PubKey X: ").strip()
        print("Responder (Band) Public Key Y (32 bytes hex):")
        resp_pub_y = input("Resp PubKey Y: ").strip()

        print("\nTo compute DHKey, we need one private key.")
        print("If you have the Mac's private key from the HCI log:")
        init_priv = input("Init Private Key (32 bytes hex, or empty to skip): ").strip()

        if init_priv:
            # Compute ECDH
            from cryptography.hazmat.primitives.asymmetric import ec

            # Reconstruct private key
            priv_int = int(init_priv, 16)
            private_key = ec.derive_private_key(priv_int, ec.SECP256R1(), default_backend())

            # Reconstruct peer's public key
            peer_x = int(resp_pub_x, 16)
            peer_y = int(resp_pub_y, 16)
            peer_pub = ec.EllipticCurvePublicNumbers(peer_x, peer_y, ec.SECP256R1())
            peer_key = peer_pub.public_key(default_backend())

            # Compute shared secret
            dhkey = private_key.exchange(ec.ECDH(), peer_key)
            dhkey_hex = dhkey.hex()
            print(f"\nComputed DHKey: {dhkey_hex}")
        else:
            print("\nCannot compute LTK without DHKey.")
            return None

    W = bytes.fromhex(dhkey_hex)

    print("\nInitiator Random (Nrand, 16 bytes hex):")
    n1_hex = input("N1: ").strip()
    N1 = bytes.fromhex(n1_hex)

    print("Responder Random (Srand, 16 bytes hex):")
    n2_hex = input("N2: ").strip()
    N2 = bytes.fromhex(n2_hex)

    print("\nInitiator Address (e.g., 90:b7:90:8f:66:d9):")
    a1_addr = input("A1 addr: ").strip()
    print("Initiator Address Type (0=public, 1=random):")
    a1_type = int(input("A1 type: ").strip())
    A1 = bytes([a1_type]) + reverse_address(a1_addr)

    print("\nResponder Address (e.g., a4:0e:2b:8f:ac:cd):")
    a2_addr = input("A2 addr: ").strip()
    print("Responder Address Type (0=public, 1=random):")
    a2_type = int(input("A2 type: ").strip())
    A2 = bytes([a2_type]) + reverse_address(a2_addr)

    # Compute LTK
    MacKey, LTK = f5(W, N1, N2, A1, A2)

    print("\n" + "="*60)
    print("RESULTS")
    print("="*60)
    print(f"MacKey: {MacKey.hex()}")
    print(f"LTK:    {LTK.hex()}")
    print("="*60)

    # Optionally verify with DHKey checks
    print("\nTo verify, enter the DHKey check values from capture:")
    ea_hex = input("Initiator DHKey Check (Ea, or empty to skip): ").strip()

    if ea_hex:
        print("IOcap (3 bytes, e.g., 040000 for KeyboardDisplay):")
        iocap_hex = input("IOcap: ").strip()
        IOcap = bytes.fromhex(iocap_hex)

        # r = 0 for Just Works
        R = b'\x00' * 16

        Ea_computed = f6(MacKey, N1, N2, R, IOcap, A1, A2)
        Ea_captured = bytes.fromhex(ea_hex)

        if Ea_computed == Ea_captured:
            print(f"\n✓ DHKey check VERIFIED! LTK is correct.")
        else:
            print(f"\n✗ DHKey check mismatch!")
            print(f"  Computed: {Ea_computed.hex()}")
            print(f"  Captured: {Ea_captured.hex()}")

    return LTK


def main():
    if len(sys.argv) > 1:
        # TODO: Parse pcapng file
        print(f"Parsing {sys.argv[1]}...")
        print("PCAP parsing not yet implemented. Use interactive mode.\n")

    ltk = compute_ltk_from_inputs()

    if ltk:
        print(f"\n\nYour LTK is: {ltk.hex()}")
        print("\nAdd this to meta_band_ecdh.py to try session decryption!")


if __name__ == "__main__":
    main()
