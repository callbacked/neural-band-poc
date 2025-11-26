# Meta Neural Band Protocol Analysis (lol i hope this generated readup checks out, it seems to)

Reverse engineering notes for the Meta Neural Band (EMG wristband).

## Device Information

- **Device Name**: Meta Band 00BC
- **Advertised Address**: `4b:bd:d9:ed:39:58` (Resolvable Private Address)
- **Public Address**: `a4:0e:2b:8f:ac:cd` (Facebook OUI)
- **IRK**: `e05d0d10a6cbee7f48449ff16c3c6c9b`

## BLE Services

| Service UUID | Name | Handles |
|--------------|------|---------|
| 0x1800 | Generic Access | - |
| 0x1801 | GATT | 0x0001-0x0005 |
| 0x180F | Battery Service | - |
| 0x180A | Device Information | - |
| 0xFEB8 | Meta Platforms, Inc. | 0x0023-0x0029 |
| 0xFD5F | Meta Platforms Technologies | 0x002a-0x002c |
| 0xEFF0 | Unknown (custom) | - |

## Key Characteristics

### Meta Platforms Inc. Service (0xFEB8)

| Handle | UUID | Properties | Purpose |
|--------|------|------------|---------|
| 0x0028 | `2d41da7c-82b6-42aa-b34e-e2e01df8cc1a` | Notify | Status heartbeat (sends 0x00) |
| 0x0029 | CCCD | Write | Enable notifications |

### Meta Platforms Technologies (0xFD5F)

| Handle | UUID | Properties | Purpose |
|--------|------|------------|---------|
| 0x002a | `05acbe9f-6f61-4ca9-80bf-c8bbb52991c0` | Read | Unknown |

## Connection Sequence

1. **Scan** for device advertising "Meta Band"
2. **Connect** to the device
3. **MTU Exchange** - Request 517 bytes
4. **Service Discovery** - Find all services/characteristics
5. **Pairing** - LE Secure Connections (Just Works)
6. **Enable Notifications** - Write 0x0001 to handle 0x0029
7. **Open L2CAP CoC** on PSM 0x00FF
8. **Protocol Handshake** over L2CAP channel

## BLE Pairing

Uses **LE Secure Connections** with:
- IO Capability: No Input, No Output (band) / Keyboard Display (phone)
- Pairing Method: Just Works (numeric comparison)
- Key Size: 16 bytes
- Bonding: Yes
- Key Distribution: IRK only

### Captured Pairing Data

```
iOS Public Key X:  511462e79815baeec959f2efc6d8f4ef048d7971e57bb0b8e8747f5a1056d275
iOS Public Key Y:  a2053d8e4ccfabc742bbe001c7938f3cc144168925eebfbc70ddf0c20907f5a8
Band Public Key X: b19964cd7eb298c6d06392e40c23699f819c26adf6b7d71b096c26d9b5dd626d
Band Public Key Y: 17eee0175625339fae33ae1dcf7ca2b9af4018cb1dd71526cf659603a995bc83

iOS Random:        7bcba138ab55140e1736b6f32d426a55
Band Random:       bf0bcedc2b939e6728ea8e508c709e74

iOS DHKey Check:   e37cc906e7d2e97a6c44034b270e917b
Band DHKey Check:  a6d84d2bd34e7d974531d0de6cce016d

Band IRK:          e05d0d10a6cbee7f48449ff16c3c6c9b
iOS IRK:           1a3148b262585b8cbe9ea9bb1b7ac7ed
```

## L2CAP Connection-Oriented Channel

- **PSM**: 0x00FF (dynamically allocated)
- **MTU**: 998 bytes (band limit)
- **MPS**: 247 bytes
- **Credits**: 5 (from band)

## Protocol Messages

### Message Header (8-12 bytes)

```
Byte 0:    0x80 (message marker)
Byte 1:    Message type
           0x60 = Init/Handshake
           0x81 = Data (initiator)
           0x82 = Data (responder)
Bytes 2-7: Flags/sequence numbers
```

### Init Message (0x60) - 100 bytes

Sent by band when L2CAP channel opens.

```
80 60 80 01 81 00 00 05 02 00 00 01  <- Header (12 bytes)
0a 40 <64 bytes>                     <- Field 1: Ephemeral ECDH public key (P-256)
12 10 <16 bytes>                     <- Field 2: Nonce/identifier
18 00                                <- Field 3: Varint (0)
20 03                                <- Field 4: Varint (3)
```

**Key Discovery**: The 64-byte blob in field 1 is a **valid P-256 elliptic curve point** (32-byte X + 32-byte Y). This is the band's ephemeral public key for session key derivation.

### Data Message (0x81/0x82) - 134 bytes

Response after handshake.

```
80 82 00 01 02 00 00 02              <- Header (8 bytes)
0a 40 <64 bytes>                     <- Field 1: Public key
12 20 <32 bytes>                     <- Field 2: Encrypted data or signature
1a 10 <16 bytes>                     <- Field 3: Auth tag
20 xx xx xx xx xx                    <- Field 4: Varints
28 03                                <- Field 5: Varint
```

## Cryptographic Analysis

### Session Key Derivation (Hypothesized)

The protocol uses ephemeral ECDH for forward secrecy:

1. Band generates ephemeral P-256 keypair
2. Client generates ephemeral P-256 keypair
3. Both compute shared secret via ECDH
4. Session key derived using HKDF or similar

**Problem**: The key derivation likely also incorporates the **BLE LTK** (Long Term Key) from pairing. Without the LTK, we cannot derive the correct session key.

### Encryption

Based on field sizes (32-byte ciphertext + 16-byte tag), likely:
- **AES-256-GCM** with 16-byte auth tag
- Or **ChaCha20-Poly1305**

### What's Missing

To complete the handshake, we need the **LTK** which is:
- Derived during BLE pairing using the `f5` function
- Computed from the DHKey (ECDH shared secret from pairing public keys)
- Not transmitted over the air
- Stored in the device's secure storage

## Current Capabilities

### What Works

- [x] Scanning and connecting to band
- [x] BLE pairing (Just Works)
- [x] Service discovery
- [x] Enabling notifications
- [x] Opening L2CAP CoC channel
- [x] Receiving band's init message
- [x] Computing ephemeral ECDH shared secret
- [x] Sending our public key to band
- [x] Receiving band's encrypted response

### What's Blocked

- [ ] Deriving correct session key (need LTK)
- [ ] Decrypting band's messages
- [ ] Sending valid encrypted responses
- [ ] Receiving gesture/EMG data

## Files

- `meta_band_connect.py` - Basic BLE connection using bleak
- `meta_band_l2cap.py` - Full L2CAP CoC using CoreBluetooth
- `meta_band_ecdh.py` - ECDH handshake implementation
- `meta_band_crypto.py` - Crypto analysis/experiments
- `meta_band_ltk.py` - LTK derivation analysis
- `unpair_band.py` - Utility to unpair device

## Next Steps

### Option 1: Extract LTK

- Jailbroken iOS: Use keychain-dumper
- macOS Keychain: Check if synced via iCloud
- Bluetooth HCI: Sniff with Ubertooth during pairing

### Option 2: Reverse Engineer App

- Decompile Meta AI iOS app (Hopper/Ghidra)
- Decompile Meta AI Android APK (jadx)
- Find key derivation function
- Look for protobuf definitions

### Option 3: Alternative Approaches

- MITM the app traffic with Frida (jailbreak required)
- Check for debug/developer modes
- Look for firmware update protocols

## References

- Bluetooth Core Specification v5.x (SMP, GATT)
- BLE Security (LE Secure Connections)
- P-256 Elliptic Curve (secp256r1)
- AES-GCM / ChaCha20-Poly1305

---

*Last updated: November 2025*
