# Reverse Engineering Meta AI App for Band Protocol (lol i hope this generated readup checks out, it seems to)

## Current Status

We have successfully:
- Connected to the Meta Band
- Completed BLE pairing and extracted LTK: `87a04e3bf1fe379251ed6cd050109707`
- Opened L2CAP channel on PSM 0x00FF
- Exchanged ECDH public keys with the band
- Computed shared secrets

But we **cannot decrypt** the band's response (32-byte field2 + 16-byte field3).

## What We Need to Find

1. **Key derivation function** - How is the session key derived from:
   - ECDH shared secret
   - LTK
   - Nonces
   - Public keys

2. **Encryption algorithm** - Likely AES-GCM but could be:
   - ChaCha20-Poly1305
   - Custom scheme
   - Noise Protocol variant

3. **Nonce derivation** - What's used as the IV/nonce

4. **Protocol state machine** - What messages to send after handshake

## Android APK Analysis

### Step 1: Get the APK

```bash
# Option A: From device with ADB
adb shell pm path com.facebook.orca  # or whatever the Meta AI app package is
adb pull /path/to/app.apk

# Option B: From APK mirror sites
# Search for "Meta AI" or "Meta View" APK
```

### Step 2: Decompile with jadx

```bash
# Install jadx
brew install jadx

# Decompile
jadx -d meta_ai_decompiled meta_ai.apk

# Or use GUI
jadx-gui meta_ai.apk
```

### Step 3: Search for Crypto Code

Look for these patterns in the decompiled code:

```bash
# Search for key derivation
grep -r "HKDF\|hkdf" meta_ai_decompiled/
grep -r "ECDH\|ecdh\|SharedSecret" meta_ai_decompiled/
grep -r "LTK\|ltk\|LongTermKey" meta_ai_decompiled/

# Search for encryption
grep -r "AES\|GCM\|ChaCha\|Poly1305" meta_ai_decompiled/
grep -r "AESGCM\|AesGcm" meta_ai_decompiled/

# Search for band-related code
grep -r "Band\|Wristband\|EMG\|Neural" meta_ai_decompiled/
grep -r "L2CAP\|PSM\|0x00FF\|255" meta_ai_decompiled/

# Search for protobuf definitions
grep -r "\.proto\|protobuf" meta_ai_decompiled/
find meta_ai_decompiled -name "*.proto"
```

### Step 4: Key Classes to Find

Look for classes related to:
- `BandManager`, `BandConnection`, `BandService`
- `L2CAPChannel`, `L2CAPConnection`
- `SessionKey`, `KeyDerivation`, `CryptoManager`
- `Handshake`, `Protocol`, `MessageHandler`

### Step 5: Native Libraries

The crypto might be in native code:

```bash
# Extract native libs
unzip meta_ai.apk -d extracted_apk
ls extracted_apk/lib/*/

# Look for relevant .so files
find extracted_apk -name "*.so" | xargs nm -D 2>/dev/null | grep -i "crypto\|aes\|ecdh"
```

If crypto is in native libs, use:
- **Ghidra** or **IDA Pro** for disassembly
- **Frida** for runtime hooking

## iOS App Analysis

### Using Hopper/Ghidra

1. Get decrypted IPA (requires jailbreak or use tools like `frida-ios-dump`)
2. Extract the Mach-O binary
3. Load in Hopper Disassembler or Ghidra
4. Search for crypto functions

### Frida Hooking (requires jailbreak)

```javascript
// Hook crypto functions to see key derivation
Interceptor.attach(Module.findExportByName("libcommonCrypto.dylib", "CCCryptorCreate"), {
    onEnter: function(args) {
        console.log("CCCryptorCreate called");
        console.log("  Algorithm: " + args[1]);
        console.log("  Key: " + hexdump(args[3], {length: args[4].toInt32()}));
    }
});

// Hook HKDF
Interceptor.attach(Module.findExportByName(null, "HKDF"), {
    onEnter: function(args) {
        console.log("HKDF called");
        // Log parameters
    }
});
```

## Alternative: Network Traffic Analysis

If the app communicates with Meta servers during setup:

```bash
# Use mitmproxy or Charles Proxy
mitmproxy --mode transparent --ssl-insecure

# On device, set proxy and install CA cert
```

Look for:
- Protocol documentation endpoints
- Key exchange with servers
- Protobuf definitions being downloaded

## Likely Protocol Structure

Based on our observations, the protocol likely:

1. Uses **protobuf** for message serialization (the 0x0a, 0x12, 0x1a tags)
2. Implements a **Noise-like** key exchange
3. May require **mutual authentication** (band verifies we have valid LTK)
4. Possibly includes **device attestation** (band checks we're genuine Meta app)

## Next Steps

1. **Get Meta AI APK** - From Play Store or APK mirror
2. **Decompile and search** - Use jadx to find crypto code
3. **Find key derivation** - Identify the exact HKDF/SHA256 pattern used
4. **Implement correctly** - Update meta_band_ecdh.py with correct derivation
5. **Test decryption** - Verify we can decrypt band responses

## Notes

- The band requires glasses to be active for gesture feedback
- This suggests band ↔ glasses ↔ phone three-way communication
- The crypto might involve keys shared with glasses too
- Consider also reverse engineering the glasses' protocol
