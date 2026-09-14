# Instrumented hardware sessions

September 13–14, 2026, New York time (capture timestamps below are September 14 UTC).

## Verified milestone

**Direct Mac-to-band raw EMG streaming works with fresh Mac-generated session keys.** Link completion enables the input service, and its raw-EMG flag activates a sustained stream. A user-started localhost recording captured 99,072 eight-channel sample frames with a clean stop. The ADC display remains experimental. Later captures were made with user-confirmed glasses-off and phone-Bluetooth-off conditions; see the [raw-stream checkpoint](#raw-emg-stream-activated-september-14-2026).

**Ten recognized index pinches were recovered on the Mac from a coordinated phone capture.** Each has `INDEX_PRESS`, `INDEX_RELEASE`, and `INDEX_SINGLE_TAP` events in checksummed glasses telemetry files. Delivery is batched and delayed. This is gesture history through the official glasses/phone path, not a live or glasses-independent controller.

Companion-app transport decryption works for both the band and glasses. The decoder independently derives each direction's keys, checks them against a targeted app observation, verifies every packet MAC before releasing plaintext, and maintains CBC IV/counter state across stream chunks.

The completed 90-second recording `gesture-session-20260913.log` decodes with **850 authenticated channel-zero packets, 65 separate unauthenticated relay/control records, no MAC failures, and no remaining bytes**:

| Connection | Phone TX packets | Phone RX packets | Negotiated parameters |
| --- | ---: | ---: | ---: |
| Meta Band | 51 | 39 | 3 |
| Meta RB Display | 466 | 294 | 31 |

All four derived encryption/MAC key pairs match the app's observed keys. An earlier independent startup (`startup-airshield-keys-20260913.log`) authenticates 632 packets; its glasses-TX capture ends partway through a frame, which the decoder reports rather than treating as success. These recordings have different session material.

Direct named-gesture delivery and glasses-off operation were subsequently demonstrated. ADC calibration, channel mapping and delivery reliability remain open. The phone recordings use keys from this user's instrumented companion app; the direct Mac raw-stream client generates its own session keys. Band↔glasses relay encryption uses a separate handshake and remains opaque; its packets are never labeled authenticated or decrypted by the phone-link decoder. Full owner identity authentication was not established by the successful input-service requests.

## Setup actually observed

- iPhone 8 (`iPhone10,4`), iOS `16.7.16`, existing palera1n setup reactivated by the user.
- Frida USB access works after switching from the USB-A-to-Lightning jailbreak cable to the user's USB-C-to-Lightning data cable.
- Meta AI bundle `com.facebook.stellaapp`, version `269.1.0`, build `948093709`. The installed manifest declares `MinimumOSVersion = 15.2`; the current App Store listing does not describe this installed build's requirements.
- Band: `Meta Band 00BC`, firmware characteristic `297b870dc9be+`.
- Glasses: `Meta RB Display 002M`, firmware characteristic `68597370069500080`.
- The app was restarted for instrumented startup captures. An early runtime heap inspection stalled, so the reusable inspector avoids heap scans. A later startup exposed delegate methods not yet being available; the recorder now waits up to five seconds for those methods and reports failure explicitly.

## Full connection bytes are now recorded

The observer hooks the real app class `L2CapTransport.L2CapTransport`, registers each channel in `peripheral:didOpenL2CAPChannel:error:`, and records the bytes accepted by the concrete input/output stream methods. Device names, channel identity, PSM, direction, timestamps, and event sequence numbers are retained. The observer does not send Bluetooth commands.

At `01:52:36.211Z`, the glasses opened PSM `0x0080`. At `01:52:36.774Z`, the band opened PSM `0x00FF`. Both initial exchanges were captured, followed by `0x40`-prefixed traffic. Later sessions added targeted key capture and verified decryption of that traffic.

Local evidence is in the ignored `captures/` directory:

- `bluetooth-20260913-startup.log`: full observed stream chunks and Bluetooth events.
- `inspection-20260913-native.log`: installed app metadata and selected Objective-C class/method names.
- `native-inspection-20260913.json`: selected native imports, symbols, and static protocol-related strings with module offsets.
- `crypto-calls-20260913.log`: early generic-import trace, superseded by the targeted AirShield observer.
- `startup-airshield-keys-20260913.log` and `gesture-session-20260913.log`: traffic plus session-key observations.
- `decrypted-20260913.json` and `gesture-session-decrypted-20260913.json`: verified plaintext and separately labeled relay/control records.
- `kdf-disassembly-20260913.json`: targeted native KDF disassembly with module offsets.

Key-bearing captures and plaintext stay in ignored `captures/`. No session secrets are included in these notes or committed test fixtures.

The completed first recording contains **6,364 stream chunks totaling 1,294,238 bytes**. The offline analyzer reports no sequence gaps, capture/hook errors, or payload/count discrepancies, and reconstructs all eight initial setup messages. A second complete recording independently yields the same eight message types and parameter negotiation. This checks the recorded events, not completeness of all radio traffic. The phone only exposes its own connections, and application messages may span multiple stream chunks.

## Strong correction to the historical framing model

The old code names the second byte `msg_type`, treating `0x60` as init and `0x82` as a response. All eight fresh startup frames instead satisfy:

```text
(big_endian_u16(first_two_bytes) & 0x7fff) + 4 == captured_frame_length
```

| Peer | Direction relative to phone | Bytes | First two bytes |
| --- | --- | ---: | --- |
| Glasses | Receive | 116 | `80 70` |
| Glasses | Send | 102 | `80 62` |
| Glasses | Send | 134 | `80 82` |
| Glasses | Receive | 138 | `80 86` |
| Band | Send | 102 | `80 62` |
| Band | Receive | 114 | `80 6e` |
| Band | Send | 134 | `80 82` |
| Band | Receive | 134 | `80 82` |

The historical 100-byte `80 60` example fits the same relationship. This is strong evidence for a length-bearing header, not a constant message-type byte. Bit meanings, large-frame behavior, and the complete framing grammar still require verification. Do not generalize this equation to `0x40` traffic or assume every stream chunk is a frame.

The four fresh band startup frames all contain valid P-256 points at the expected candidate field offsets (after 12-byte init headers or 8-byte response headers). This validates field structure, not the KDF or cipher. The phone sent its first init before the recorded band init in this session.

The band's characteristic `2D41DA7C-82B6-42AA-B34E-E2E01DF8CC1A` returned `ff00`, matching the subsequently opened PSM 255 if interpreted little-endian. Together with the app's `L2CapPSMData.swift` string, this is a lead for PSM discovery. Its prior description as a simple zero heartbeat is incomplete.

## Matching public schema and crypto vectors

The [public AirShield/DataX research](protocol.md) supplies concrete `RequestEncryption` and `EnableEncryption` protobuf definitions. Their wire types and byte-field lengths match the fresh messages. Field 2 of enable is a 32-byte **seed**, and field 3 is a 16-byte **IV** in that schema, contradicting the old ciphertext/tag interpretation.

The phone offers supported parameters 31. The **band offers and negotiates 3**; the **glasses negotiate 31**. Unknown request field 7 is retained by the analyzer. Enable lengths can vary when protobuf counter varints use different byte counts; a later phone-to-band enable was 133 bytes. This further contradicts hardcoded type-by-length assumptions.

The public implementation uses P-256 ECDH and AES-CBC with truncated HMAC-SHA256, and has reproducible parameter-31 key derivation vectors. The research pass reproduced two expected derived keys and the packet MAC (3/3 checks). Those public checks validate that example. The subsequent native observations and packet checks above independently establish this band's parameter-3 branch. The public sample still has substantial receive/authentication defects; do not transplant it as a driver.

`instrumentation/analyze_capture.py` now buffers initial setup by device/channel/direction, parses protobuf varints and byte fields with bounds checks, validates P-256 points, preserves unknown fields, and reports capture inconsistencies. Four CLI tests cover split/coalesced setup, a sequence gap, truncation, and enable without request. Encrypted traffic is left uninterpreted.

## Concrete native-code leads

Observed runtime classes include `L2CapTransport.L2CapSecureLink`, `L2CapTransport.L2CapGATTReader`, and `L2CapTransport.L2CapTransport`. The app's static strings include:

- `L2CapTransport/L2CapSecureLink.swift` at main-module offset `0x88fdb10`.
- `L2CapTransport/L2CapPSMData.swift` at `0x88fe9d0`.
- Connectivity paths under `fbobjc/Libraries/ARConnectivity/ConnectivityCommon/`.
- `configureLSV3LinkManager(secureLink:lease:)` at `0x963bbb0`.
- `extractKeyDerivationKey(pendingOwnershipReceipt:)` at `0x93bd8d0`.

These are leads from this app build, not proof they implement the band handshake. Offsets belong to build `948093709` and must be interpreted relative to that run's main-module base.

The imported-crypto observer was subsequently run during startup. P-256/SharedSecret hits were metadata initialization functions, not observed key-agreement execution; AES-GCM calls had other app/network call paths. CommonCrypto cipher calls were plentiful and exhausted the initial sample limit before the connections opened. The observer now refreshes its budget at channel openings, but those generic callers still do not establish the band's cipher.

A broader static inventory, `native-inspection-airshield-20260913.json`, contains `hmac_derive` at `0x896e075` and native AirShield log strings. Objective-C metadata identifies `MWALinkSetupService` with `_txBuilder` and `_rxBuilder` at offsets 48 and 168. Their `CipherBuilder` types contain challenge/seed/IV and OpenSSL/BoringSSL-shaped `ec_key_st`, `ec_group_st`, and `ec_point_st` objects. **That class's request/receive methods were not called during the observed startup**, so its presence alone does not identify the active path.

A read-only scan of the loaded ARM64 text found the `hmac_derive` reference at main-module `0x2ac75bc`. A targeted observer recorded two calls to that anchor, with parent return offset `0x45e47a8` and hash-update target `0x11e444`. Their times (`02:22:28.131Z`, `02:22:28.219Z`) align with the **glasses** exchange, after the band's setup. This makes the parameter-3 branch especially important: no call to this anchor was recorded during the preceding band setup. That anchor alone was not a KDF proof; following its caller led to the verified derivations below. Local evidence: `kdf-xrefs-20260913.json` and `startup-kdf-20260913.log`.

## Verified directional derivation and framing

Let `S` be the 32-byte shared-secret cache value produced by the native P-256 exchange, `C` the **receiver's** RequestEncryption challenge, and `R` the **sender's** EnableEncryption seed. SHA256 returns 32 bytes; HKDF uses SHA256, info `AirShield`, and output length 32.

For **parameters 3** (band):

```text
H    = SHA256(S)
Kenc = HKDF(IKM=H, salt=SHA256(H || C || R), info="AirShield", length=32)
Kmac = Kenc
```

For **parameters 31** (glasses):

```text
Kenc = HKDF(IKM=S, salt=SHA256(C || R), info="AirShield", length=32)
Kmac = HKDF(IKM=S, salt=SHA256(R || C || "hmac_derive"), info="AirShield", length=32)
```

Initial IV and counter come from the sender's EnableEncryption fields 3 and 4. After a verified packet, use its last ciphertext block as the next IV and increment the uint32 counter modulo 2^32. The decoder only implements the two observed parameter values.

Observed post-setup stream records:

| Record | Layout | Handling |
| --- | --- | --- |
| Encrypted channel 0 | `40 || MAC8 || block_count_minus_1:u8 || CBC ciphertext` | Ciphertext length is `16 × (byte9 + 1)`; verify before decrypting. |
| Clear relay channel 1/2 | `channel:u8 || payload_length_minus_1:u8 || payload` | Preserve separately, without authentication claims. |
| Encrypted relay channel 1/2 | `41/42 || MAC8 || block_count_minus_1:u8 || ciphertext` | Preserve opaque; do not advance channel-0 crypto state. |
| Control | `81/82 || 00/01` | Preserve both bytes; exact control semantics remain unresolved. |

The channel-zero MAC is the first eight bytes of HMAC-SHA256 over:

```text
prefix || uint32_le(counter) || block_count_minus_1 || ciphertext
prefix = empty for parameters 3; 02 02 00 00 for parameters 31
```

All 850 packets in the second recording verify with these rules, including after interleaved relay/control records and fragmented reads/writes. This supports the observed subset of the framing, not arbitrary channel IDs or a complete published protocol specification. Decrypted plaintext retains DataX padding.

The native KDF begins at main-module offset `0x45e45ec`; the capture point after derivation is `0x45e4810`. The observer correlates challenge/seed/IV to captured setup frames, samples the valid shared-secret cache, and captures derived keys for independent comparison. It checks build-specific instruction/string anchors before reading native offsets. `MWALinkSetupService` itself was not the active path.

Reusable tools:

- `instrumentation/capture_airshield_keys.js`: targeted native observer for this installed build.
- `instrumentation/airshield.py`: verified KDF, framing, MAC verification, and CBC state.
- `instrumentation/decrypt_capture.py`: capture integrity checks, key-observation correlation, and timed plaintext output.
- `instrumentation/extract_telemetry.py`: checked file reconstruction and named EMG SDK event extraction.
- Sixteen tests cover public vectors, fragmentation/coalescing, counter wrap, relay interleaving, bad MAC/ciphertext, incorrect counter, setup validation, raw file continuations, transfer checksums, truncation, and telemetry stage filtering. The build-specific probe and CLIs also run against real recordings.

## Recognized gestures recovered from telemetry

The first band's phone channel closed about 17 seconds after opening; glasses traffic continued. Later decoded captures show the phone forwarding a second handshake between band and glasses, followed by opaque encrypted relay records. Matching bytes establish forwarding, not the content or route of subsequent gestures.

The first timed gesture request had a coordination mismatch. The subsequent interactive recording, `coordinated-gestures-20260913.log`, ran without an automatic stop. Its GO marker is `02:50:42.990Z`; the user's completion report was marked at `02:54:28.632Z`. A quiet interval followed, and the recorder is now stopped. The user confirmed waking the sleeping glasses **before** the pinches by double pressing middle finger with thumb, and uses the band's haptic feedback as confirmation that pinches are recognized.

This capture authenticates **1,325 channel-zero packets**: band TX/RX 45/27 and glasses TX/RX 593/660. The final glasses receive record is incomplete (2,498 captured bytes); all preceding authenticated packets are retained, with no MAC failure. The phone's band channel closed at `02:50:09.576Z`, before GO. The gesture records were recovered from the continuing **glasses-to-phone** connection.

Four telemetry files passed announced/completed lengths, Adler-32 over compressed bytes, and complete zlib decompression. A fifth file was cut off when recording stopped and is excluded. The two files carrying the index events contain 16,386 and 31,920 compressed bytes. The latter expands to 406,135 bytes with 245 telemetry records; its transfer Adler-32 is 282596329. JSON inside the protobuf batch includes explicit `interaction_emg_sdk` events with source `EMG`. Downstream system/recognition/application stages are excluded from the counts below.

All ten press/release/tap sequences fall after GO and before the completion report. Times below are **September 13, 2026, EDT**; add four hours for September 14 UTC. These are recorded glasses event times, not manually labeled times for each physical movement.

| Sequence | Index press | Index release | Single tap | File received by phone |
| --- | --- | --- | --- | --- |
| 1 | 22:50:51.280 | 22:50:51.430 | 22:50:51.430 | 22:51:24.221 |
| 2 | 22:51:11.933 | 22:51:12.069 | 22:51:12.070 | 22:51:24.221 |
| 3 | 22:51:15.444 | 22:51:15.595 | 22:51:15.595 | 22:51:24.221 |
| 4 | 22:51:18.608 | 22:51:18.715 | 22:51:18.715 | 22:51:24.221 |
| 5 | 22:51:21.609 | 22:51:21.715 | 22:51:21.715 | 22:51:24.221 |
| 6 | 22:51:25.357 | 22:51:25.465 | 22:51:25.465 | 22:53:53.756 |
| 7 | 22:51:27.685 | 22:51:27.822 | 22:51:27.822 | 22:53:53.756 |
| 8 | 22:51:31.120 | 22:51:31.255 | 22:51:31.255 | 22:53:53.756 |
| 9 | 22:51:34.074 | 22:51:34.195 | 22:51:34.195 | 22:53:53.756 |
| 10 | 22:51:36.458 | 22:51:36.580 | 22:51:36.581 | 22:53:53.756 |

The initial manual extraction found only the later five. Reassembling all completed telemetry files recovered the earlier five as well, with distinct interaction IDs and timestamps. The apparent press-to-file-receipt delay ranges from about 3 to 148 seconds. Glasses and phone clocks have not been calibrated, so these differences are not a latency benchmark. Batch delivery itself is directly observed.

Other SDK names include `MIDDLE_ACTION_IA` and thumb-left/right actions. Their exact physical meanings and relationship to waking the display are unverified; the user's wake gesture must not be mapped to `MIDDLE_ACTION_IA` from its name alone. No raw electrode samples were identified in that telemetry capture; the later direct raw stream is documented below.

The observed DataX frame length is `(u16be(first_two_bytes) & 0x7fff) + 4`. The high bit of the **length word** flags a chain of four-byte typed headers, ending when a header's high bit is clear. The high bit of the channel word must not discard bytes from raw file continuations. File announcements use the observed words `81000014 02000001`, data starts `02000004`, intermediate checkpoints `02000005`, and finishes `02000006`. Checkpoint/finish protobuf fields 1 and 2 match cumulative compressed byte count and Adler-32. Padding removal follows the observed repeated `0xc0 + count` suffix, with file checks gating output; its full grammar remains unverified.

Reproduce from the local decrypted capture:

```sh
python3 instrumentation/extract_telemetry.py captures/coordinated-gestures-decrypted-20260913.json \
  --output captures/coordinated-telemetry-20260913.json
```

Expected: four completed telemetry files, ten each of index press/release/single-tap, and explicit errors for the transport tail and unfinished fifth file. The nonzero exit is intentional; it does not invalidate completed files. Detailed events and original captures remain ignored/local.

The subsequent direct-connection test is described below. The subsequent raw subscription is documented below; a live named-gesture path and a fully powered-off glasses test remain open. Raw EMG availability remains separate from recognized gesture access.

## Direct Mac-to-band connection

After the user put the band in pairing mode, a Mac BLE scan discovered `Meta Band 00BC` advertising service FD5F at RSSI −48. A direct GATT connection succeeded. It read firmware `297b870dc9be+` and PSM characteristic `ff00`, matching the earlier phone observation. The inventory includes battery/device-information services, FEB8, FD5F, and a private EFF0/DADA service. No characteristic was identified as a raw sEMG stream; private characteristics still require protocol interpretation.

The first two `instrumentation/mac_band_probe.py` exchanges established encrypted transport (UTC September 14; filenames retain the session-start date):

| Run | UTC interval | Query | Verified receive packets | Result |
| --- | --- | --- | ---: | --- |
| 1 | 03:27:04–03:27:31 | Service `0x24`, message `0x3000` | 2 (1,888 padded plaintext bytes) | Message `0x3001`, 1,878-byte certificate/identity payload. |
| 2 | 03:32:45–03:33:08 | Same query plus service `0xce56`, message `0x314` | 2 (2,000 padded plaintext bytes) | Identity response, an additional identity-service `0x1001` message, and error `0xc001` on the device-info query's channel. |

Both runs generated their own ephemeral P-256 private keys, challenge, seed, IV and initial counter on the Mac. ECDH used the band's fresh public point; the verified parameter-3 derivation produced valid packet MACs. No iPhone session keys, legacy BLE LTK constants, or replayed handshake material were used. Successful replies establish direct encrypted protocol communication, not identity authorization or access to privileged services. Whether the glasses were physically powered off during these probes was not separately confirmed; the recorded connection and keys are directly Mac-to-band.

The identity payload's fields 1 and 5 parse as DER X.509 EC certificates of 967 and 889 bytes; field 2 is 14 bytes. Certificate parsing is not certificate-chain trust validation or proof of ownership. The empty identity request comes from the [pinned Starcruiser implementation](https://github.com/zhuowei/Starcruiser-mac/blob/1bc6f9418ad85a10991817c74e15a84f85078f53/Sources/starcruiser/Datax.swift). Our crypto, receive buffering, and partial-write handling use the corrected local implementation.

The device-info request is supported by the captured official session: typed header `8100ce56 02000314`, protobuf request ID in field 1 and an empty field 3. The official session responds with `0x315`, including firmware and model metadata. In run 2, before link completion was implemented, the same request shape received the terminal word `0300c001` with no payload. **The exact meaning of `0xc001` is not established.** Authentication/setup gating is a candidate explanation, not a decoded error definition.

Before stream activation, the user reported tapping without band haptic feedback. No gesture/sensor subscription had been activated, no corresponding samples were observed, and the bounded probes disconnected after their stated durations. The absent haptics must not be treated as proof that encryption failed, that recognition was active, or that raw EMG is unavailable.

Useful phone-code leads were confirmed by a read-only class inventory:

- `WearableInputServiceProtosSwift` has storage classes for `StreamControlReq`, `StreamControlResp`, `DeviceInfoResp`, `ConfigReq`, `ConfigResp`, and `SensorTelemetryUpdate`.
- Static field names include `enableRawEmg`, `enableRawEmgImuBatch`, `enabledRawEmg`, and `enabledRawEmgImuBatch`.
- `RawEmgDecoderBridge` exposes `onRawEmgEvent:size:` at module offset `0x5245c2c`, `onRawEmgEventWrist16:size:` at `0x5245d84`, and `getDecodedBufferSize` at `0x29e3bc4` in the installed build.
- `IdentityServiceClient.IdentityServiceClient` and `FWADeviceIdentitySecureStore.FWADeviceIdentitySecureStore` exist, but expose no own Objective-C methods in this inventory. Presence does not identify the active authentication path.

Initial evidence remains in ignored local files: `mac-band-discovery.json`, `mac-band-gatt.json`, `mac-band-probe-20260913-1.jsonl`, `mac-band-probe-20260913-2.jsonl`, `mac-band-identity-response.bin`, and `emg-identity-inspection-20260913.log`.

## Raw EMG stream activated September 14, 2026

**The Mac can enable the band's raw-EMG subscription and receive a sustained stream using fresh Mac-generated keys.** The input service is not blocked by the earlier `0xc001` once link setup is completed. No signed owner-authentication replay, persistent sensor configuration change, or phone session key is required by these successful runs. This is the observed behavior of firmware `297b870dc9be+`; it is not a claim about every firmware or privileged service.

| Run | UTC interval | Experiment | Result |
| --- | --- | --- | --- |
| 3 | ~03:49–03:50 | First EndLinkSetup attempt | Invalid trial: dashboard and CLI overlapped. A shared cross-process connection lock now prevents this. |
| 4 | 03:52:32–03:52:56 | EndLinkSetup, then device-info RPC | Two verified records; successful `0x315` device-info response instead of `0xc001`. |
| 5 | 04:02:54–04:03:13 | Query current stream flags | Raw EMG reported disabled. |
| 6 | 04:03:51–04:04:19 | Enable raw EMG | Flag changed 0→1; 1,819 complete raw messages, 428 authenticated records. Incomplete final DataX frame. Disable was mistakenly sent on a separate channel and did not stop the original stream before disconnect. |
| 7 | 04:06:36–04:06:49 | Read sensor configuration | EMG configuration reports 2,048 Hz, eight channels, 16-bit ADC, 16 samples/batch, encoding 0. |
| 8 | 04:10:56–04:11:54 | Raw EMG, disable on the original channel | 5,170 batches, 82,720 sample frames (661,760 channel readings), 1,206 authenticated records. 1,517 missing batches: 22.7% of observed sequence span. Clean DataX completion; no sample after the disable acknowledgement. |
| Dashboard | 04:15–04:16:01 | User started recording through localhost | 6,192 batches, 99,072 sample frames (792,576 channel readings), 1,543 authenticated records. 630 missing batches: 9.2% of observed sequence span. Disable acknowledged, no incomplete tail. |

The user reported haptic feedback during raw activation and later clarified that the glasses were off their head on the desk. This supports operation without wearing/viewing the glasses. **At that point this did not prove the glasses were powered off.** A later user-confirmed isolation capture is documented below. The Mac's connection ownership and session-key origin are directly established by the client and capture.

### Exchanges recovered from the official session and native code

1. Complete AirShield with fresh P-256 keys and verified parameter-3 record authentication.
2. Send `EndLinkSetup` on channel `0x8001`, typed word `02001000`, protobuf field 1 = 1 and field 2 = a fresh 16-byte link identifier.
3. Open the input service using typed words `8100ce56 02000314`. `RpcRequest` field 1 is request ID, field 3 is device info, field 4 is stream control, field 5 is configuration.
4. `StreamControlReq.enableRawEmg` is field **2**. Query with an empty stream-control message; enable with `10 01`; disable with `10 00`.
5. Retain the **same DataX channel** across query, enable, and disable. Follow-up requests are untyped DataX continuations. Opening a new channel creates a distinct subscription context. A successful disable on that separate context does not stop the original stream.
6. Responses use typed word `02000315`: request ID in field 1, observed success status 1 in field 2, stream-control response in field 5. The raw-enable flag is field 2 there.
7. Stream messages use `0200020a`, with sequence number in field 1, timestamp in field 2, and the 256-byte sample block in field 3. Adjacent batches commonly differ by 7,812/7,813 timestamp units, consistent with 16 samples at 2,048 Hz and microsecond timestamps. Sequence gaps are real missing batches in the decoded stream; their cause is not yet isolated.

Native instruction references in Meta AI build `948093709` corroborate the maps rather than merely relying on storage-property order:

- `enableRawEmg` literal at `0x93d69f1`; name-map call at `0x35d0b4c`–`0x35d0b6c` associates it with field 2.
- `streamControlReq` literal at `0x93d70f0`; name-map setup at `0x35d05a8`–`0x35d05bc` associates it with RPC field 4.
- EmgConfig name-map function begins at `0x566794c`, with sampling frequency 1, channels 2, ADC bits 4, samples per batch 5, and encoding 10. Configuration response field 6 contains nested field 42 with the matching values.
- `RawEmgDecoderBridge` has separate compressed decoder paths, including an eight-channel / 128-reading wrist16 path. We have not invoked that decoder on this stream or equated its compressed input with the fixed 256-byte blocks.

### Interpretation and validation limits

`input_service.py` interprets only the observed configuration and exact 256-byte blocks as 128 little-endian unsigned 16-bit values, arranged into 16 time frames of eight channels. Fixed block length, configuration dimensions, timestamp cadence, and channel continuity support this interpretation. **It remains an experimental ADC view pending comparison with the official sample consumer.** No calibrated voltage, electrode location, or classifier accuracy is claimed. The reported sampling rate is not the achieved host delivery rate.

Run 8's requested relax/flex/relax cue was recorded at **04:11:42.711**, with the last sample at **04:11:51.475**. The cue arrived too late to capture the requested 30-second sequence. Do not treat it as a controlled movement validation. The dashboard now starts a local cue after the first samples arrive: 15 seconds relaxed, 15 seconds gentle flexing, then relaxation. Actual wearer compliance still needs confirmation.

The console at `http://localhost:8765` shows live/recent experimental ADC traces, channel-centered values with a shared count scale, sequence gaps, transport traffic, and separately labeled historical pinches. The browser receives allowlisted readings; keys, ciphertext, plaintext hex, and certificates stay in ignored local captures. Both hardware CLIs take the same process lock. Record and Stop operate the original subscription channel; Ctrl-C permits a short shutdown drain.

The instrumentation suite passes **26 tests**, covering cryptographic verification, framing/reassembly, telemetry integrity, continuation requests, raw sample values/gaps, unsupported encoding/shape rejection, and stop-response handling. HTTP/API checks verified the real recorded sample counts and absence of key/wire fields. The user's dashboard-started hardware run independently exercised the recording path and clean stop. A subsequent API Record→Stop check on the countdown build received 83 batches / 1,328 sample frames with zero detected sequence gaps, emitted `recording_started`, acknowledged disable after Stop, and received no later samples or framing errors. Browser screenshots/DOM QA were not performed.

New local evidence: `mac-band-probe-20260913-4.jsonl`, `mac-band-probe-20260914-5.jsonl` through `-8.jsonl`, `mac-band-probe-dashboard-20260914T041455956560.jsonl`, `emg-name-xrefs.json`, `rpc-stream-name-xrefs.json`, `emg-config-name-xrefs.json`, `raw-emg-decoder-disassembly.json`, `proto-storage-layouts.json`, and `raw-emg-trial-markers.jsonl`.

The subsequent isolation confirmation and direct gesture/motion experiment are documented below. Remaining raw-signal work: verify sample decoding against the official consumer and characterize/reduce loss.

## Glasses-off confirmation and next input experiment

The user subsequently confirmed that the glasses were off and the iPhone 8 had Bluetooth off. Their latest completed localhost recording, `mac-band-probe-dashboard-20260914T042629485176.jsonl`, started receiving at 04:26:37.708 UTC and stopped at 04:26:59.660 UTC. It contains 1,515 batches / 24,240 eight-channel sample frames, with 919 missing batches and a clean disable acknowledgement. Taken with the user's stated isolation conditions, this establishes a direct capture with the glasses off and phone Bluetooth disabled. Physical power state is user-reported; the transport and sample evidence are instrumented. Confirmation is preserved in `captures/isolation-confirmations.jsonl`.

The next experiment targets the user's pinch-and-rotate dial. Native name-map code confirms `enableGestures=3`, `enableGyro=6`, and `enableQuat=8`. The `dial` probe mode queries, enables, and disables these flags on the same subscription channel. It does not enable raw EMG or issue haptic commands. `hapticsReq` has RPC field 17 in the RPC name map (a separate ConfigReq reference uses another field number); its nested request schema still needs recovery before use.


## Direct hand and dial prototype — September 14, 2026

With glasses off and phone Bluetooth off as reported by the user, `mac-band-dial-20260914-2.jsonl` received **153 recognized-gesture messages, 38,023 gyro samples, and 1,580 quaternion samples**. All requested flags (3, 6, 8) were acknowledged enabled and disabled. Gesture type is `0x0200020d`, gyro `0x0200020f` (three little-endian int16 values), quaternion `0x02000212` (four little-endian floats with unit norm). Swift static field metadata supplies sequence/timestamp/sample field names and gesture enum case names. Numeric gesture mappings are provisional, supported by the observed press/release sequences; reflection case order alone is not a general proof of protobuf raw values.

The new parser exposes recognized index and middle pinch states. A relative gyro integrator drives an illustrative hand orientation and a held-index virtual dial. Gesture timestamps appear to use epoch microseconds; gyro timestamps use device uptime. The implementation uses receive ordering and only integrates differences between gyro timestamps. The observed gyro config field value 0.07 is used as an experimental scaling factor; physical units and axes still need native-consumer confirmation. Quaternion component order is also unverified, so the illustration uses integrated gyro instead. The model does not infer finger-joint angles from raw EMG.

Replay of the five-minute capture through the first dial implementation produced 15 engagement intervals and virtual value changes (range 28–100). This was an offline logic check, not physical validation. The first dashboard trial, `mac-band-probe-dashboard-20260914T045104230730.jsonl`, received 27 gestures, 669 gyro samples, and 153 quaternions, but delivery became delayed and the stop had an incomplete DataX tail and no disable acknowledgement. It is **not a clean streaming success**. The first held pinch moved the old virtual value 50→32→50; stale motion later canceled holds. The user initially reported the dial did not work and no hand was visible, then confirmed it did work but required excessive rotation and repeated release/re-pinching.

Active sensor sessions use Apple's user-initiated process activity hint to avoid App Nap and log host-loop delays over 100 ms. This is a candidate mitigation and diagnostic, **not an established cause or fix for delayed delivery**. The sidecar write benchmark was sub-millisecond (median ~0.15 ms), which did not explain the observed seconds-long gaps. [Apple's process activity guidance](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/power_efficiency_guidelines_osx/PrioritizeWorkAtTheAppLevel.html).

**Handedness:** `captures/proto-storage-layouts.json` contains native `ConfigReq._isLeftHanded`. Its wire field mapping, current value and write behavior remain unverified. The UI selection only mirrors the model. A new read-only native reflection attempt stalled during Frida script loading and was terminated; no handedness or haptic commands were sent.

**Ring/pinky:** not present among the decoded native finger enum cases. The user wants these eventually. A separate Mac classifier trained and evaluated on labeled raw sEMG is the next experimental route. Success and cross-session accuracy are not yet established. Ring/pinky model geometry remains illustrative and does not claim recognition.

Validation: **39 Python tests pass**, including fragmented motion/gesture parsing, dial engagement/release, synthetic-event rejection, sensitivity, rate control at a held twist, gap/timeout cancellation, clamping, and stale-data/secret exclusion. JavaScript/module checks pass; the local Three.js modules load and construct 3D geometry. HTTP checks verify the module assets, hand panel markup, settings API acceptance/rejection, and offline status. Browser rendering/visual QA has not been performed. Hardware testing was paused at that checkpoint while the band charged; later console trials are recorded below.


## Hand mesh and gesture references

The console uses the MIT-licensed generic right-hand GLB from WebXR Input Profiles: a continuous skin with 1,360 vertices, 2,314 triangles and 25 joints. [Asset provenance and license](../dashboard/static/models/README.md) stay with the model. Pose checks cover fingertip-pad proximity, release, unchanged ring/pinky joints, finite skin bounds and mirroring.

The supplied videos and current animation behavior are documented in [gesture references](gestures.md). Joint poses illustrate recognized events rather than measured finger angles.

## Console gesture animations and stream selection — September 14, 2026

The console now discovers nearby named Meta Band advertisements, lets the user select one, and saves that selection locally. A live ten-second scan found the existing band at RSSI −55. Start uses a selected stream mode: hand/dial (gesture, gyro and quaternion flags 3/6/8) or raw sEMG (flag 2). Stop requests subscription shutdown. macOS handles any required OS pairing prompt; the UI does not claim to have created or verified a Bluetooth bond.

The hand uses bounded recent gesture events so taps between browser polls remain visible. Single/double taps, holds and four thumb-swipe directions animate the skinned mesh. These are illustrative poses, with an adjustable palm-down view, not measured joint angles.

A combined flag 2/3/6/8 experiment received raw sEMG and motion, but failed when a complete gesture-only authenticated record arrived while a sensor DataX frame was unfinished. Offline analysis recovered the independent gesture batch, but the framing/interleaving grammar and sustained combined-stream reliability remain unresolved. Further combined runs had stalls and incomplete shutdown. The console therefore retains separate stream modes rather than enabling the combined experiment. Local evidence is in ignored `mac-band-probe-dashboard-20260914T054053169470.jsonl`, `...T054437283658.jsonl`, and `...T054602189359.jsonl`.

Returning to gesture/motion only in `mac-band-probe-dashboard-20260914T055222834048.jsonl` restored a fresh live state: an intermediate check counted 2,711 gyro messages with zero missing sequence numbers and no host-loop delay above 100 ms. This is a short-run comparison, not a claim that radio delivery is always reliable.
