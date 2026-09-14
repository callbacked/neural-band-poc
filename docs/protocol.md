# protocol sources

Checked September 13, 2026 (local date). Read-only research; no device calls. Local inputs: `captures/native-inspection-20260913.json` and `captures/bluetooth-20260913-startup.log`. All cited community repositories were last updated **October 26, 2025**, per GitHub commit metadata.

## Current local verification

The public sources below supplied the starting schema and parameter-31 vectors. Subsequent hardware work now verifies both the band (parameters 3) and glasses (31): the latest complete capture authenticates **850 channel-zero packets** with independently derived keys matching the companion app. See [findings.md](findings.md) for the measured formulas, relay framing, capture files, and limits. Statements below about what the public repositories do not document remain limitations of those sources, not current blockers to phone-link decryption.

## Decisive public lead

Zhuowei Zhang published **SimStella**, **Starcruiser-mac**, and Android Frida notes implementing/researching the Meta Ray-Ban **AirShield + DataX** protocol. These provide an actual setup protobuf schema and reproducible key-derivation vectors. This is substantially more specific than inferring AES-GCM from imports or packet lengths. It is community reverse-engineering evidence, not an official Meta protocol specification or a proven complete band driver.

Exact pinned sources:

- [SimStella setup schema, `atc.proto`](https://github.com/zhuowei/SimStella/blob/5c603b2957c8d51ba134dd51b580ee7a06d76c83/app/src/main/proto/com/oculus/atc/atc.proto).
- [Starcruiser `Datax.swift`: framing, handshake, crypto](https://github.com/zhuowei/Starcruiser-mac/blob/1bc6f9418ad85a10991817c74e15a84f85078f53/Sources/starcruiser/Datax.swift).
- [Starcruiser `key_derivation_test.swift`: public vectors](https://github.com/zhuowei/Starcruiser-mac/blob/1bc6f9418ad85a10991817c74e15a84f85078f53/key_derivation_test.swift).
- [Android Frida instrumentation](https://github.com/zhuowei/meta-ray-ban-android-app-frida/blob/6bfcf7ca873bb636bec8ff9560d3057a203c7062/dump_pairing.js) and [nonmultiplexed trace/derivation notes](https://github.com/zhuowei/meta-ray-ban-android-app-frida/blob/6bfcf7ca873bb636bec8ff9560d3057a203c7062/notes/non_multiplexed_differences.txt).

The [Starcruiser README](https://github.com/zhuowei/Starcruiser-mac/blob/1bc6f9418ad85a10991817c74e15a84f85078f53/README.md) documents receiving `RequestEncryption` from glasses over service `FD5F`, characteristic `05ACBE9F-6F61-4CA9-80BF-C8BBB52991C0`, and an L2CAP channel. It describes limited functionality; do not assume full end-to-end control.

## Schema and fresh-capture comparison

Public `com.oculus.atc` setup IDs: request encryption `1`, enable encryption `2`, link setup config `3`, end link setup `0x1000`. The schema contains these protobuf fields:

| Message | Fields |
| --- | --- |
| RequestEncryption | `1 bytes public_key`; `2 bytes challenge`; `3 int32 elliptic_curve`; `4 int32 supported_parameters`; `5 repeated bytes key_hint`; `6 int32 quirks` |
| EnableEncryption | `1 bytes public_key`; `2 bytes seed`; `3 bytes iv`; `4 uint32 base`; `5 int32 parameters`; `6 int32 quirks`; `7 bool phased_link_setup_supported`; `8 int64 supported_link_setup_services` |

[Schema source](https://github.com/zhuowei/SimStella/blob/5c603b2957c8d51ba134dd51b580ee7a06d76c83/app/src/main/proto/com/oculus/atc/atc.proto).

An independent offline wire-type parse of the local startup capture consumed **all eight plaintext setup frames without leftovers** using protobuf offset 12 for requests and 8 for enables. Source code selects these offsets via the high bit of byte 2. All eight also satisfy the locally observed `(u16be(first2) & 0x7fff) + 4 == length` rule. Preserve that observed length rule: the public sample's request encoder does not consistently account for its extra four-byte header.

| Local capture sequences | Observations |
| --- | --- |
| Glasses 8, 9 | Type 1; public key 64 bytes, challenge 16 bytes, curve 0, supported parameters 31. Unknown field 7 is 17/16. |
| Glasses 10, 12 | Type 2; key 64, seed 32, field 3 length 16, base varint, parameters 31. Glasses response additionally has fields 7=1 and 8=1. |
| Band 96, 97 | Type 1; phone offers 31, band offers **3**; band key hint is 12 bytes. Phone includes unknown field 7=16. |
| Band 98, 106 | Type 2; key 64, seed 32, field 3 length 16, base varint, parameters **3** in both directions. |

The field-3-as-IV interpretation now has a concrete matching schema. The public implementation distinguishes parameters **0, 7, 31**; it does not document what changes for the band's **3**. Unknown request field 7 and a general definition of every parameter bit remain unresolved. The later local native-key/MAC checks, rather than this schema parse, establish decryption for values 3 and 31.

## Candidate algorithms and exact roles

For the published **31** vector, let `S` be the raw P-256 ECDH shared secret. For a sender, `C` is the receiver's RequestEncryption challenge; `R` is the sender's EnableEncryption seed. The vectors implement:

```text
Kenc = HKDF-SHA256(IKM=S, salt=SHA256(C || R),
                  info=UTF8("AirShield"), output=32 bytes)
Kmac = HKDF-SHA256(IKM=S, salt=SHA256(R || C || UTF8("hmac_derive")),
                  info=UTF8("AirShield"), output=32 bytes)
```

TX uses remote challenge/local seed; RX uses local challenge/remote seed. **Offline validation reproduced the two published key values and packet's eight-byte HMAC: 3/3 checks passed**, using Python `hashlib`/`hmac` and the public vector constants. This verifies that example, not the live session. [Vector source](https://github.com/zhuowei/Starcruiser-mac/blob/1bc6f9418ad85a10991817c74e15a84f85078f53/key_derivation_test.swift).

The separate **7** notes use `H=SHA256(S)` as HKDF input, encryption salt `SHA256(H || C || R)`, and MAC salt `SHA256(R || C || "hmac_derive" || H)`. The notes omit the multiplexing header from the MAC input. Later local checks confirm that parameter 3 uses this encryption-key branch but reuses the encryption key as its MAC key; it does not use this separate parameter-7 MAC derivation. [Primary experiment notes](https://github.com/zhuowei/meta-ray-ban-android-app-frida/blob/6bfcf7ca873bb636bec8ff9560d3057a203c7062/notes/non_multiplexed_differences.txt).

The Swift implementation uses AES-CBC and truncated HMAC-SHA256. For 31, the MAC input is `02 02 00 00 || LE32(base) || metadata_byte || ciphertext`; wire output prepends `40` and the first eight MAC bytes. Initial directional IV/base come from the sender's EnableEncryption. **Do not copy this as a working driver:** receive uses TX keys, advances IV from plaintext, omits MAC rejection, assumes reads equal frames, and uses fixed test randomness. Its header logic and negotiation also need validation. [Inspected implementation](https://github.com/zhuowei/Starcruiser-mac/blob/1bc6f9418ad85a10991817c74e15a84f85078f53/Sources/starcruiser/Datax.swift).

## Parameter-bit limits

**No explicit parameter-3 definition was found in the pinned sources.** SimStella contains a comment attributing multiplexing to `1 << 1`, but its actual implementation treats 31 as multiplexed and 7 as nonmultiplexed. Both contain that bit, so the comment is internally insufficient and must not become a protocol constant. Its only named protocol variants are 0, 7, and 31. [Pinned Kotlin implementation](https://github.com/zhuowei/SimStella/blob/5c603b2957c8d51ba134dd51b580ee7a06d76c83/app/src/main/java/net/zhuoweizhang/simstella/MainActivity.kt).

## Relay framing: public evidence and limits

A final bounded pass found **primary evidence for a separate Relay framing layer, but no public grammar for the standalone `81 00` or `01 <length>` records**. All three previously pinned repositories were searched for relay/framing handlers; their current heads remain the October 26, 2025 commits. Their implementations handle the initial DataX headers and the encrypted `40` prefix, but do not implement the new relay/control forms observed locally. The public fork list did not expose a newer implementation in this pass.

The researcher's **October 19, 2025** app log explicitly says the RequestEncryption handler enables TX Relay framing when multiplexing is enabled; the EnableEncryption handler then enables RX Relay framing. In the same log, the app sends 26 encrypted bytes on the wire but reports a complete received frame of 25 bytes. That is consistent with one byte being consumed by an outer framing layer; it does not by itself define arbitrary relay records. [Direct first-party experiment post](https://notnow.dev/notice/AzMB113Mv5m2mwwmf2).

A separate **October 11, 2025** post identifies the Android native wrapper as `com.facebook.wearable.airshield.stream.Framing`. This matches the `airshield::stream::Framing` type seen in the local iOS inventory. [Direct first-party post](https://notnow.dev/notice/Az7D7HydWy3E12VWMa). The captured iOS string at `0x896ca80` also specifically names Substream Advertising Relay between AirShield 1.1+ devices; that is local static evidence, not a wire-format definition.

Local captures established authenticated outer-channel crypto in both band directions, plus byte-for-byte forwarding of an inner handshake between band and glasses. Those are newer local results and supersede the earlier research-only uncertainty about parameter 3. The reported `01 71 + 114 bytes` and `01 73 + 116 bytes` support a payload-length-minus-one interpretation **for those examples only**. Public research here does not establish the general length encoding, the meaning of `81 00`, stream-number bits, or control-opcode assignments. Keep outer authenticated records, relay payloads, and control records distinct; inner authentication is a separate session and is not proved by outer-channel MAC success.


### Subsequent local framing results (September 13, 2026)

Local MAC verification established these record boundaries. These are **observations from this project, not a published AirShield specification**, and refine the limits of the earlier public-source pass:

| Observed prefix | Local interpretation and evidence |
| --- | --- |
| `40` | Authenticated channel 0 record: `40 || MAC[8] || block_count_minus_1[1] || ciphertext[16 × (block_count_minus_1 + 1)]`. Every one of **850 authenticated channel 0 packets** satisfied the ciphertext block-count rule. The count byte is byte 9 with zero-based indexing. |
| `01` | Clear relay record: `01 || payload_length_minus_1[1] || payload[payload_length_minus_1 + 1]`. Subsequent authenticated-record boundaries verified this length rule in the observed stream. |
| `81 00` | Observed standalone control record. Its exact control meaning remains unresolved. |
| `41` | Observed encrypted relay/channel 1 records, forwarded byte-for-byte between peers after the forwarded handshake. The decoder preserves these as opaque records using the same block-count rule; outer channel 0 authentication does not authenticate the inner session. |

The public sample's fixed `00` byte after its eight-byte MAC therefore corresponds to **one ciphertext block** in these captures. Treating it as an arbitrary constant or metadata byte loses record boundaries for longer ciphertext. This correction comes from local authenticated packets; the cited public example happens to encrypt a 16-byte identity request.

The live parameter-3 branch was authenticated in both directions: with `H = SHA256(S)`, `Kenc = HKDF-SHA256(IKM=H, salt=SHA256(H || C || R), info="AirShield", output=32)` and `Kmac = Kenc`. This supersedes the earlier candidate-only status of parameter 3. Session secrets are intentionally omitted here.
