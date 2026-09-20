# offline research report

condensed and sanitized findings from the static-analysis and device-in-the-loop
fuzzing campaign against the band's identity service. sanitized: no serial
numbers, device identifiers, host paths, or key material. the full protocol
material lives in [enrollment-flow.md](enrollment-flow.md) and
[trust-handshake.md](trust-handshake.md). the firmware format lives in
[firmware-format.md](firmware-format.md).

scope of the original work: static analysis of recovered package and app
artifacts, plus authorized fuzzing of our own band over ble. no meta contact.
the band's watchdog recovers it from fuzz-induced faults.

## identity service certificates

the identity response (`0x02003001`, 1878-byte payload) is a three-field
protobuf:

| field | bytes | content |
| --- | --- | --- |
| 1 | 967 | device certificate, raw der |
| 2 | 14 | serial, ascii |
| 5 | 889 | secondary certificate, raw der |

certificates are raw der on the wire. base64 wrapping exists only in the
phone-side json keystore.

- the leaf (`CN=Swiftlet Test Certificate`) is issued by the on-device
  secondary certificate (`CN=Swiftlet-PSoC Test Certificate`). validity runs
  40 years. names are test-style.
- the secondary chains to `Ceres MP Device Signing CA`. that root is absent
  from every retained artifact: package, captures, and app bundles. no chain
  signature to it can be checked or forged offline.
- custom enterprise oids `1.3.6.1.4.1.40981.2.3.8` through `.12` ride on both
  certificates: a date string, the serial string, a shared 83-byte blob (13
  opaque bytes plus a 70-byte der ecdsa signature), the `id-ecPublicKey` der,
  and a second embedded p-256 spki. no local key matches the blob's signature
  or the embedded key.
- the firmware boot chain (Qualcomm sec-image headers: `Swiftlet Qcom FW
  Signing Certificate` under `Swiftlet FW Root 3`, plus alternate roots 0-2,
  and the separate Qualcomm SRoT chain) ships in plaintext and parses as der.
  all five meta boot certs use secp384r1. this chain is separate from the
  identity chain.
- no identity-chain key matches any host-side, band-side, or candidate key in
  the evidence set.

## json depth guard

the identity service parses the receipt json, then decodes the
`additional_data` string as json a second time. recursion depth is therefore
attacker-controlled.

- coarse bracket: depths up to 224 parse (`0x1044`, parsed but bad signature);
  240+ hits the guard (`0xd021`, deserialize failed).
- exact boundary on one boot, by bisection at single-depth precision: depth
  228 parses, depth 229 rejects. 54 informative attempts, zero flaky depths.
- the boundary drifts across boots. another session saw 200 parse and 224
  reject. the guard constant may track boot state or charge state.
- the guard is size-insensitive: at fixed depth 300, padding the receipt from
  2546 to 3354 bytes changes nothing. depth, not bytes, trips it.
- depth 256+ payloads produced silence twice (watchdog reboot or wedge), while
  depth 300 rejected cleanly three times in the same connection. the
  rejection-versus-silence split near the boundary is stateful or
  nondeterministic.

## array bypass

the depth guard tracks object nesting or receipt shape. arrays bypass it:

- array bombs (`'[' * D + '1' + ']' * D` in `additional_data`) parsed at
  depths where object bombs were guard-rejected, and the band stayed alive.
- array rpc-silence onset moved from `(440, 500]` to `(200, 300]` across a
  charger reboot. state-dependent, like the object boundary.
- full array ladder, 30 attempts, zero reboots:

| depth | wire bytes | records | outcome |
| --- | --- | --- | --- |
| 500-1600 | 1158-3358 | 1 | no case reply, band alive |
| 2000-2800 | 4158-5758 | 2 | input-service read died 9/9 for that connection |
| 3200-3600 | 6558-7358 | 2 | alive again |

the damage zone is non-monotone in depth. deeper frames did less visible
damage than mid-depth frames, which suggests a fast-fail length precheck
before the parser recurses at mid depths.

## wedge behavior

a method correction that invalidates earlier results: the identity read
answers exactly once per setup channel. a second read on a used channel, or a
read on a virgin channel, gets no reply on a healthy band. identity reads are
not a liveness probe. valid liveness probes are the input-service device-info
read on `0x8003` (answers `0x300c001` in about 40 ms when healthy) and the
battery gatt read (acl level, always answers).

with the corrected method:

- a deep narrow string sibling (3800 chars inside the deepest object, 7478
  bytes across 2 records) soft-killed the device-info read 5/5. per-connection
  damage, no reboot, no identifier rotation.
- a depth-2400 array bomb killed the entire datax rpc surface on that
  connection: device-info, config read, end link setup, and case parses all
  silent, while battery gatt stayed alive. the damage sits in the datax
  dispatch layer, below acl.
- wedges never survived reconnection. a fresh connection answered everything,
  every time.
- oversized two-record frames (up to about 7.5 kb) are accepted at the
  transport level and then either processed or silently ignored, with no
  damage. one encrypted record caps at 256 blocks (4096 bytes); the datax
  frame reassembles across records.

## corruption verdict: mpu wall

the question behind the wedge hunt: does deep recursion overwrite live memory
(the depth boundary should drift after wedges) or hit a benign wall (the
boundary stays put)?

- baseline bisection: 228 parses, 229 rejects.
- five depth-2800 wedges (full dispatcher death) and five depth-3600 wedges
  (rpc-silent, dispatcher alive) later: 228 parses, 229 rejects. identical at
  every probed depth, three bisections in a row.
- verdict: benign-fault wall, consistent with an mpu stack-guard fault on the
  parse thread. not memory corruption. see also
  [firmware-format.md](firmware-format.md#mpu-wall-verdict).

## error semantics

`datax_error_name` (exported by the band's datax library) maps error codes to
names through two jump tables. full extracted table:

| code | name | code | name |
| --- | --- | --- | --- |
| `0x0000` | ok | `0xd005` | missing_type |
| `0xc001` | service_not_found | `0xd001` | unknown_type |
| `0xc002` | service_lost | `0xd002` | deprecated_type |
| `0xc003` | out_of_channels | `0xd003` | removed_type |
| `0xc004` | internal_error | `0xd004` | bad_type |
| `0xc005` | message_overflow | `0xd010` | bad_request |
| `0xc006` | channel_closed | `0xd011` | bad_response |
| `0xc010` | service_restored | `0xd020` | serialize_failed |
| | | `0xd021` | deserialize_failed |

the phone-side `Error` class corroborates the c family: wire code =
`0xc000 | ordinal`. the d family is a glasses/band-side dispatch family with
its own numbering.

campaign observations:

- across 97 rounds (1164 mutated receipt cases), the band produced exactly two
  reply kinds: `0x03001044` (parsed, bad signature, 616 times) and
  `0x0300d021` (deserialize failed, 523 times). nothing else ever.
- the `0xd021` send sites in the band binary sit in peer-connection and
  topology services, not in the identity handler. the identity handler itself
  sends `0xd004`, `0xd001`, and `0xd010`. inference: observed receipt
  rejections with `0xd021` come from the request deserialization layer before
  the identity handler parses the payload.

## jsoncpp vintage track

to identify the band's json parser, three jsoncpp vintages (1.9.8, 1.9.5,
0.10.7) were built from source and fuzzed with a 5505-case corpus through the
band's double-decode pattern (outer receipt, then `additional_data`).

- classic `Json::Reader` mode: zero crashes; the depth-limit throw escapes
  `parse` with no internal catch.
- `CharReader` mode: 1037 crashes, all SIGABRT. root cause in every one:
  jsoncpp counts nesting depth, throws `Exceeded stackLimit in readValue()`,
  and the exception escapes `parse` into `std::terminate`.
- depth ceilings: 255 for 1.9.8, 999 for 1.9.5 and 0.10.7. no other input
  family crashed anything.
- the band matches no stock vintage on two facts: its cap sits at 228/229
  (stock rejects at 256 or 1000), and it answers gracefully with
  `deserialize_failed` (stock dies by SIGABRT without a handler).
- verdict: the band runs a depth or size check in a wrapper layered over
  jsoncpp, with a catch that maps failures to `deserialize_failed`. the exact
  jsoncpp vintage stays unknown; the band links a vndk-era `libjsoncpp.so` it
  does not ship in any readable artifact.

## firmware and kek architecture summary

full notes in [firmware-format.md](firmware-format.md). the short form:

- the ota package ships otbh-framed records with a qcompart partition table.
  the firmware keystore ships as plaintext; the application regions are
  aes-ctr encrypted by a readable bootstrap.
- `ML_KEYSTORE` is byte-identical to `FW_KEYSTORE`: one wrapped key opens both
  the firmware and the ml model.
- all crypto is engine-side. bootstrap and sbl reach the secure world through
  one gateway: `0x10b` single-block ops, `0x10c` key schedule plus aes-ctr
  bulk decrypt, `0x117` keyram/keystore unwrap.
- the parent key that unwraps the keystore lives in qcc rom / keyram defaults
  behind service `0x117`. it is not in the package. static analysis of the
  package alone cannot extract the production key.
- the sbl's unlock verifier trusts a standalone p-256 anchor that matches no
  recovered certificate.
