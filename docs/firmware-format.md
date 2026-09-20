# firmware package format

notes on the band's ota package format, condensed from a recovered production
package. version studied: `1003366292` (kek generation 20). the parser is
[instrumentation/unpack_band_ota.py](../instrumentation/unpack_band_ota.py);
it runs standalone on any package file. bring your own package.

## acquisition

the package was recovered from the companion app's local ota cache: the app
stores the download url and metadata on device, and the url itself serves the
package from a public cdn without login. the recovered package's manifest is
byte-identical to the phone's retained manifest. its rsa-pss signature
verifies under the supplied certificate. a changed-body negative control
fails. both payload blobs match manifest sizes and sha256 digests.

package sha256 for the studied version:
`03330e2343fc6dd2c8412d16be99ce39a533d91f4e12e2942d58f31c8c296a21`.

## otbh record framing

the package is a sequence of records. each data record starts with a 50-byte
header, struct format `<4sHIII32s`:

| offset | size | field |
| --- | --- | --- |
| 0 | 4 | magic `OTBH` |
| 4 | 2 | flags |
| 6 | 4 | this record's file offset |
| 10 | 4 | destination flash offset |
| 14 | 4 | payload length |
| 18 | 32 | sha256 digest |

- flags `0` (data): digest is `sha256(first 18 header bytes + payload)`.
- flags `1` (terminal): 132 bytes, ends the file. it carries a separate
  signature the parser does not verify.
- all 651 firmware and 638 ml data records in the studied package verify.

## qcompart table

the first record's payload is the partition table:

- 8-byte ascii magic `QcomPart`, then `u32 version` (1) and `u32 count`.
- then `count` rows of 64 bytes each: `u32` flash address at 0, `u32` kind at
  4, 12-byte ascii name at 8, `u32` capacity at 20, `u32` declared length at
  24, `u32` flags at 28, 16-byte iv at 32.
- table lengths exclude transport padding. partitions are reconstructed by
  flash offsets; the parser checks gaps, overlaps, lengths, and per-record
  checksums.

## partition table (firmware side)

| partition | flash offset | declared bytes |
| --- | --- | ---: |
| QCC_RAM_patc | 0x10000 | 85,020 |
| slnv20_IMAGE | 0x30000 | 4,092 |
| QCC_IMAGE | 0x40000 | 2,941,584 |
| ASSETS | 0x310000 | 2,195,456 |
| FW_KEYSTORE | 0x530000 | 150 |
| SBL_CANDIDAT | 0x540000 | 66,540 |

ml side, declared in the same manifest: `ML_CC_MODEL`, `ML_MOCK_DATA`, and
`ML_WAKE_MODE` are declared but ship zero bytes; `ML_HW_MODEL` is 5,203,940
bytes; `ML_KEYSTORE` is 256 bytes.

## what is readable and what is encrypted

readable in the package:

- `slnv20_IMAGE`: a plaintext configuration and tuning blob. lookup tables,
  ramps, parameter blocks, float coefficients. no executable code.
- `FW_KEYSTORE` and `ML_KEYSTORE`: plaintext keystore structures (below).
- `QCC_IMAGE`: an outer arm elf with a readable bootstrap. the plaintext
  bootstrap sits at file offset `0x2c98f4` (virtual address `0x2e3000`,
  17,356 bytes). the six main application regions are encrypted.
- `SBL_CANDIDAT`: readable arm code at file offset `0x81b8` (virtual address
  `0x2db000`, 31,820 bytes).

encrypted:

- the six qcc application regions. the bootstrap's region table at `0x2e6f20`
  holds `[u16 3][u8 0][u8 count][u32 entry]` then 24-byte entries of
  `[u32 dest][u32 len][16-byte iv]`. destinations match the elf's encrypted
  segments. decryption is aes-ctr; the counter is a 16-byte big-endian value
  incremented every 16 processed bytes. after decrypting, the bootstrap jumps
  to application entry `0x5e1e5`.
- `ML_HW_MODEL`: entropy 8.0, no structure recoverable without the key.

nested elf headers inside the outer containers are metadata. their offsets do
not identify intact nested executables in the flattened file.

## keystore format

a keystore is a 12-byte header plus 138-byte records at `base + 12 + 0x8a*i`.

header: `u16 format` (1), `u32 magic`, `u32 declared_size`,
`u8 record_count`, `u8 extra_count`. observed magics: `0xE7F87EED` (keystore
file), `0xDE0AA0ED` (embedded default keystore), `0x180781ED`
(already-unwrapped path). magic `0xFFFFFFFF` falls back to the embedded
default keystore.

record layout:

| offset | size | field |
| --- | --- | --- |
| 0 | 4 | firmware version |
| 4 | 4 | zero |
| 8 | 2 | type |
| 10 | 2 | parent selector |
| 12 | 4 | algorithm selector |
| 16 | 16 | wrapped key payload |
| 32 | 4 | payload length (16) |
| 36 | 16 | check bytes |
| 52 | ... | zeros |
| 134 | 4 | trailer; the check compares `record+0x86`, the last four bytes |

- `FW_KEYSTORE` record 0: version `1003366292`, type `0x3000`, parent
  selector `0xc0`, algorithm selector `0x11000004`.
- the embedded default keystore holds one populated development record for
  version 18, with the ascii string `KEKValForDevOnly` in the check position.
- context opener: parent selector = `key & 0xc0`. `0x40` selects keystore
  kind 200, `0xc0` kind 210.
- type-to-engine mapping: types `0x3000`..`0x3007` map to engine key ids
  `0x1300001E`, `1F`, `27`, `28`, `29`, `24`, `25`, `26`.

## secure-world service architecture

all key handling and bulk crypto run engine-side. bootstrap and sbl reach the
secure world through one gateway (call sites at `0x2E322C` → `0x2E363C`):

| service | command | purpose |
| --- | --- | --- |
| `0x10B` | `0x2A1419` | single-block operation; the key check builds `transform(zeros, key, algo 0x11000006/7)` and compares 4 bytes |
| `0x10C` | `0x215419` | key schedule from key handle + algorithm, then aes-ctr bulk decrypt |
| `0x117` | `0x1147` | keyram/keystore operation; turns the wrapped payload into an installed key handle |

the gateway maps error `0` to the value, `-0x20` to 1, `-0x22` to 2, anything
else to -1. the `0x117` handler is not present in any readable package image.

the decrypt-all routine at `0x2E3010` initializes (returns the algorithm
selector and a key handle), walks the region table calling the ctr decryptor
at `0x2E3340` per region, unloads the key, and jumps to the application
entry. its error paths distinguish loading the firmware key from decrypting a
segment.

## kek verdict

- the ota keystore is identical for every band of this model, so the parent
  key that unwraps it must be device-independent.
- that parent key is not in the package. it lives in the qcc rom / keyram
  defaults behind service `0x117`.
- the package requires kek generation 20. the embedded development key
  (version 18) does not unwrap it: offline candidate tests with common aes
  ctr/cbc/ecb wrapping modes matched neither the stored check bytes nor a
  plausible application vector.
- conclusion: static analysis of the package alone cannot recover the
  production firmware key. the realistic firmware-side payoff is finding an
  enforcement bug, not dodging the server receipt signature wall described in
  [enrollment-flow.md](enrollment-flow.md).

## mpu wall verdict

deep-recursion probes through the identity service (see
[research-report.md](research-report.md#corruption-verdict-mpu-wall)) bisected
the parser's depth boundary before and after dispatcher-killing wedges. the
boundary did not move across three bisections. verdict: a benign-fault wall,
consistent with an mpu stack-guard fault on the parse thread. deep json
recursion in receipts trips a protection fault, not memory corruption.
