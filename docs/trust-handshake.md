# trust handshake

this page is the implementation guide for the band's `enabletrust` exchange.
it is written for a port author: every constant, field, and ordering rule
below comes from working code and verified hardware sessions. read
[protocol.md](protocol.md) first for the transport handshake; the trust
handshake runs on top of it.

## when it runs

the handshake replaces the legacy empty identity query (`0x02003000`) on a
connection to an enrolled band. it runs once per connection, after the
airshield exchange and before end link setup. the band does not open the
input service until both directions trust each other.

two facts matter for reconnection logic:

- enrollment persists on the band across reboots. ownership and the
  provisioned identity survive power cycles.
- the trust handshake is per-session. every new encrypted connection replays
  it. a band that reboots mid-session expects a fresh handshake on the next
  connection, not a resume.

## the transcript digest

both proofs sign one digest. for sender `S` and receiver `R`:

```text
digest = SHA256( SHA256(R.challenge16 || R.pub64) || SHA256(S.seed32 || S.pub64) )
```

- `challenge16` is the 16-byte challenge the receiver sent in its
  `RequestEncryption` message.
- `seed32` is the 32-byte seed the sender sent in its `EnableEncryption`
  message.
- `pub64` is the raw 64-byte p-256 public point (x||y, no `04` prefix).

for the host proof the band is the receiver and the host is the sender. for
the band proof the roles flip.

signatures are p-256 ecdsa over the digest, encoded as raw 64-byte `r || s`.
no der, no hash headers.

## host proof: enable trust

frame:

| part | value |
| --- | --- |
| channel | `0x8002` |
| words | `[0x81000024, 0x02001000]` |
| payload field 1 | `SHA256` of the host identity public key's raw 64-byte point (32 bytes) |
| payload field 2 | the host identity signature, 64 bytes raw `r||s`, over the digest with the band as receiver and the host as sender |

`0x81000024` opens the identity service on the channel. it is only needed
before the first identity exchange on that channel; a later `enable trust` on
the same channel sends the single word `[0x02001000]`.

the host identity key is the p-256 signing key provisioned at enrollment
(see [enrollment-flow.md](enrollment-flow.md)). field 1 binds the proof to
that key without sending it.

## band result

the band answers with a result word on channel 2, in the `0x0300xxxx` family:

| word | meaning |
| --- | --- |
| `0x03001000` | host identity accepted |
| `0x03001043` | band enrolled to a different key |
| anything else | rejection |

`0x03001043` means the stored host key does not match the band's enrollment.
the full result-code map is in
[enrollment-flow.md](enrollment-flow.md#identity-service-error-map).

## band proof: enable trust ec

after (or before, or interleaved with) the result, the band sends its own
proof:

| part | value |
| --- | --- |
| type word | `0x02001001` |
| channel | a channel with the rx bit set; observed `0x8003` |
| payload field 1 | a hint, 12 bytes observed |
| payload field 2 | the band's signature, 64 bytes raw `r||s`, over the digest with the host as receiver and the band as sender |
| payload field 3 | provisioning capabilities, observed value `1` |

verification on the host side:

- if the host stores the band identity public key, verify field 2 against it.
  a wrong signature fails the connection before any acknowledgement.
- if no band key is stored, there is nothing to verify against. band
  acceptance is what matters.

acknowledge a valid (or untestable) proof with `0x03001000` on the proof's
low channel (`0x8003` → channel 3). never acknowledge a proof that failed
verification against a stored band key.

## ordering and end link setup

the band result and the band proof may arrive in either order. handle both.
acknowledgements for the band proof go out at once, but end link setup waits
until both directions are trusted.

once trusted both ways, the host sends end link setup:

| part | value |
| --- | --- |
| channel | `0x8001` |
| words | `[0x02001000]` |
| payload field 1 | varint `1` |
| payload field 2 | 16 fresh random bytes |

the band acknowledges with `0x02001000` on `0x8001`, field 1 = `1` and field 2
= 16 bytes. after that the flow rejoins the shared startup: device-info query
on `0x8003` (`0x8100ce56`, `0x02000314`), the input subscription, the
handedness read, then streams.

## failure handling

- `0x03001043`: the stored host key is wrong for this band. surface it, drop
  the connection, and forget the stored identity or re-enroll. a stale
  identity must never block a band that would otherwise connect in pairing
  mode.
- any other `0x0300xxxx`: rejection. retry the connection; if it repeats, the
  enrollment state and the stored key disagree.
- duplicate band proof: a protocol error. the band sends at most one proof
  per session.
- a band proof signed by the wrong key (when a band key is stored): fail the
  connection. do not acknowledge. do not send end link setup.

## worked timeline

one full enrolled startup, as observed:

1. transport: host `RequestEncryption` (`0x8001`, `0x02000001`), band
   `0x02000001`, host `EnableEncryption` (`0x02000002`), band `0x02000002`.
   both sides now hold the shared secret.
2. host sends `enable trust` on `0x8002` (one encrypted frame; enrolled mode
   sends no empty identity query).
3. band sends `0x03001000` on channel 2 and its `0x02001001` proof on
   `0x8003`, in either order.
4. host acks the proof with `0x03001000` on channel 3, then sends end link
   setup on `0x8001`.
5. band acks end link setup; host queries device info on `0x8003`; the input
   subscription and handedness read follow; streams open.
