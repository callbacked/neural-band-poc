# enrollment flow

one-time enrollment claims an unowned band and provisions an owner identity.
it runs half on the ble link and half against the hardware graph. this page
documents both halves: the https auth chain, the two `pair` routes, the ble
ceremony steps, and the identity-service error map. the trust handshake that
follows enrollment (and every later connection) lives in
[trust-handshake.md](trust-handshake.md). the transport under everything is in
[protocol.md](protocol.md).

field orders and wire shapes below were verified against a real enrollment
session and against the companion app's implementation.

## auth chain

the goal is a user access token in the `ar` universe. four form posts:

1. post `https://meta.graph.meta.com/webview_tokens_query`. it is an anonymous
   form post with the public client constant
   `FRL|388177446008673|083800dd7efbbd42eab18c9886d79c18`. the response
   carries a native SSO token and an etoken. validated with http 200.
2. open the auth url in a web view. the user signs in. the callback goes to
   `fb-viewapp://frl_login` with `token = first16(sha256(native_sso_token))`
   and a blob.
3. post `https://meta.graph.meta.com/webview_blobs_decrypt`. form fields:
   `blob`, `request_token = native_sso_token`,
   `access_token = FRL|388177446008673|083800dd7efbbd42eab18c9886d79c18`,
   `lsd = "S0." + 6 random digits`, `jazoest = "2" + digitSum(lsd)`.
   the response carries the fro access token.
4. post `https://ar-genai.graph.meta.com/login`. form fields: `frl_access_token`,
   `logging_session_id = uuid`, `format = json`, `device_id = uuid`,
   `generate_session_cookies = 1`, `generate_analytics_claim = 1`,
   `method = post`. header `Authorization: OAuth
   AR|306760944872162|a919421a55a8ea18080ab2f10f57f1be`. the response carries
   the `ar` access token and user id. this is the user session.

## pair ceremony http

both routes are form-encoded posts to
`https://graph.facebook-hardware.com/<endpoint>`. the `method = post`
convention applies. gzip is fine.

### pair_request

fields:

| field | value |
| --- | --- |
| `access_token` | `HW|1312539125771114|98588f106d5d542adbf590619ca071fe` |
| `user_access_token` | the `ar` session token |
| `user_token_universe` | `ar` |
| `pair_protocol_version` | `3` |
| `device_cert` | base64 of the band device identity certificate (identity response field 1, 967 bytes) |
| `serial_number` | the band serial (identity response field 2, 14 ascii bytes) |
| `additional_data` | compact json, see below |

`additional_data` shape:

```json
{"device_nonce": "<b64 nonce>", "app_pubkey": "<b64 app public key, 64 bytes>",
 "secondary_cert": "<identity response field 5, base64>"}
```

response json:

| field | content |
| --- | --- |
| `pending_ownership_receipt` | the server pending ownership receipt, a json string |
| `receipt_signature` | base64 der signature, 70-71 bytes |

### pair

fields:

| field | value |
| --- | --- |
| `access_token` | same hardware constant as above |
| `user_access_token` / `user_token_universe` | same as above |
| `pair_protocol_version` | `3` |
| `device_pending_ownership_receipt` | the receipt json string from the band's start-change-owner response |
| `device_pending_ownership_receipt_signature` | the base64 signature from the same response |

response json: `final_ownership_receipt`, `receipt_signature`, and
`additional_data.device_ec_public_key` (the band's ec public key — store it).

## ble ceremony

service `0x24` on top of the encrypted transport. all frames below use
channel `0x8002` with the service-open word `0x81000024` unless stated
otherwise. see [trust-handshake.md](trust-handshake.md) for the handshake
that follows step 7.

1. identity read. send words `[0x81000024, 0x02003000]`. the response
   `0x02003001` carries a protobuf: field 1 = device certificate der
   (967 bytes), field 2 = serial (14 ascii bytes), field 5 = secondary
   certificate (889 bytes). store all three.
2. skip challenge. send `[0x81000024, 0x02002000]` on a fresh channel. the
   response `0x02002001` payload is `0a10` plus a 16-byte nonce.
3. http `pair_request` (above).
4. start change owner. send `[0x02002002]` with a protobuf payload:
   field 1 = the decoded `receipt_signature` (der bytes), field 2 = the
   pending ownership receipt (the exact utf-8 json string). the response
   `0x02002003` carries the device pending ownership receipt and its
   signature: signature in field 1, receipt json string in field 2. the
   receipt contains `final_ownership_change_nonce`.
5. http `pair` (above). this returns the final receipt and signature.
6. finish change owner. send `[0x02002004]` with a protobuf payload:
   field 1 = the final receipt signature (der bytes), field 2 = the final
   receipt (the exact utf-8 json string). note the order: signature first,
   receipt second. the response `0x02002005` is empty on success.
7. enable trust, both directions. see
   [trust-handshake.md](trust-handshake.md).
8. end link setup, then device info on `0x8003`, then the input
   subscription and streams, as in the normal startup flow.

## receipts are signed bytes

receipt strings are signed byte sequences. keep them verbatim. never
reformat, reserialize, or re-indent the json before sending it to the band.

## app key storage

generate a fresh p-256 key per enrollment attempt. store it in the keychain
under the band identifier together with the band ec public key from the final
receipt. later connections use the enrolled-startup path: the trust handshake
replaces the empty identity query.

## identity service error map

results arrive as `0x0300xxxx` words on the result channel. the observed wire
form is the low 16 bits below prefixed with `0x0300`.

| code | meaning |
| --- | --- |
| `0x1041` | invalid nonce |
| `0x1042` | invalid user id |
| `0x1043` | invalid app identity |
| `0x1044` | invalid signature |
| `0x1045` | invalid time |
| `0xd001` | unknown type |
| `0xd004` | deserialize failed |
| `0xd021` | deserialize failed (transport layer; see [research-report.md](research-report.md)) |
| `0xc001` | service not found |
| `0xc004` | parse failed |
