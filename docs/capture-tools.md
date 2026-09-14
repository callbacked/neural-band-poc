# capture tools

These scripts were exercised against Meta AI `269.1.0` (`948093709`) on an iPhone 8 running iOS `16.7.16`, using Frida `17.5.1` on the Mac. The installed app manifest declares minimum iOS `15.2`. Other builds may have different classes or methods.

Use the Frida CLI: it includes the Objective-C bridge needed by the inspection and Bluetooth scripts. The Frida observers do not initiate Bluetooth connections or send protocol commands. Attaching and hooking still adds overhead and may affect app behavior. The direct Mac probe below actively connects and sends its documented queries.

## Direct Mac connection probe

`mac_band_probe.py` is an **active** CoreBluetooth client, separate from the passive Frida scripts. Supply the band's macOS UUID from a fresh BLE scan, and a new local capture filename:

```sh
python3 instrumentation/mac_band_probe.py BAND_COREBLUETOOTH_UUID \
  --seconds 35 --output captures/mac-probe.jsonl
```

The probe reads the band's PSM characteristic, opens L2CAP PSM 255, generates fresh P-256 keys/challenge/seed/IV/counter, and implements the observed parameter-3 exchange. It sends an empty identity/certificate query from the pinned public Starcruiser source. Received ciphertext must pass its MAC before plaintext is logged. It handles split/coalesced receive data and partial writes, and closes the connection when its duration expires. Capture files include session material for offline replay and must remain local/ignored. An existing output file is never overwritten.

The initial certificate probes established direct encrypted transport. Input-service access subsequently succeeded after `--end-link-setup`, which sends the observed `EndLinkSetup` message with a fresh link UUID. The earlier `0xc001` result is historical; its exact error definition remains unknown.

Read device information and current sensor configuration:

```sh
python3 instrumentation/mac_band_probe.py BAND_COREBLUETOOTH_UUID \
  --end-link-setup --query-device-info --query-config --seconds 20 \
  --output captures/mac-info.jsonl
```

Record the observed raw-EMG stream:

```sh
python3 instrumentation/mac_band_probe.py BAND_COREBLUETOOTH_UUID \
  --query-device-info --stream-control raw-emg --seconds 60 \
  --output captures/mac-emg.jsonl
```

Raw mode includes link completion and a configuration query. It queries stream flags, enables `StreamControlReq.enableRawEmg` (protobuf field 2 inside RPC field 4), then disables it on the **same DataX channel** before disconnecting. Follow-up requests use untyped continuations retaining the original RPC type. Opening a separate channel for disable does not stop the original subscription. Ctrl-C schedules the same shutdown with a short drain interval. Abrupt disconnects can still prevent an acknowledgement.

`input_service.py` only interprets the observed combination: 2,048 Hz, eight channels, 16-bit ADC, 16 samples per batch, encoding value 0, and 256 sample bytes. Other configurations remain uninterpreted payloads. The little-endian, interleaved ADC view is experimental; it does not provide calibrated muscle voltages or electrode identities. Sequence gaps are counted, and incomplete DataX tails are reported separately. `probe_result` includes received messages, interpreted sample frames, missing batches, and disable acknowledgement. Exit zero indicates authenticated transport reception; inspect these result fields to assess stream success. Owner identity authentication is not claimed.

For the user-controlled console:

```sh
python3 -m dashboard.server --port 8765
```

Open `http://localhost:8765`. Record starts up to 60 seconds of collection after ADC samples arrive; the displayed cue asks for 15 seconds relaxed, 15 seconds gentle flexing, then relaxation. Cue times indicate requested behavior, not verified wearer actions. The trace shows recent samples centered on each channel's window mean, with a shared ADC-count scale and visible gaps. The server exposes only allowlisted assets and curated state, requires loopback/same-origin actions, and shares the band connection lock with both hardware CLIs. Historical pinch events are explicitly separate from the live ADC view.

The read-only `inspect_emg.js` inventories relevant classes/methods in the installed phone app without heap scans or invoking device actions:

```sh
frida -U -N com.facebook.stellaapp -q -t 8 --exit-on-error --no-auto-reload \
  -l instrumentation/inspect_emg.js > captures/emg-inspection.log 2>&1
```

## Capture and decrypt a working session

Keep this iPhone unlocked with Meta AI in the foreground. The key observer is specific to the installed build above and refuses mismatched instruction/string anchors. This command launches a fresh app session and records until you type `exit`:

```sh
mkdir -p captures
frida -U -f com.facebook.stellaapp --no-auto-reload \
  -l instrumentation/capture_airshield_keys.js -l instrumentation/capture_bluetooth.js \
  -o captures/session.log
```

Wait for both `airshield_probe_ready` and `recorder_ready`. The key observer records at most 16 AirShield derivations, including shared-secret cache values and derived keys, plus challenge/seed/IV for correlation to the captured device exchange. Store these logs locally in ignored `captures/`.

After stopping:

```sh
python3 instrumentation/decrypt_capture.py captures/session.log --output captures/decrypted.json
```

The decoder verifies capture integrity, reconstructs each initial handshake, matches observations by challenge/seed/IV, independently derives keys for parameters **3** and **31**, and compares them to the app's keys. It verifies each channel-zero packet MAC before CBC decryption. Output retains padding and stream-completion timestamps. Relay/control records are stored separately without authentication/decryption claims. Session keys are not copied to the decoded output.

An incomplete final frame or failed MAC produces a nonzero exit status with an explicit error; previously authenticated records remain marked separately. Unknown parameter values, channel IDs, and control codes are rejected rather than guessed. This is transport analysis, not a standalone device-authentication or gesture client.

For a coordinated gesture sample, keep the interactive recorder running, confirm readiness, insert a marker, and only then give the wearer a GO cue. Wait for their completion reply and a quiet interval before stopping. Do not use a fixed recording timeout as a substitute for wearer confirmation. A marker can be inserted at the Frida prompt:

```js
console.log(JSON.stringify({event: 'gesture_marker', timestamp: new Date().toISOString(), phase: 'go_five_pinches'}))
```

See [findings.md](findings.md) for verified KDF/framing details and current capture results.

## Extract recorded gestures

```sh
python3 instrumentation/extract_telemetry.py captures/decrypted.json --output captures/telemetry.json
```

This reads the preceding decoder's authenticated plaintext, reassembles the observed DataX file-transfer messages, and selects files labeled `telemetry`. It verifies announced/completed lengths, Adler-32 over compressed bytes, and complete zlib decompression before releasing records. Output includes transfer receipt times and named `interaction_emg_sdk` events whose source is `EMG`. Later system/application pipeline stages are excluded to avoid counting the same recognition at every stage. All telemetry batches remain separate; aggregate counts are SDK records, not a general deduplication guarantee.

The coordinated capture contains **ten `INDEX_PRESS`, ten `INDEX_RELEASE`, and ten `INDEX_SINGLE_TAP` events** after the GO marker. They were delivered in two delayed glasses telemetry batches. This provides recorded gesture history, not a live input stream, raw EMG, or a glasses-independent connection. Event timestamps originate on the glasses and have not been calibrated against the phone's capture clock.

The parser supports the observed typed-header chain, raw file continuations, and intermediate byte-count/checksum checkpoints. Padding removal follows the observed `0xc0 + count` suffix pattern; the full padding grammar has not been independently verified. File checks detect corruption from an incorrect interpretation. This is a bounded protocol subset, not a complete DataX implementation. Files are limited to 4 MiB compressed and 16 MiB decompressed.

An incomplete transfer, invalid checksum, or upstream transport error returns nonzero. Previously completed, checked transfers remain in the output, with errors listed separately. The coordinated recording ended during a later file: its four completed telemetry files remain valid; the unfinished fifth is excluded. Input must come from `decrypt_capture.py`; this extraction step cannot authenticate arbitrary plaintext JSON itself.

## Inspect

With Meta AI running:

```sh
mkdir -p captures
frida -U -N com.facebook.stellaapp -q -t 10 --exit-on-error --no-auto-reload \
  -l instrumentation/inspect_meta.js > captures/inspection.log 2>&1
```

The inspection enumerates class names from the app and CoreBluetooth images. It deliberately avoids heap scans: `ObjC.chooseSync` stalled instrumentation during the first hardware session and required restarting Meta AI.

## Record a connection

```sh
frida -U -N com.facebook.stellaapp -q -t 120 --exit-on-error --no-auto-reload \
  -l instrumentation/capture_bluetooth.js > captures/bluetooth.log 2>&1
```

Wait for `recorder_ready` in the log before reconnecting through the official app. Existing channels opened before attachment are not registered. To capture app startup, replace `-N` with `-f`; spawning launches the app, so use it when a fresh launch is intended. Use distinct output paths to preserve earlier captures.

The observer waits up to five seconds for the app's `L2CapTransport.L2CapTransport` delegate methods to become available, then registers channels. It records channel openings, stream closes, characteristic values, and the complete bytes actually read or written for the named Meta band and display glasses. Partial writes record only the accepted bytes. Unexpected counts over 1 MiB are explicitly reported as capture errors. Stream reads and writes are **chunks**, not guaranteed application-message boundaries. Reassembly and protocol interpretation are separate work.

Every event includes a timestamp; Bluetooth events also have a sequence number. Check `capture_error`, `hook_error`, missing sequence numbers, and `stream_closed` before interpreting an interval without bytes. A silent connection does not prove absence of gestures.

## Observe crypto call sites

```sh
frida -U -N com.facebook.stellaapp -q -t 120 --exit-on-error --no-auto-reload \
  -l instrumentation/trace_crypto.js > captures/crypto-calls.log 2>&1
```

This records up to 50 calls per selected imported primitive, with module-relative caller addresses. It includes CommonCrypto cipher-create parameters and Security framework key exchange, as well as CryptoKit candidates. It does not collect keys or plaintext. When both scripts are loaded in one CLI invocation, each observed channel opening resets the sample budget through `globalThis.neuralBandChannelEpoch`. The epoch identifies a sampling interval, not ownership of every crypto call in it. Unrelated app crypto can still exhaust a budget.

For a combined bounded startup trace:

```sh
frida -U -f com.facebook.stellaapp -q -t 30 --exit-on-error --no-auto-reload \
  -l instrumentation/trace_crypto.js -l instrumentation/capture_bluetooth.js \
  -o captures/startup-crypto.log > captures/startup-crypto-console.log 2>&1
```

Imported primitives are candidates; their mere presence does not establish the band's cipher or KDF. Match observed calls to the device exchange before drawing conclusions.

## Analyze recorded setup

```sh
python3 instrumentation/analyze_capture.py captures/bluetooth.log
python3 -m unittest discover -s instrumentation -p 'test_*.py' -v
```

The analyzer requires `cryptography`. It checks event sequences and payload lengths, buffers split/coalesced initial plaintext messages by peer/channel/direction, parses protobuf wire values, validates P-256 public points, and summarizes field lengths/integers. It preserves unknown fields. It exits nonzero on capture errors or an incomplete initial exchange. A capture taken after channels opened cannot supply the missing setup.

Only the initial RequestEncryption/EnableEncryption framing observed in this build is implemented. The analyzer stops setup parsing after each direction's enable message and does not decode subsequent encrypted traffic. Its successful exit establishes capture/setup consistency, not authentication or complete radio coverage.

## Inspect native metadata

`inspect_native.js` exposes a Frida RPC `snapshot()` containing selected static strings, native imports/symbols, and main-module offsets. It does not require the Objective-C bridge. With the app running:

```sh
python3 - <<'PY'
import json
from pathlib import Path
import frida

device = frida.get_usb_device(timeout=5)
app = next(a for a in device.enumerate_applications() if a.identifier == 'com.facebook.stellaapp')
session = device.attach(app.pid)
try:
    script = session.create_script(Path('instrumentation/inspect_native.js').read_text())
    script.load()
    Path('captures').mkdir(exist_ok=True)
    Path('captures/native-inspection.json').write_text(json.dumps(script.exports_sync.snapshot(), indent=2))
finally:
    session.detach()
PY
```

The static scan can take tens of seconds. Offsets are specific to the installed app build. A symbol or string being present does not prove it runs on the observed link.

Raw logs stay in the ignored `captures/` directory. They can contain full device traffic; publish derived findings separately.

Reference: [Frida bridge packaging](https://frida.re/docs/bridges/), [Frida JavaScript API](https://frida.re/docs/javascript-api/).


## 3D hand and virtual pinch dial

Open http://localhost:8765 and refresh to load the current layout. Choose **Hand + dial**, then press **Start** for a five-minute gesture/gyro/quaternion session. Choose **sEMG** for a separate one-minute raw stream. **Band hand** reads the device setting by default; choosing left or right applies and verifies it on Start. Stop before changing hands. The 3D model mirrors the confirmed hand and supports drag or arrow-key orbit and recenter. Recognized index/middle taps and holds, plus four thumb-swipe directions, animate the hand. The default view is palm-down. Finger poses are illustrative. Wrist orientation is relative gyro integration with experimental scaling, not calibrated anatomical pose.

The slider sets 0.5–4× sensitivity; **Hold to adjust** converts a sustained twist into continuous value changes. Response and sensitivity update the active receiver through ignored local JSON; after changing them, release and pinch again. Stream gaps, stale receive data and a 10-second hold timeout release the dial. The dial waits for a confirmed hand and reverses its gyro-derived direction for the left wrist. It changes only the virtual value, never Mac volume or haptic settings. The separate Band hand selector writes the native setting; see [handedness](handedness.md).

CLI equivalent (without the dashboard's live settings file):

```sh
python3 instrumentation/mac_band_probe.py BAND_COREBLUETOOTH_UUID --query-device-info --stream-control dial --seconds 300 --output captures/my-dial.jsonl
```

Full events stay in the capture; a curated `.live.json` sidecar supplies the fast dashboard hand endpoint. Gyro is type `0x0200020f`, quaternion `0x02000212`, recognized gestures `0x0200020d`. `host_loop_delay` records receive-loop pauses over 100 ms. Probe completion now requires clean framing and explicit disable acknowledgements for the requested streams. The vendored Three.js files include their license and source information under `dashboard/static/vendor/`.
