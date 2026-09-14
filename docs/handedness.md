# handedness

the band has a native hand setting. the old dashboard picker only mirrored the illustration. it now reads the setting from the band and can change it before starting a session.

## use it

choose **band hand** before pressing **start**. **use band setting** reads without writing. left or right writes only when the current value differs, then reads it again to confirm. stop before changing hands. the hand illustration follows the confirmed value.

the cli uses the same flow. quit other band clients first; only one should own the connection.

```sh
# read the current configuration without changing it
python3 instrumentation/mac_band_probe.py BAND_COREBLUETOOTH_UUID --query-config --seconds 15 --output captures/hand-read.jsonl

# use the left wrist for a gesture/dial session
python3 instrumentation/mac_band_probe.py BAND_COREBLUETOOTH_UUID --hand left --stream-control dial --seconds 300 --output captures/left-dial.jsonl

# switch back to the right wrist
python3 instrumentation/mac_band_probe.py BAND_COREBLUETOOTH_UUID --hand right --seconds 15 --output captures/right-hand.jsonl
```

output files must be new. omitting `--hand` keeps the band setting. gesture/dial sessions still read it so the dial gets the correct direction. `--hand` exits unsuccessfully if the requested value cannot be confirmed. `handedness_confirmed` and `handedness_failed` events record the result; the live sidecar includes `hand` and `hand_error`.

## wire format

input service `0xce56`, request type `0x02000314`, response type `0x02000315`. these are observed private protocol fields, not a published meta api.

| message | field | meaning |
| --- | --- | --- |
| rpc request | 1 | request id |
| rpc request | 5 | nested config request |
| config request | 10 | `is_left_handed`: 0 right, 1 left |
| rpc response | 1 | matching request id |
| rpc response | 2 | observed success value 1 |
| rpc response | 6 | nested config response |
| config response | 10 | current `is_left_handed` value |

an empty config request reads current settings. nested write bytes are `50 00` for right and `50 01` for left. example rpc payloads, before datax framing and encryption:

```text
08 05 2a 00          request 5: read configuration
08 06 2a 02 50 01    request 6: set left
08 07 2a 00          request 7: independently read it back
```

the poc uses channel `0x8007` for these requests and matches reply channel 7 plus request id. the first request declares `[0x8100ce56, 0x02000314]`; follow-ups retain that type on the same channel. stream subscriptions stay on their existing channel. no calibration, electrode, haptic, or other configuration fields are written.

a write acknowledgement alone does not confirm the hand. the subsequent read must contain field 10 with the requested value. missing, invalid, rejected, mismatched, stale, and timed-out replies leave the hand unconfirmed. each request has a five-second deadline. an omitted boolean is unknown, not an implicit right hand.

## gestures and dial direction

recognized swipe labels pass through unchanged. with the band configured for the left wrist, the user confirmed that swiping right still produced right.

the virtual dial is derived from gyro motion, separately from the band's gesture recognizer. the same intended turn had the opposite gyro sign on the left wrist. the dial therefore multiplies its increment by -1 for confirmed left-hand mode, for both direct rotation and hold-to-adjust. raw gyro, quaternion, and emg data are not remapped. electrode order and calibrated anatomical axes remain unverified.

the dial cannot engage until a hand is confirmed. confirmation clears any held pinch, so release and pinch again to begin.

## evidence

on september 14, 2026, read-only inspection of meta ai ios build `948093709` mapped the `is_left_handed` string at module offset `0x93d15b0` to field 10 in the native name map (`0x35d03b8–0x35d03e0`) and descriptor construction (`0x3b1b5f0–0x3b1b610`). offsets are build-specific; the live wire checks establish the behavior used here.

the native swift client, [kinesis](https://github.com/callbacked/kinesis), read right, wrote left, and read left back independently. left remained set after disconnecting and reconnecting. the user checked gestures and corrected dial direction on the left wrist, then switched back and confirmed right-hand operation. this was one band and one wearer; persistence across a band reboot and other firmware remain untested.

the poc cli then independently performed right → left → right with a separate read-back after each write. the two ten-second sessions received 1,127 and 1,131 motion messages respectively, confirmed their requested hands, and acknowledged stream shutdown without framing errors. these checked the python transport and configuration flow; no physical gesture trials were performed during those two sessions. the ignored captures are `handedness-left-20260914-pr.jsonl` and `handedness-right-20260914-pr.jsonl`.

synthetic encrypted-peer tests cover both explicit boolean values, correlation, independent read-back, and failure paths. motion tests check both dial response modes, unchanged swipe labels and raw orientation, and unknown-hand gating. dashboard http tests check selection, start arguments, and rejection of changes during an active session.
