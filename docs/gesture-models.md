# gesture models

notes from september 14 and 15, 2026. the consumer band now streams readable model scores. eight output channels have been matched to gestures, and the app's native label table names the ninth `thumb_tap`. the weights remain unrecovered.

## what meta already released

the closest reference is [generic-neuromotor-interface](https://github.com/facebookresearch/generic-neuromotor-interface). it includes model implementations, training code, datasets and downloadable pretrained checkpoints for discrete gestures, wrist movement and handwriting. each checkpoint comes with its configuration. this is a concrete starting point for inspecting a gesture decoder without extracting anything from the band.

the associated [nature paper](https://www.nature.com/articles/s41586-025-09255-w) describes a discrete-gesture decoder with a temporal convolution, three lstm layers and a classifier. its nine outputs cover index/middle press and release, thumb tap and four thumb swipes. that vocabulary is close to our observed events, but it does not establish that the consumer firmware uses the same architecture or weights. the repository's [input constants](https://github.com/facebookresearch/generic-neuromotor-interface/blob/main/generic_neuromotor_interface/constants.py) explicitly specify 16 channels at 2,000 hz.

[emg2pose](https://github.com/facebookresearch/emg2pose) also releases pretrained hand-pose checkpoints and paired motion-capture data. [emg2qwerty](https://github.com/facebookresearch/emg2qwerty) releases typing data and checkpoints. these are useful research references for richer input, not consumer-band drivers. the repositories carry noncommercial licenses; public weights do not imply unrestricted reuse.

our stream reports eight channels at 2,048 hz, and its interpretation remains an experimental adc view: electrode mapping and voltage calibration are unresolved. matching channel count, placement, filtering, scale and timestamps is necessary before judging transfer; resampling or duplicating eight channels into sixteen does not demonstrate compatibility. see [our raw-stream findings](findings.md#raw-emg-stream-activated-september-14-2026).

## where the consumer model might be

[meta's emg faq](https://www.meta.com/en-gb/emerging-tech/emg-wearable-technology/) says the machine learning runs locally on device. our standalone gesture events are consistent with inference on the band. the sources reviewed do not establish a public release of the exact consumer weights, firmware image or model architecture.

ignored local evidence in `captures/native-inspection-20260913.json` includes `gesture_tracking_models`, `emg_handwriting_models`, `emg_device_model_ids`, `MCU_EMG_MODEL_SWITCH`, `EMG_MODEL_STATE`, `emg_raw_gesture_inference_model_load_ts_us` and `emg_device_ml_model_version`.

## what the consumer app and band expose

read-only inspection of meta ai 269.1.0 recovered the native `RawInferenceSample` and `InferenceConfig` schemas. the sample has fields for output channels, pipeline type, sequence number, timestamp, emg batch ids and imu timing. swift reflection identifies channels as `Data`, the sequence as `UInt32`, and the timestamp as `UInt64`. native name maps supply wire numbers; descriptor order is not wire order.

native protobuf name maps establish:

| message | field | name |
| --- | --- | --- |
| `StreamControlReq` | 4 | `enableRawInference` |
| `ConfigReq` / `ConfigResp` | 46 | `inferenceConfig` |
| `InferenceConfig` | 1 | `DownsampleWindow` |
| `InferenceConfig` | 2 | `ModelStride` |
| `InferenceConfig` | 3 | `pipeline_type` |
| `InferenceConfig` | 4 | `normalized` |
| `InferenceConfig` | 5 | `numLogits` |
| `DeviceInfoResp` | 9 | `modelId` |
| `DeviceInfoResp` | 10 | `allModelIds` |

the band reports pipeline 2, downsample window 0, model stride 32 and nine logits. `normalized` is absent. the earlier handedness capture also reported nine logits before and after its hand-setting write. matching the public research model's output count does not establish matching labels, architecture or weights.

the saved device-info response reports these six model ids through repeated field 10:

```text
cc_od_resetlstm_F1017719999_260108
ia_od_F1068590897_260418
hw_t59_f1076659698_260503
Ceres_BOD_v48
Ceres_PLI_Detect_v38
tightness_f1032497175_260207
```

`resetlstm` is an architecture clue in a consumer model name, not a recovered graph. field 9 was absent in this response, so the list alone does not identify the currently active model.

the native bulk-transfer enum also contains `modelUpdate`, separately from `ota`, `coreDump` and `log`. this identifies a model-transfer mechanism; it does not establish that we can download weights, bypass update verification or install our own model.

the app bundle and its library/documents inventory did not reveal an identifiable consumer gesture checkpoint. the bundled `pytorchmodel.pt` describes a speech segment encoder; other named models are camera assets. the inspected `model_blobs` and executorch model directories were empty, and the remote-asset cache contained videos. firmware preferences had no cached ota binary entries. files with opaque names or assets stored elsewhere remain unresolved.

local evidence is saved under ignored `captures/`: `gesture-model-native-metadata.json`, `gesture-model-name-xrefs.json`, `gesture-model-map-helpers.json`, `gesture-model-sample-xrefs.json`, `gesture-inference-config-evidence.json` and `gesture-device-model-id-evidence.json`. the latter two come from existing authenticated captures. no firmware or model changes were made during this investigation, and no consumer weights have been recovered.

## native gesture label table

the meta ai binary builds two string-keyed tables in one static initializer (main-module offsets `0x184e58`–`0x185698`). read-only inspection recovered both from memory on september 14.

the first table maps nine model label names to output indices:

| index | native label |
| --- | --- |
| 0 | `index_press` |
| 1 | `index_release` |
| 2 | `middle_press` |
| 3 | `middle_release` |
| 4 | `thumb_tap` |
| 5 | `thumb_up` |
| 6 | `thumb_down` |
| 7 | `thumb_in` |
| 8 | `thumb_out` |

the second table describes practice gestures as sequences of those labels. `thumb tap` is `thumb_tap`. `thumb double_tap` is `thumb_tap` twice. `index tap` and `index hold` are both `index_press` then `index_release`, and `index double_tap` is that pair twice. `middle tap` is `middle_press` then `middle_release`. the `middle hold` and `middle double_tap` entries fall outside the saved disassembly window. neighbouring strings (`trial-start`, `trial-end`, `xr-action`, `gesture_practice_well_done`) place these tables in the app's gesture-practice code.

the index table agrees with all eight measured channels, including the consumer swipe order. the public [research constants](https://github.com/facebookresearch/generic-neuromotor-interface/blob/b6bf250e2be5a67b23488104335373cdb87a15c9/generic_neuromotor_interface/constants.py#L16) use `thumb_click = 4`, `thumb_down = 5`, `thumb_in = 6`, `thumb_out = 7`, `thumb_up = 8`; the consumer order is up, down, in, out. on the right wrist `thumb_in` corresponded to the band's `left` swipe event and `thumb_out` to `right`. [handedness](handedness.md) showed that left/right events keep their physical meaning on the left wrist, so the in/out to left/right translation appears to happen on the band rather than in the model output. that inference has not been checked against firmware.

the only code references to the index table are its constructor and two registered destructors. a scan of the main binary for direct address references found no other consumer, so the runtime reader of this table is still unidentified. the band's own gesture-event enum contains `click` and `partialClick` actions, and the app keeps `thumbClickGestures` and `thumbClickGesturesDiscarded` counters, so a thumb click exists in the consumer vocabulary. no thumb click event has appeared in any capture yet, and meta's [public faq](public-integrations.md) lists only the four swipes and the index and middle pinches.

local evidence: `gesture-label-map-native-evidence.json` (initializer disassembly and strings), `gesture-label-map-consumers.json` (map nodes and references), `gesture-label-map-xrefs.json`, `inference-label-name-xrefs.json`, and the frida scripts beside them.

## live score capture

requesting gesture and raw-inference flags 3/4 returns type `0x0200020c`. the observed sample has sequence in field 1, device timestamp in field 2, a 36-byte channels block in field 3, and pipeline type 2 in field 10. the block decodes as nine little-endian float32 scores. the new `inference` mode waits for a stream-query response before enabling, then disables both flags on the original subscription channel.

the coordinated capture contains 6,134 score samples over 95.89 seconds of device time, with a median 15,625 µs period and four missing sequence numbers: approximately 64 hz. both enable and disable were acknowledged. the user performed two rounds of taps and swipes, including repeated swipes. kinesis was stopped for the recording and reopened afterward.

| channel | association on the right wrist | matching dominant peaks / recognized events |
| --- | --- | --- |
| 0 | index press | 11 / 11 |
| 1 | index release | 11 / 11 |
| 2 | middle press | 14 / 14 |
| 3 | middle release | 14 / 14 |
| 4 | `thumb_tap` by native label; no live activation | no matching event |
| 5 | thumb swipe up | 8 / 8 |
| 6 | thumb swipe down | 8 / 8 |
| 7 | thumb swipe left | 11 / 11 |
| 8 | thumb swipe right | 8 / 8 |

these are empirical associations from one band and one wearer. the comparison takes each channel's maximum score from 250 ms before to 40 ms after a recognized gesture's host receipt time. partial and derived events are excluded. the gesture and score device timestamps use different time bases, so this does not measure inference latency. the analyzer reports the native labels beside the measured channels; it does not rename the measured associations.

the swipe ordering differs from the public [research constants](https://github.com/facebookresearch/generic-neuromotor-interface/blob/b6bf250e2be5a67b23488104335373cdb87a15c9/generic_neuromotor_interface/constants.py#L16) and matches the native label table above. channel 4 carries the native label `thumb_tap`; neither live capture activated it.

a follow-up asked the user to alternate side-of-index thumb taps with ordinary fingertip pinches. `captures/raw-inference-thumb-tap-20260914.jsonl` contains 4,600 score samples with both stream acknowledgements. channel 4 stayed negative, peaking at −1.1473, and no thumb tap/click event appeared. its median in that capture was −17.44, and each of its eight highest peaks (−1.15 to −2.75) coincided with an `index_release` score above zero, so the attempts registered mostly as index presses and releases. recognized events were mainly index presses/releases, alongside partial index and swipe motions. individual attempted taps and control pinches were not separately timestamped, so the events cannot be assigned to specific attempts. this did not produce a live thumb-tap activation; a negative score alone does not establish the consumer's activation threshold, and the motion that the consumer model expects is unverified. analysis is saved in `raw-inference-thumb-tap-summary.json` and `raw-inference-thumb-tap-analysis.json`.

all captured score values reconstruct exactly as `float32(integer * float32(0.1147265625))`. this recording contains 254 distinct levels with integer multipliers from −192 to 61. that is consistent with dequantized output, but does not establish the weights' precision, signedness or zero point. scores are exposed unchanged. the public [research code](https://github.com/facebookresearch/generic-neuromotor-interface/blob/b6bf250e2be5a67b23488104335373cdb87a15c9/generic_neuromotor_interface/lightning.py#L281) applies independent sigmoids rather than softmax; the consumer's probability calibration and event thresholds remain unverified.

the experimental reader and offline analyzer are local changes:

```sh
python instrumentation/mac_band_probe.py <band-uuid> --stream-control inference --seconds 100 --output captures/inference.jsonl
python instrumentation/analyze_inference.py captures/inference.jsonl --output captures/inference-analysis.json
```

close kinesis and other band listeners first. captures include session material and stay ignored. analysis outputs contain only score/gesture statistics. the plot and evidence are in `captures/raw-inference-gestures.png`, `raw-inference-gesture-analysis.json`, `raw-inference-quantization.json` and `raw-inference-gestures-20260914.jsonl`.

next: activate channel 4 live, ideally while the meta app's own thumb-tap practice prompt is running, find the runtime reader of the label table, establish the score-to-event rules and clock relationship, and trace model-update packages using the reported model ids. paired emg/score recording could support a replacement model, but simultaneous capture and alignment have not been established in this pass. no model weights, firmware, thresholds or handedness settings were written.
