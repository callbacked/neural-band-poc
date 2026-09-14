# public integration references

Source snapshot: September 13, 2026. This covers other integration paths. The project’s later direct Mac results are in [findings](findings.md). Undated documentation reflects its state when inspected.

## What has changed

**There is now a documented way to receive consumer Neural Band inputs in third-party software, through a Web App running on Meta Ray-Ban Display glasses. This does not establish a glasses-free Bluetooth interface.** Meta announced its display development paths on **May 14, 2026**. The Web Apps path uses HTML/CSS/JavaScript and includes band input; the native Device Access Toolkit extends mobile apps to the glasses. “Standalone” in this announcement describes a display web experience, not a standalone wristband connection. [Meta announcement](https://developers.meta.com/blog/build-for-display-glasses/), [Meta FAQ](https://developers.meta.com/wearables/faq/).

The live FAQ describes four directional swipes, index pinch for enter, and middle pinch for cancel, with no custom gestures. It still calls the platform a **Developer Preview**, says general publishing is unavailable, and permits sharing Web App URLs with users who enable Developer Mode. These are current documentation statements, not confirmation that a particular user's firmware exposes every capability. [Meta FAQ](https://developers.meta.com/wearables/faq/).

**The official code repository documents more than the FAQ's basic gesture list:** its `add-gestures` instructions describe continuous pinch-and-drag, enabled by `body { touch-action: none; }` in the initial stylesheet, then `pointerdown`, `pointermove`, and `pointerup` handlers. It explicitly requires verifying event fields on-device and says Pointer Lock is unsupported. That file's latest commit was **August 6, 2026**, `24d7bfc5`. Treat this as a promising documented capability to test, not a measured result on our hardware. [Pinned Meta gesture instructions](https://github.com/facebook/meta-wearables-webapp/blob/24d7bfc553d33d7fe849cd70d04544b1de555896/plugins/meta-wearables-webapp/skills/add-gestures/SKILL.md).

## Available paths and their limits

| Path | Evidence | What remains unresolved |
| --- | --- | --- |
| Glasses-mediated control of another computer/app | Official Web Apps code includes event handling and REST/WebSocket integration patterns. A small web app can receive band events; forwarding them to our own receiver is an engineering proposal supported by those primitives. | Hardware behavior, latency, app suspension, off-head use, reconnects, and usable continuous pointer fields. Glasses remain part of this route. |
| Direct consumer-band BLE integration | This bounded search did not identify and verify an independent implementation completing the consumer-band handshake and decoding live inputs without glasses. | This is not proof that none exists. The local protocol work must be evaluated on its captures and reproducible results. |
| Meta EMG partnership | Meta's **January 6, 2026** CES post describes Garmin and home-control prototypes and explicitly invites developers/companies to describe EMG integrations through a linked form. | A prototype and invitation are not a public SDK, acceptance, delivery date, or permission to use restricted partner interfaces. |
| Project Aria research | Meta's research application asks about Neural Band EMG/IMU use. Aria Gen 2 docs expose a `register_neural_band_batch_callback` API; open-source readers decode EMG, accelerometer, and gyroscope batches. | This is an Aria research context. Consumer-band provisioning, firmware compatibility, and direct laptop pairing are unestablished. |

Sources: [Meta REST/WebSocket instructions](https://github.com/facebook/meta-wearables-webapp/blob/main/plugins/meta-wearables-webapp/skills/connect-api/SKILL.md), [Meta CES post, January 6, 2026](https://www.meta.com/blog/ces-2026-meta-ray-ban-display-teleprompter-emg-handwriting-garmin-unified-cabin-university-of-utah-tetraski/), [Garmin's same-day proof-of-concept announcement](https://www.garmin.com/en-US/newsroom/press-release/automotive/garmin-and-meta-announce-automotive-oem-proof-of-concept-with-garmin-unified-cabin-and-meta-neural-band/), [Aria research application](https://ai.meta.com/aria-application/), [Aria Gen 2 API](https://facebookresearch.github.io/projectaria_tools/gen2/technical-specs/client-sdk/api).

The CES partnership link currently lands on Meta's [wearables interest page](https://developers.meta.com/wearables/notify/). No application or message was submitted.

## Source code worth inspecting

- **Meta's official Web Apps repository:** concrete platform instructions and a Snake example. The README explicitly says apps are rendered on Display glasses and describes a public HTTPS URL added through the Meta AI app. README last changed **August 25, 2026**, `a2714f86`. [Pinned README](https://github.com/facebook/meta-wearables-webapp/blob/a2714f862c61b1ce9c6cb624fc7e4938087102db/README.md).
- **Community `useNeuralBand` hook:** inspected code installs normal `keydown` and `wheel` listeners and maps them to callbacks. It is useful event-adapter code, not a BLE implementation or independently verified hardware driver. File last changed **June 13, 2026**, `976d9a70`. [Pinned source](https://github.com/ShakenTheCoder/meta-rayban-display-boilerplate/blob/976d9a707ae38018d5eeafefb260a84e0609a35d/hooks/useNeuralBand.ts).
- **Meta Aria `NeuralBandBatchPlayer.cpp`:** reads VRS record layouts and decodes little-endian EMG/IMU payloads. It does not implement consumer-band authentication or BLE connection setup. The inspected file last changed **August 24, 2026**, `c55187ab`. Useful for interpreting future proven sensor payloads; no basis to assume these recording layouts equal the consumer GATT wire format. [Pinned source](https://github.com/facebookresearch/projectaria_tools/blob/c55187ab3d7918520667e5dd8957d151a9883c89/core/data_provider/players/NeuralBandBatchPlayer.cpp).
