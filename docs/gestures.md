# User-supplied gesture references

Reviewed September 14, 2026. The user identifies these as Meta Instagram videos downloaded to this Mac. Original Instagram post URLs were not supplied. Sources remain local:

- `/Users/alex/Downloads/infographic.mp4` — 8.03 seconds, 720×960, animated six-panel guide.
- `/Users/alex/Downloads/live.mp4` — 29.48 seconds, 720×960, person demonstrating gestures alongside the glasses UI.

Local source hashes are saved in ignored `captures/gesture-video-references.json`; sampled contact sheets are also in `captures/`. The clips were reviewed through extracted frames, including a closer sample of the wrist-roll sequence around 13–19 seconds. Audio was not analyzed.

| Gesture | Labeled behavior in the reference |
| --- | --- |
| Middle-finger double tap | Wake and sleep display |
| Press and hold middle finger | Go home |
| Index-finger single tap | Select |
| Index pinch + wrist roll | Optical zoom, brightness and volume adjustment |
| Thumb–index swipe | Navigate UI |
| Index-finger double tap | Meta AI |

The live clip shows thumb movements against a curled index finger for navigation, and a held index–thumb contact combined with forearm/wrist roll during zoom. The user additionally confirms four swipe directions: up, down, left, right. The video does not establish our protobuf values, gyro axes/scaling, raw sEMG classification accuracy, or haptic tick commands. The user separately corrected their recollection of haptic ticks to uncertain.

Implementation: the console animates recognized index/middle taps and holds, and moves the thumb across the curled index for up/down/left/right swipes. Brief gestures survive browser polling; raw/derived equivalents are deduplicated for animation. The default view lays the hand palm-down. Wrist roll continues to use approximate relative gyro motion. After user feedback, the thumb stroke takes 200 ms after a short setup. The index closes over 180 ms and stays curled across quick repeated swipes, then releases gently. Horizontal thumb motion is reversed relative to the initial implementation. Incoming left/right labels are unchanged. Direction mappings still require a labeled four-direction hardware trial.

The mesh is the continuous skinned WebXR Input Profiles hand with a neutral matte material. Displayed joint poses are illustrative animations, not estimated anatomical measurements. Ring/pinky recognition remains a proposed custom raw-sEMG classifier experiment.
