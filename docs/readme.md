# notes

setup and everyday use are in the [main readme](../readme.md). commands in these notes run from the repo root. capture filenames refer to the local, ignored `captures/` folder.

- [findings](findings.md): hardware results, verified derivations, stream captures, and known failures.
- [protocol](protocol.md): public schemas, pinned source code, and framing references.
- [gestures](gestures.md): the supplied video references and how the hand illustrates them.
- [capture tools](capture-tools.md): direct mac commands and optional phone instrumentation.
- [public integrations](public-integrations.md): a dated look at meta's glasses and research APIs.

## open work

- verify ADC channel order, electrode mapping, and voltage scaling.
- validate gesture directions and relative wrist axes with labeled trials.
- reduce dropped data and shutdown failures. combined semg/gesture framing is still unresolved; the console uses separate modes.
- investigate native handedness and haptic settings. ring/pinky recognition would need labeled semg data and a separate classifier.

the superseded clients and early text exports are in [git history](https://github.com/callbacked/neural-band-poc/tree/36b99eaf37ffd7a6116e563744457bfdd52e1af6).
