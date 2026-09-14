# neural band poc

https://github.com/user-attachments/assets/4fc157bc-b579-480d-971b-bae8bdbb86fa

live sEMG readings from a meta neural band connected directly to a mac. no glasses or phone needed for the streams tested here.

there's a local console with eight channels, a 3d gesture hand, and a pinch and roll dial. you can find and connect the band from there too.

## run it

macos + python 3.11. allow bluetooth access for the terminal when asked.
unpair your neural band from the app, and run the pairing process again, for the console to pick up

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m dashboard.server
```

open [localhost:8765](http://localhost:8765). put the band in pairing mode, hit find band, choose it, then start. it remembers the band after that.

pick hand + dial for gestures, or semg for raw readings. hand sessions run for up to five minutes; semg runs for a minute. stop ends the session. captures stay local.

## what would be cool

training a model for more hand gestures and even better hand tracking (as in, you can see your fingers articulate freely)

[doing that thing meta did where you can write on a surface and it turns your gestures to text](https://www.meta.com/help/ai-glasses/866944989643926/)



## still figuring out

also i'm right handed so i have not yet explored how this would fare for left handed people

raw readings are experimental adc values. voltage scaling and electrode mapping aren't verified, and some data gets dropped. semg and gestures run separately for now since running both made things lag.

the hand shows recognized taps, holds and swipes. it isn't tracking every finger joint, and ring/pinky gestures aren't supported (same behavior when used natively with the glasses so it's probably not trained on those gestures) the dial only changes the number in the console.

[findings](docs/findings.md) · [gesture references](docs/gestures.md) · [protocol notes](docs/protocol.md) · [capture tools](docs/capture-tools.md)

shoutout astra for reviving this project lol, this definitely contains a bunch of unreadable slop though, I would advise combing through this repo with an agent.
