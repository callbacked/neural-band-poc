"""Compare recorded inference scores with recognized gestures on the same connection.

Replays locally authenticated plaintext; it does not authenticate an arbitrary
JSONL file. Gesture and inference device clocks differ, so comparison windows
use host receipt times and must not be interpreted as model latency.

Native labels come from the Meta AI app's own label table (docs/gesture-models.md).
They name output indices; they are not live confirmation of what fires each channel.
"""

import argparse
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from datetime import datetime
import json
from pathlib import Path
from statistics import median

from input_service import InputService

NATIVE_LABELS = ("index_press", "index_release", "middle_press", "middle_release",
                 "thumb_tap", "thumb_up", "thumb_down", "thumb_in", "thumb_out")


def analyze(capture):
    samples, gestures = [], []
    observed = None

    def emit(event, **values):
        if event == "inference_sample":
            samples.append({"received_at": observed, **values})
        elif event == "gesture" and not values["synthetic"] and values["action"] in (
            "press", "release", "up", "down", "left", "right", "tap", "click"
        ):
            gestures.append({"received_at": observed, **values})

    reader = InputService(emit, requested_fields=(3, 4))
    with capture.open() as source:
        for line in source:
            row = json.loads(line)
            if row.get("event") == "authenticated_packet":
                observed = datetime.fromisoformat(row["timestamp"]).timestamp()
                reader.feed(bytes.fromhex(row["plaintext"]))
    reader.finish()
    if not samples:
        raise ValueError("No supported inference samples found")

    samples.sort(key=lambda row: row["received_at"])
    times = [row["received_at"] for row in samples]
    # The current capture contains one pipeline. Mixing models would obscure the mapping.
    pipelines = sorted({row["pipeline_type"] for row in samples})
    if len(pipelines) != 1:
        raise ValueError("Analyze one inference pipeline at a time")
    groups = defaultdict(list)
    comparisons = []
    for gesture in gestures:
        start = bisect_left(times, gesture["received_at"] - .25)
        end = bisect_right(times, gesture["received_at"] + .04)
        window = samples[start:end]
        if not window:
            continue
        peaks = [max(row["scores"][channel] for row in window) for channel in range(9)]
        dominant = max(range(9), key=peaks.__getitem__)
        label = f'{gesture["finger"]}_{gesture["action"]}'
        groups[label].append((dominant, peaks))
        comparisons.append({"gesture": label, "received_at": gesture["received_at"],
                            "dominant_channel": dominant, "window_peak_scores": peaks})

    associations = {}
    for label, matches in groups.items():
        counts = Counter(channel for channel, peaks in matches)
        channel, count = counts.most_common(1)[0]
        associations[label] = {"channel": channel, "native_label": NATIVE_LABELS[channel],
                               "events": len(matches), "matching_peaks": count,
                               "dominant_channel_counts": dict(sorted(counts.items())),
                               "median_peak_scores": [median(peaks[i] for ch, peaks in matches) for i in range(9)]}
    duration = (samples[-1]["timestamp_us"] - samples[0]["timestamp_us"]) / 1e6
    intervals = [b["timestamp_us"] - a["timestamp_us"] for a, b in zip(samples, samples[1:])]
    report = {
        "capture": capture.name, "pipeline_type": pipelines[0], "samples": len(samples),
        "device_duration_seconds": duration,
        "mean_samples_per_second": (len(samples) - 1) / duration if duration > 0 else None,
        "median_period_us": median(intervals) if intervals else None,
        "missing_samples": sum(row["missing_before"] for row in samples),
        "stream_enable_acknowledged": reader.streams_enabled_acknowledged,
        "stream_disable_acknowledged": reader.streams_disabled_acknowledged,
        "inference_config": reader.inference_config,
        "native_labels": list(NATIVE_LABELS),
        "association_window_seconds": [-.25, .04],
        "alignment": "host receipt time; does not establish model latency or causal independence",
        "associations": associations,
        "unassigned_channels": sorted(set(range(9)) - {v["channel"] for v in associations.values()}),
        "channel_minima": [min(row["scores"][i] for row in samples) for i in range(9)],
        "channel_maxima": [max(row["scores"][i] for row in samples) for i in range(9)],
    }
    return report, samples, comparisons


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--output", type=Path, required=True, help="new JSON analysis file")
    args = parser.parse_args()
    report, samples, comparisons = analyze(args.capture)
    with args.output.open("x") as destination:
        json.dump(report, destination, indent=2)
        destination.write("\n")
    print(json.dumps(report, indent=2))
