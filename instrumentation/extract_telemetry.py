"""Recover checksummed telemetry files and EMG SDK events from decrypted captures.

This implements the DataX/file-transfer subset observed in the installed app.
It reads authenticated channel-zero plaintext from decrypt_capture.py; it cannot
authenticate arbitrary input JSON or decrypt the separate band/glasses relay.
"""

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import zlib

from analyze_capture import protobuf_fields


class DataXStream:
    """Incrementally reassemble the observed DataX framing over verified records."""

    def __init__(self):
        self.pending = bytearray()

    def feed(self, plain, observed):
        if not plain or len(plain) % 16:
            raise ValueError("expected block-aligned authenticated plaintext")
        # Observed AirShield padding can interrupt a DataX frame. Its complete
        # grammar remains unverified; file length, Adler-32 and zlib checks below
        # must all pass before any telemetry events are released.
        count = plain[-1] - 0xc0
        if 1 <= count <= 15 and plain[-count:] == bytes([plain[-1]]) * count:
            plain = plain[:-count]
        self.pending.extend(plain)
        while len(self.pending) >= 4:
            size = (int.from_bytes(self.pending[:2], "big") & 0x7fff) + 4
            if len(self.pending) < size:
                break
            frame = bytes(self.pending[:size])
            del self.pending[:size]
            payload, words = frame[4:], []
            # The LENGTH word flags typed headers. The channel word's high bit
            # must not consume four bytes from raw file continuations.
            if frame[0] & 0x80:
                while True:
                    if len(payload) < 4:
                        raise ValueError("truncated DataX typed header")
                    word, payload = payload[:4], payload[4:]
                    words.append(int.from_bytes(word, "big"))
                    if not word[0] & 0x80:
                        break
            yield int.from_bytes(frame[2:4], "big"), words, payload, observed

    def finish(self):
        if self.pending:
            raise ValueError(f"incomplete DataX frame: {len(self.pending)} bytes remain")


def datax_frames(packets):
    decoder = DataXStream()
    for packet in packets:
        yield from decoder.feed(bytes.fromhex(packet["plaintext"]), packet["observed_complete"])
    decoder.finish()


def checked_fields(payload):
    fields = {}
    for number, wire, value in protobuf_fields(payload):
        if (number, wire) in fields:
            raise ValueError(f"duplicate scalar protobuf field {number}")
        fields[number, wire] = value
    return fields


def verify_progress(transfer, payload):
    fields = checked_fields(payload)
    packed = transfer["data"]
    if fields.get((1, 0)) != len(packed):
        raise ValueError("file-transfer byte count mismatch")
    if fields.get((2, 0)) != zlib.adler32(packed):
        raise ValueError("file-transfer Adler-32 mismatch")


def telemetry_events(packed):
    decoder = zlib.decompressobj()
    # Telemetry is compressed input from an external device; bound expansion.
    plain = decoder.decompress(packed, 16 * 1024 * 1024 + 1)
    if len(plain) > 16 * 1024 * 1024:
        raise ValueError("telemetry exceeds 16 MiB decompression limit")
    if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        raise ValueError("incomplete or trailing zlib data")
    events, records, batches = [], 0, 0
    for number, wire, batch in protobuf_fields(plain):
        if (number, wire) != (1, 2):
            continue
        batches += 1
        for number, wire, entry in protobuf_fields(batch):
            if (number, wire) != (1, 2):
                continue
            fields = checked_fields(entry)
            records += 1
            if fields.get((2, 2)) != b"constellation_step_event":
                continue
            event = json.loads(fields[3, 2])
            if event.get("step_name") != "interaction_emg_sdk":
                continue
            metadata = event["input_metadata"]
            if metadata.get("source") != "EMG":
                continue
            timestamp = event["timestamp_ms"]
            events.append({
                "timestamp_ms": timestamp,
                "timestamp_utc": datetime.fromtimestamp(timestamp / 1000, timezone.utc).isoformat(timespec="milliseconds"),
                "action": metadata["action"], "source": metadata["source"],
                "interaction_id": event["interaction_id"],
            })
    if not batches:
        raise ValueError("telemetry batch envelope not found")
    return len(plain), records, events


def extract_telemetry(capture):
    result = {"transfers": [], "errors": [f"transport: {error}" for error in capture.get("errors", [])]}
    for direction in capture["directions"]:
        active = {}
        context = {key: direction[key] for key in ("peer", "direction", "opening_sequence")}
        label = f"{context['peer']} {context['direction']} opening {context['opening_sequence']}"
        try:
            for channel, words, payload, observed in datax_frames(direction["packets"]):
                try:
                    if words == [0x81000014, 0x02000001]:
                        if channel in active:
                            raise ValueError("new transfer before previous transfer completed")
                        fields = checked_fields(payload)
                        if fields.get((3, 2)) != b"telemetry":
                            continue
                        expected = fields[2, 0]
                        if not 0 < expected <= 4 * 1024 * 1024:
                            raise ValueError("telemetry length outside supported 1 byte–4 MiB range")
                        active[channel] = {
                            "expected": expected, "name": fields[4, 2].decode("utf-8"),
                            "announced": observed, "data": bytearray(), "receiving": False,
                        }
                        continue
                    if channel not in active:
                        continue
                    transfer = active[channel]
                    if words == [0x02000004]:
                        transfer["receiving"] = True
                    elif words == [0x02000005]:
                        verify_progress(transfer, payload)
                        transfer["receiving"] = False
                        continue
                    elif words == [0x02000006]:
                        verify_progress(transfer, payload)
                        if len(transfer["data"]) != transfer["expected"]:
                            raise ValueError("completed file differs from announced length")
                        plain_bytes, record_count, events = telemetry_events(transfer["data"])
                        result["transfers"].append({
                            **context, "datax_channel": channel, "name": transfer["name"],
                            "announced": transfer["announced"], "received_complete": observed,
                            "compressed_bytes": len(transfer["data"]), "plaintext_bytes": plain_bytes,
                            "adler32": zlib.adler32(transfer["data"]),
                            "record_count": record_count, "events": events,
                        })
                        del active[channel]
                        continue
                    elif words:
                        raise ValueError(f"unsupported message during telemetry transfer: {words}")
                    if not transfer["receiving"]:
                        raise ValueError("file continuation without a data-start message")
                    transfer["data"].extend(payload)
                    if len(transfer["data"]) > transfer["expected"]:
                        raise ValueError("file exceeds announced length")
                except (ValueError, KeyError, TypeError, zlib.error) as error:
                    result["errors"].append(f"{label} DataX {channel:#06x}: {error}")
                    active.pop(channel, None)
        except (ValueError, KeyError, TypeError) as error:
            result["errors"].append(f"{label}: {error}")
        for channel, transfer in active.items():
            result["errors"].append(
                f"{label} DataX {channel:#06x}: incomplete telemetry file "
                f"({len(transfer['data'])}/{transfer['expected']} bytes)"
            )
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decrypted", type=Path)
    parser.add_argument("--output", type=Path, help="save checked transfer metadata and EMG SDK events")
    args = parser.parse_args()
    if args.output and args.output.resolve() == args.decrypted.resolve():
        parser.error("output must not overwrite the decrypted source")
    try:
        result = extract_telemetry(json.loads(args.decrypted.read_text()))
    except (ValueError, KeyError, TypeError, OSError) as error:
        parser.exit(1, f"Unable to extract telemetry: {error}\n")
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"completed_transfers": len(result["transfers"]),
                      "sdk_actions": dict(Counter(event["action"] for transfer in result["transfers"] for event in transfer["events"])),
                      "errors": result["errors"]}, indent=2))
    raise SystemExit(bool(result["errors"]))
