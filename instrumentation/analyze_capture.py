"""Reassemble and summarize initial AirShield setup from recorder JSON lines.

Only the observed plaintext setup framing is implemented. Encrypted traffic is
counted, never interpreted as a plaintext message based on a coincidental byte.
Schema provenance and limitations: ../docs/protocol.md.
"""

import argparse
import json
from collections import Counter
from pathlib import Path


def varint(data, offset):
    value = 0
    for shift in range(0, 70, 7):
        if offset >= len(data):
            raise ValueError("truncated varint")
        byte = data[offset]
        offset += 1
        if shift == 63 and byte > 1:
            raise ValueError("varint exceeds 64 bits")
        value |= (byte & 127) << shift
        if byte < 128:
            return value, offset
    raise ValueError("unterminated varint")


def protobuf_fields(data):
    fields = []
    offset = 0
    while offset < len(data):
        tag, offset = varint(data, offset)
        number, wire = tag >> 3, tag & 7
        if not 0 < number < (1 << 29):
            raise ValueError("invalid protobuf field number")
        if wire == 0:
            value, offset = varint(data, offset)
        else:
            if wire == 2:
                size, offset = varint(data, offset)
            elif wire in (1, 5):
                size = 8 if wire == 1 else 4
            else:
                raise ValueError(f"unsupported protobuf wire type {wire}")
            if offset + size > len(data):
                raise ValueError("truncated protobuf field")
            value = data[offset:offset + size]
            offset += size
        fields.append((number, wire, value))
    return fields


def setup_summary(frame):
    offset = 8 if frame[2] & 0x80 else 4
    if len(frame) < offset + 4 or frame[offset] != 2:
        raise ValueError("unrecognized setup header")
    message_type = int.from_bytes(frame[offset + 1:offset + 4], "big")
    names = {1: "RequestEncryption", 2: "EnableEncryption"}
    if message_type not in names:
        raise ValueError(f"unexpected initial setup type {message_type}")
    fields = protobuf_fields(frame[offset + 4:])
    known_wires = {1: 2, 2: 2, 3: 0, 4: 0, 5: 2, 6: 0} if message_type == 1 else {
        1: 2, 2: 2, 3: 2, 4: 0, 5: 0, 6: 0, 7: 0, 8: 0,
    }
    if any(number in known_wires and wire != known_wires[number] for number, wire, value in fields):
        raise ValueError("unexpected wire type for a known setup field")
    expected = {1: (2, 64), 2: (2, 16)} if message_type == 1 else {
        1: (2, 64), 2: (2, 32), 3: (2, 16),
    }
    for number, (wire, size) in expected.items():
        values = [value for field, actual_wire, value in fields if field == number and actual_wire == wire]
        if len(values) != 1 or len(values[0]) != size:
            raise ValueError(f"unexpected shape for field {number}")
    # Validate the point independently of the protobuf byte-length check.
    from cryptography.hazmat.primitives.asymmetric import ec
    public_key = next(value for number, wire, value in fields if number == 1 and wire == 2)
    ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + public_key)
    return {
        "message": names[message_type], "bytes": len(frame),
        "fields": [
            {"number": number, "wire": wire, **({"value": value} if wire == 0 else {"bytes": len(value)})}
            for number, wire, value in fields
        ],
    }


def analyze(path):
    errors, setup, streams = [], [], {}
    events = Counter()
    last_sequence = None
    byte_count = 0
    for line_number, line in enumerate(path.read_text().splitlines(), 1):
        if not line.startswith("{"):
            continue  # Frida CLI status text is not recorder data.
        state = None
        try:
            row = json.loads(line)
            event = row["event"]
            events[event] += 1
            if "sequence" in row:
                sequence = row["sequence"]
                if last_sequence is None and sequence != 0:
                    errors.append(f"line {line_number}: recording starts at sequence {sequence}")
                elif last_sequence is not None and sequence != last_sequence + 1:
                    errors.append(f"line {line_number}: sequence {last_sequence} -> {sequence}")
                last_sequence = sequence
            if event in ("capture_error", "hook_error", "channel_error"):
                errors.append(f"line {line_number}: {event}: {row.get('message')}")
            if event == "channel_open":
                for direction in ("tx", "rx"):
                    key = (row["peer"]["identifier"], row["channel"], direction)
                    previous = streams.get(key)
                    if previous is not None and not previous["complete"]:
                        errors.append(f"line {line_number}: previous initial exchange incomplete for {key}")
                    streams[key] = {"pending": b"", "complete": False, "failed": False, "requested": False}
            if event != "stream_bytes":
                continue
            data = bytes.fromhex(row["hex"])
            if len(data) != row["count"]:
                raise ValueError("payload/count mismatch")
            byte_count += len(data)
            key = (row["peer"]["identifier"], row["channel"], row["direction"])
            if key not in streams:
                raise ValueError("stream bytes without a recorded channel opening")
            state = streams[key]
            if state["complete"] or state["failed"]:
                continue
            state["pending"] += data
            while len(state["pending"]) >= 4:
                pending = state["pending"]
                if not pending[0] & 0x80:
                    raise ValueError("non-setup bytes before EnableEncryption; capture may start mid-channel")
                size = (int.from_bytes(pending[:2], "big") & 0x7fff) + 4
                if size < 8:
                    raise ValueError("invalid setup frame length")
                if len(pending) < size:
                    break
                summary = setup_summary(pending[:size])
                if summary["message"] == "RequestEncryption":
                    if state["requested"]:
                        raise ValueError("duplicate RequestEncryption")
                    state["requested"] = True
                elif not state["requested"]:
                    raise ValueError("EnableEncryption without RequestEncryption")
                setup.append({"sequence": row["sequence"], "timestamp": row["timestamp"],
                              "peer": row["peer"]["name"], "direction": row["direction"], **summary})
                state["pending"] = pending[size:]
                if summary["message"] == "EnableEncryption":
                    state["complete"] = True
                    state["pending"] = b""  # Remaining bytes belong to the encrypted phase.
                    break
        except (ValueError, KeyError, TypeError) as error:
            errors.append(f"line {line_number}: {error}")
            if state is not None:
                state["failed"] = True
                state["pending"] = b""
    for key, state in streams.items():
        if not state["complete"]:
            errors.append(f"incomplete initial exchange for {key}; {len(state['pending'])} buffered bytes")
    if events["recorder_ready"] != 1:
        errors.append("expected exactly one recorder_ready event")
    if not setup:
        errors.append("no initial setup messages captured")
    return {"events": dict(events), "recorded_bytes": byte_count, "setup": setup, "errors": errors}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    args = parser.parse_args()
    result = analyze(args.capture)
    print(json.dumps(result, indent=2))
    raise SystemExit(bool(result["errors"]))
