"""Authenticate/decrypt a local recording made with capture_airshield_keys.js."""

import argparse
import bisect
import json
from pathlib import Path

from airshield import AuthenticatedPacket, StreamDecryptor, derive_keys
from analyze_capture import analyze, protobuf_fields


def initial_exchange(data):
    messages, consumed = {}, 0
    for expected_type in (1, 2):
        size = (int.from_bytes(data[:2], "big") & 0x7fff) + 4
        frame, data = data[:size], data[size:]
        offset = 8 if frame[2] & 0x80 else 4
        message_type = int.from_bytes(frame[offset + 1:offset + 4], "big")
        if message_type != expected_type:
            raise ValueError("unexpected initial message order")
        messages[message_type] = {number: value for number, wire, value in protobuf_fields(frame[offset + 4:])}
        consumed += size
    return messages, consumed


def decrypt_capture(path):
    integrity = analyze(path)
    if integrity["errors"]:
        raise ValueError("capture integrity/setup errors: " + "; ".join(integrity["errors"]))
    sessions, active, derivations = [], {}, {}
    for line in path.read_text().splitlines():
        if not line.startswith("{"):
            continue
        row = json.loads(line)
        event = row["event"]
        if event == "airshield_probe_error":
            raise ValueError("key observer error: " + row["message"])
        if event == "airshield_kdf_enter":
            if row["id"] in derivations:
                raise ValueError("duplicate key observer ID")
            derivations[row["id"]] = {"inputs": row}
        elif event == "airshield_derived_keys":
            derivations[row["id"]]["keys"] = row
        elif event == "airshield_shared_secret":
            derivations[row["id"]]["secret"] = row
        elif event == "channel_open":
            session = {"peer": row["peer"], "channel": row["channel"], "opening_sequence": row["sequence"],
                       "streams": {direction: {"data": bytearray(), "ends": [], "events": []} for direction in ("tx", "rx")}}
            sessions.append(session)
            active[(row["peer"]["identifier"], row["channel"])] = session
        elif event == "stream_bytes":
            stream = active[(row["peer"]["identifier"], row["channel"])]["streams"][row["direction"]]
            stream["data"].extend(bytes.fromhex(row["hex"]))
            stream["ends"].append(len(stream["data"]))
            stream["events"].append({"sequence": row["sequence"], "timestamp": row["timestamp"]})

    output = {"capture": str(path), "directions": [], "errors": []}
    for session in sessions:
        parsed = {direction: initial_exchange(bytes(stream["data"])) for direction, stream in session["streams"].items()}
        for direction, (messages, consumed) in parsed.items():
            result = {"peer": session["peer"]["name"], "channel": session["channel"],
                      "opening_sequence": session["opening_sequence"], "direction": direction,
                      "packets": [], "unauthenticated_records": []}
            output["directions"].append(result)
            try:
                opposite = "rx" if direction == "tx" else "tx"
                challenge = parsed[opposite][0][1][2]
                enable = messages[2]
                seed, iv, base, parameters = enable[2], enable[3], enable[4], enable.get(5, 0)
                matches = [sample for sample in derivations.values() if
                           sample["inputs"]["challenge"] == challenge.hex() and
                           sample["inputs"]["seed"] == seed.hex() and sample["inputs"]["iv"] == iv.hex()]
                if len(matches) != 1:
                    raise ValueError(f"expected one matching key observation, found {len(matches)}")
                sample = matches[0]
                if sample["secret"]["valid"] != 1:
                    raise ValueError("shared-secret cache was not valid")
                keys = derive_keys(bytes.fromhex(sample["secret"]["hex"]), challenge, seed, parameters)
                if (keys.encryption.hex(), keys.mac.hex()) != (sample["keys"]["encryption"], sample["keys"]["mac"]):
                    raise ValueError("derived keys do not match the app's observed keys")
                if bytes.fromhex(sample["inputs"]["parameters"])[:4] != base.to_bytes(4, "little"):
                    raise ValueError("observed MAC counter disagrees with EnableEncryption")
                result.update(parameters=parameters, observed_keys_match=True, key_observation=sample["inputs"]["id"])
                decoder = StreamDecryptor(keys, iv, base, parameters)
                stream = session["streams"][direction]
                # Feeding capture-sized pieces preserves authenticated results before any later failure.
                position = consumed
                for end in stream["ends"]:
                    if end <= position:
                        continue
                    chunk = bytes(stream["data"][position:end])
                    position = end
                    for packet in decoder.feed(chunk):
                        consumed += packet.wire_bytes
                        observed = stream["events"][bisect.bisect_left(stream["ends"], consumed)]
                        if isinstance(packet, AuthenticatedPacket):
                            result["packets"].append({"counter": packet.counter, "block_count": packet.block_count,
                                                      "wire_bytes": packet.wire_bytes, "plaintext": packet.plaintext.hex(),
                                                      "observed_complete": observed})
                        else:
                            result["unauthenticated_records"].append({"kind": packet.kind, "channel": packet.channel, "wire_bytes": packet.wire_bytes,
                                                                      "payload": packet.payload.hex(), "observed_complete": observed})
                decoder.finish()
                if not result["packets"]:
                    raise ValueError("no encrypted packets authenticated")
            except (ValueError, KeyError) as error:
                output["errors"].append(f"{result['peer']} {direction}: {error}")
    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--output", type=Path, help="save authenticated plaintext locally; omit for summary only")
    args = parser.parse_args()
    if args.output and args.output.resolve() == args.capture.resolve():
        parser.error("decoded output must not overwrite the source capture")
    try:
        result = decrypt_capture(args.capture)
    except (ValueError, KeyError) as error:
        parser.exit(1, f"Unable to decode capture: {error}\n")
    if args.output:
        args.output.write_text(json.dumps(result, indent=2))
    print(json.dumps({"directions": [
        {"peer": row["peer"], "direction": row["direction"], "parameters": row.get("parameters"),
         "authenticated_packets": len(row["packets"]),
         "unauthenticated_records": len(row["unauthenticated_records"]),
         "plaintext_bytes": sum(len(packet["plaintext"]) // 2 for packet in row["packets"])}
        for row in result["directions"]], "errors": result["errors"]}, indent=2))
    raise SystemExit(bool(result["errors"]))
