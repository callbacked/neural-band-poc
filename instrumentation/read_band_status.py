"""Read ordinary GATT status from the band; does not activate input streams."""

import argparse
import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path

from bleak import BleakClient
from bleak.exc import BleakError
from band_access import band_connection


async def read_status(identifier):
    result = {"read_at": datetime.now(timezone.utc).isoformat(), "errors": []}
    async with BleakClient(identifier, timeout=15) as client:
        for name, uuid in (
            ("battery", "00002a19-0000-1000-8000-00805f9b34fb"),
            ("firmware", "00002a26-0000-1000-8000-00805f9b34fb"),
            ("psm", "2d41da7c-82b6-42aa-b34e-e2e01df8cc1a"),
        ):
            try:
                raw = bytes(await asyncio.wait_for(client.read_gatt_char(uuid), 8))
                if name == "battery":
                    if len(raw) != 1 or raw[0] > 100:
                        raise ValueError("invalid battery percentage")
                    result[name] = raw[0]
                elif name == "psm":
                    if len(raw) != 2:
                        raise ValueError("invalid PSM length")
                    result[name] = int.from_bytes(raw, "little")
                else:
                    result[name] = raw.decode("utf-8")
            except (ValueError, TimeoutError, OSError, BleakError) as error:
                result["errors"].append(f"{name}: {error}")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("identifier")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        with band_connection():
            result = asyncio.run(read_status(args.identifier))
    except Exception as error:
        result = {"read_at": datetime.now(timezone.utc).isoformat(), "errors": [str(error)]}
    args.output.write_text(json.dumps(result, indent=2))
    print(json.dumps(result))
    raise SystemExit(bool(result["errors"]))
