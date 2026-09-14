"""Find nearby band advertisements without connecting to other devices."""

import argparse
import asyncio
import json
from pathlib import Path

from bleak import BleakScanner
from band_access import band_connection


async def scan_bands():
    advertisements = await BleakScanner.discover(timeout=10, return_adv=True)
    bands = []
    for device, advertisement in advertisements.values():
        name = advertisement.local_name or device.name or ""
        if name.lower().startswith("meta band"):
            bands.append({"address": device.address, "name": name, "rssi": advertisement.rssi})
    return sorted(bands, key=lambda band: band['rssi'], reverse=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        with band_connection():
            result = {"devices": asyncio.run(scan_bands()), "error": None}
    except Exception as error:
        result = {"devices": [], "error": str(error)}
    args.output.write_text(json.dumps(result))
    raise SystemExit(bool(result['error']))
