#!/usr/bin/env python3
"""
Meta Neural Band Connection PoC

Connects to the Meta Neural Band, pairs, subscribes to notifications,
and attempts to open L2CAP CoC channel.

Requirements:
    pip install bleak

Note: L2CAP CoC support in bleak is limited. This script handles
GATT operations. For full L2CAP CoC, you may need platform-specific code.
"""

import asyncio
import sys
from bleak import BleakClient, BleakScanner
from bleak.exc import BleakError

# Meta Band identifiers
BAND_NAME_PREFIX = "Meta Band"
BAND_PUBLIC_ADDRESS = "a4:0e:2b:8f:ac:cd"  # Real address from Identity Info

# Service UUIDs
META_PLATFORMS_SERVICE = "0000feb8-0000-1000-8000-00805f9b34fb"
META_PLATFORMS_TECH_SERVICE = "0000fd5f-0000-1000-8000-00805f9b34fb"

# Characteristic UUIDs
META_CHARACTERISTIC = "2d41da7c-82b6-42aa-b34e-e2e01df8cc1a"

# Handles (from capture analysis)
HANDLE_META_CHAR = 0x0028
HANDLE_META_CCCD = 0x0029
HANDLE_META_TECH = 0x002a

# L2CAP PSM for data channel
L2CAP_PSM = 0x00FF


class MetaBandClient:
    def __init__(self):
        self.client = None
        self.device = None
        self.connected = False
        self.notifications_enabled = False

    async def scan_for_band(self, timeout=10.0):
        """Scan for Meta Neural Band devices."""
        print(f"Scanning for {BAND_NAME_PREFIX} devices...")

        devices = await BleakScanner.discover(timeout=timeout, return_adv=True)

        meta_bands = []
        for device, adv_data in devices.values():
            name = device.name or adv_data.local_name or ""
            if BAND_NAME_PREFIX in name:
                meta_bands.append(device)
                print(f"  Found: {name} [{device.address}]")

        if not meta_bands:
            # List all found devices for debugging
            print("\n  All discovered devices:")
            for device, adv_data in devices.values():
                name = device.name or adv_data.local_name or "(unknown)"
                print(f"    {name} [{device.address}]")

        return meta_bands

    async def connect(self, device):
        """Connect to the Meta Band."""
        self.device = device
        print(f"\nConnecting to {device.name or device.address}...")

        self.client = BleakClient(
            device,
            timeout=30.0,
        )

        try:
            await self.client.connect()
            self.connected = True
            print(f"Connected!")
            print(f"  MTU: {self.client.mtu_size}")

            # Check if paired
            if hasattr(self.client, 'is_paired'):
                is_paired = await self.client.is_paired()
                print(f"  Paired: {is_paired}")

            return True

        except BleakError as e:
            print(f"Connection failed: {e}")
            return False

    async def pair(self):
        """Initiate pairing with the band."""
        if not self.client:
            return False

        print("\nInitiating pairing...")
        try:
            # On macOS, pairing happens automatically when accessing secured characteristics
            # On Linux, you may need to use bluetoothctl or dbus
            if hasattr(self.client, 'pair'):
                await self.client.pair()
                print("Pairing complete!")
            else:
                print("Pairing will occur on first secured access")
            return True
        except Exception as e:
            print(f"Pairing error: {e}")
            return False

    async def discover_services(self):
        """Discover and print all services and characteristics."""
        if not self.client:
            return

        print("\nDiscovering services...")

        for service in self.client.services:
            print(f"\nService: {service.uuid}")
            if service.uuid.lower() == META_PLATFORMS_SERVICE.lower():
                print("  ^ Meta Platforms, Inc. Service")
            elif service.uuid.lower() == META_PLATFORMS_TECH_SERVICE.lower():
                print("  ^ Meta Platforms Technologies Service")

            for char in service.characteristics:
                props = ", ".join(char.properties)
                print(f"  Characteristic: {char.uuid}")
                print(f"    Handle: 0x{char.handle:04x}")
                print(f"    Properties: {props}")

                for desc in char.descriptors:
                    print(f"    Descriptor: {desc.uuid} (0x{desc.handle:04x})")

    def handle_notification(self, sender, data):
        """Handle incoming notifications from the band."""
        handle = sender if isinstance(sender, int) else sender.handle
        hex_data = data.hex()
        print(f"Notification [0x{handle:04x}]: {hex_data}")

        # Interpret known values
        if len(data) == 1 and data[0] == 0x00:
            print("  -> Status: OK/Heartbeat")
        elif len(data) > 10:
            print(f"  -> Data packet ({len(data)} bytes)")

    async def enable_notifications(self):
        """Enable notifications on Meta characteristics."""
        if not self.client:
            return False

        print("\nEnabling notifications...")

        try:
            # Find the Meta characteristic
            for service in self.client.services:
                for char in service.characteristics:
                    # Check if this is our target characteristic
                    if char.uuid.lower() == META_CHARACTERISTIC.lower():
                        if "notify" in char.properties:
                            print(f"  Subscribing to {char.uuid} (0x{char.handle:04x})...")
                            await self.client.start_notify(char, self.handle_notification)
                            print("  Subscribed!")
                            self.notifications_enabled = True

                    # Also try the Meta Tech service characteristic
                    if service.uuid.lower() == META_PLATFORMS_TECH_SERVICE.lower():
                        if "notify" in char.properties:
                            print(f"  Subscribing to {char.uuid} (0x{char.handle:04x})...")
                            try:
                                await self.client.start_notify(char, self.handle_notification)
                                print("  Subscribed!")
                            except Exception as e:
                                print(f"  Failed: {e}")

            return self.notifications_enabled

        except Exception as e:
            print(f"Failed to enable notifications: {e}")
            return False

    async def read_device_info(self):
        """Read standard device information."""
        if not self.client:
            return

        print("\nReading device information...")

        # Standard BLE Device Information Service characteristics
        device_info_chars = {
            "00002a29-0000-1000-8000-00805f9b34fb": "Manufacturer",
            "00002a24-0000-1000-8000-00805f9b34fb": "Model Number",
            "00002a25-0000-1000-8000-00805f9b34fb": "Serial Number",
            "00002a27-0000-1000-8000-00805f9b34fb": "Hardware Revision",
            "00002a26-0000-1000-8000-00805f9b34fb": "Firmware Revision",
            "00002a28-0000-1000-8000-00805f9b34fb": "Software Revision",
        }

        for uuid, name in device_info_chars.items():
            try:
                value = await self.client.read_gatt_char(uuid)
                print(f"  {name}: {value.decode('utf-8', errors='ignore')}")
            except Exception:
                pass  # Characteristic not available

        # Read battery level
        try:
            battery = await self.client.read_gatt_char("00002a19-0000-1000-8000-00805f9b34fb")
            print(f"  Battery Level: {battery[0]}%")
        except Exception:
            pass

    async def send_l2cap_data(self, data: bytes):
        """
        Send data over L2CAP CoC.

        Note: bleak doesn't support L2CAP CoC directly.
        This is a placeholder for platform-specific implementation.
        """
        print(f"\nL2CAP CoC (PSM 0x{L2CAP_PSM:04x}) not directly supported in bleak")
        print("For L2CAP CoC, consider using:")
        print("  - macOS: CoreBluetooth with CBL2CAPChannel")
        print("  - Linux: BlueZ with l2cap sockets")
        print("  - Python: pybluez or direct socket programming")

    async def disconnect(self):
        """Disconnect from the band."""
        if self.client and self.connected:
            print("\nDisconnecting...")
            await self.client.disconnect()
            self.connected = False
            print("Disconnected")


async def main():
    client = MetaBandClient()

    try:
        # Scan for devices
        bands = await client.scan_for_band(timeout=10.0)

        if not bands:
            print("\nNo Meta Band devices found!")
            print("Make sure the band is:")
            print("  - Powered on")
            print("  - Not connected to another device")
            print("  - Within range")
            return

        # Connect to first found band
        device = bands[0]
        if not await client.connect(device):
            return

        # Discover services
        await client.discover_services()

        # Read device info
        await client.read_device_info()

        # Pair (if needed)
        await client.pair()

        # Enable notifications
        await client.enable_notifications()

        # Note about L2CAP
        await client.send_l2cap_data(b"")

        # Keep running to receive notifications
        print("\n" + "="*50)
        print("Listening for notifications... (Ctrl+C to stop)")
        print("="*50 + "\n")

        while True:
            await asyncio.sleep(1)

    except KeyboardInterrupt:
        print("\n\nStopping...")
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
    finally:
        await client.disconnect()


if __name__ == "__main__":
    # Check Python version
    if sys.version_info < (3, 7):
        print("Python 3.7+ required")
        sys.exit(1)

    asyncio.run(main())
