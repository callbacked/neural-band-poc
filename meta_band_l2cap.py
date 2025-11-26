#!/usr/bin/env python3
"""
Meta Neural Band L2CAP CoC Connection (macOS)

Uses pyobjc to access CoreBluetooth's L2CAP channel support.
This allows opening the proprietary data channel on PSM 0x00FF.

Requirements:
    pip install pyobjc-framework-CoreBluetooth

Note: Requires macOS 11+ for L2CAP CoC support.
"""

import asyncio
import sys
import objc
from Foundation import NSObject, NSRunLoop, NSDate
from CoreBluetooth import (
    CBCentralManager,
    CBCentralManagerStatePoweredOn,
    CBUUID,
)
import CoreBluetooth

# Meta Band identifiers
BAND_NAME_PREFIX = "Meta Band"

# Service UUIDs
META_PLATFORMS_SERVICE = CBUUID.UUIDWithString_("FEB8")
META_PLATFORMS_TECH_SERVICE = CBUUID.UUIDWithString_("FD5F")

# Characteristic UUID
META_CHARACTERISTIC = CBUUID.UUIDWithString_("2d41da7c-82b6-42aa-b34e-e2e01df8cc1a")

# L2CAP PSM
L2CAP_PSM = 0x00FF


class MetaBandDelegate(NSObject):
    """Delegate handling CBCentralManager and CBPeripheral callbacks."""

    def init(self):
        self = objc.super(MetaBandDelegate, self).init()
        if self is None:
            return None

        self.central_manager = None
        self.peripheral = None
        self.l2cap_channel = None
        self.connected = False
        self.services_discovered = False
        self.characteristics = {}
        self.ready_event = asyncio.Event()
        self.connect_event = asyncio.Event()
        self.service_event = asyncio.Event()
        self.l2cap_event = asyncio.Event()
        self.received_messages = []
        self.band_init_blob = None

        return self

    # MARK: - CBCentralManagerDelegate

    def centralManagerDidUpdateState_(self, central):
        """Called when Bluetooth state changes."""
        if central.state() == CBCentralManagerStatePoweredOn:
            print("Bluetooth is powered on")
            self.ready_event.set()
        else:
            print(f"Bluetooth state: {central.state()}")

    def centralManager_didDiscoverPeripheral_advertisementData_RSSI_(
        self, central, peripheral, ad_data, rssi
    ):
        """Called when a peripheral is discovered."""
        name = peripheral.name()
        if name and BAND_NAME_PREFIX in name:
            print(f"Found: {name} [{peripheral.identifier().UUIDString()}] RSSI: {rssi}")
            self.peripheral = peripheral
            central.stopScan()
            central.connectPeripheral_options_(peripheral, None)

    def centralManager_didConnectPeripheral_(self, central, peripheral):
        """Called when connected to peripheral."""
        print(f"Connected to {peripheral.name()}")
        self.connected = True
        peripheral.setDelegate_(self)
        self.connect_event.set()

        # Discover services
        peripheral.discoverServices_(None)

    def centralManager_didFailToConnectPeripheral_error_(self, central, peripheral, error):
        """Called when connection fails."""
        print(f"Failed to connect: {error}")
        self.connect_event.set()

    def centralManager_didDisconnectPeripheral_error_(self, central, peripheral, error):
        """Called when disconnected."""
        print(f"Disconnected: {error if error else 'user initiated'}")
        self.connected = False

    # MARK: - CBPeripheralDelegate

    def peripheral_didDiscoverServices_(self, peripheral, error):
        """Called when services are discovered."""
        if error:
            print(f"Service discovery error: {error}")
            return

        print("\nDiscovered services:")
        for service in peripheral.services():
            uuid = service.UUID().UUIDString()
            print(f"  Service: {uuid}")

            # Discover characteristics for Meta services
            peripheral.discoverCharacteristics_forService_(None, service)

    def peripheral_didDiscoverCharacteristicsForService_error_(
        self, peripheral, service, error
    ):
        """Called when characteristics are discovered."""
        if error:
            print(f"Characteristic discovery error: {error}")
            return

        uuid = service.UUID().UUIDString()
        print(f"\n  Characteristics for {uuid}:")

        for char in service.characteristics():
            char_uuid = char.UUID().UUIDString()
            props = char.properties()
            print(f"    {char_uuid} (props: 0x{props:02x})")

            # Store for later use
            self.characteristics[char_uuid] = char

            # Enable notifications on Meta characteristic
            if char.UUID().isEqual_(META_CHARACTERISTIC):
                if props & 0x10:  # Notify
                    print(f"    -> Enabling notifications")
                    peripheral.setNotifyValue_forCharacteristic_(True, char)

        self.services_discovered = True
        self.service_event.set()

    def peripheral_didUpdateValueForCharacteristic_error_(
        self, peripheral, characteristic, error
    ):
        """Called when a characteristic value is updated (notification)."""
        if error:
            print(f"Read error: {error}")
            return

        value = characteristic.value()
        if value:
            data = bytes(value)
            hex_str = data.hex()
            uuid = characteristic.UUID().UUIDString()
            print(f"Notification [{uuid}]: {hex_str}")

            if len(data) == 1 and data[0] == 0x00:
                print("  -> Status: OK")

    def peripheral_didUpdateNotificationStateForCharacteristic_error_(
        self, peripheral, characteristic, error
    ):
        """Called when notification state changes."""
        if error:
            print(f"Notification state error: {error}")
            return

        uuid = characteristic.UUID().UUIDString()
        if characteristic.isNotifying():
            print(f"Notifications enabled for {uuid}")
        else:
            print(f"Notifications disabled for {uuid}")

    def peripheral_didWriteValueForCharacteristic_error_(
        self, peripheral, characteristic, error
    ):
        """Called when a write completes."""
        if error:
            print(f"Write error: {error}")
        else:
            print(f"Write successful to {characteristic.UUID().UUIDString()}")

    def peripheral_didOpenL2CAPChannel_error_(self, peripheral, channel, error):
        """Called when L2CAP channel opens."""
        if error:
            print(f"L2CAP channel error: {error}")
            self.l2cap_event.set()
            return

        print(f"\nL2CAP channel opened!")
        print(f"  PSM: 0x{channel.PSM():04x}")
        print(f"  Input stream: {channel.inputStream()}")
        print(f"  Output stream: {channel.outputStream()}")

        self.l2cap_channel = channel

        # Configure streams
        input_stream = channel.inputStream()
        output_stream = channel.outputStream()

        if input_stream:
            input_stream.setDelegate_(self)
            input_stream.scheduleInRunLoop_forMode_(
                NSRunLoop.currentRunLoop(),
                "kCFRunLoopDefaultMode"
            )
            input_stream.open()

        if output_stream:
            output_stream.setDelegate_(self)
            output_stream.scheduleInRunLoop_forMode_(
                NSRunLoop.currentRunLoop(),
                "kCFRunLoopDefaultMode"
            )
            output_stream.open()

        self.l2cap_event.set()

        # Send handshake response when channel opens
        # We need to wait for the band's init message first
        # The response will be sent after receiving the init

    def send_handshake_response(self):
        """Send protocol handshake response to the band."""
        # Replay exact iOS response from Wireshark capture (frame 562)
        # This was the first L2CAP CoC message iOS sent to the band

        captured_response = bytes.fromhex(
            "8060800181000005020000010a40"  # Header + field 1 tag + length 64
            "79b73740f70dfa3bd2fea282353f55d45c342f"
            "f41415acdcf5319c6cb44da2e6b7d010c6655222bc"
            "66fdb2ed54e9841f79f5bbcaea55ba754ff01c96"
            "3e3d235312100f47585dc36adae98a8b29f55c29"
            "1ef018002003"
        )

        print(f"\nSending captured iOS response ({len(captured_response)} bytes)")
        print(f"Payload: {captured_response.hex()}")
        return self.send_l2cap_data(captured_response)

    # MARK: - NSStreamDelegate

    def stream_handleEvent_(self, stream, event):
        """Handle stream events for L2CAP channel."""
        if event == 1:  # NSStreamEventOpenCompleted
            print(f"Stream opened: {stream}")
        elif event == 2:  # NSStreamEventHasBytesAvailable
            # Read data from L2CAP channel
            buffer = bytearray(1024)
            result = stream.read_maxLength_(buffer, len(buffer))
            # PyObjC returns a tuple (length, buffer) or just length depending on version
            if isinstance(result, tuple):
                length = result[0]
            else:
                length = result
            if length > 0:
                data = bytes(buffer[:length])
                print(f"L2CAP data received ({length} bytes): {data.hex()}")
                self.parse_protocol_message(data)
        elif event == 4:  # NSStreamEventHasSpaceAvailable
            pass  # Ready to write
        elif event == 8:  # NSStreamEventErrorOccurred
            print(f"Stream error: {stream.streamError()}")
        elif event == 16:  # NSStreamEventEndEncountered
            print("Stream ended")

    def parse_protocol_message(self, data):
        """Parse Meta Band protocol messages."""
        self.received_messages.append(data)

        if len(data) < 8:
            print("  -> Short message")
            return

        # Parse header
        marker = data[0]
        msg_type = data[1]
        print(f"  -> Header: marker=0x{marker:02x}, type=0x{msg_type:02x}")

        if marker == 0x80:
            if msg_type == 0x60:
                print("  -> Message type: Init/Handshake")
                # Extract the 64-byte blob from band's init
                if len(data) > 14 and data[12] == 0x0a and data[13] == 0x40:
                    self.band_init_blob = data[14:14+64]
                    print(f"  -> Extracted band init blob: {self.band_init_blob.hex()[:32]}...")
                # Send response to init message
                self.send_handshake_response()
            elif msg_type in (0x81, 0x82):
                print("  -> Message type: Data")
                # The band responded! Let's try to continue the protocol
                self.handle_data_message(data)

        # Check for protobuf fields
        if len(data) > 8:
            payload = data[8:]
            if len(payload) > 0 and payload[0] == 0x0a:  # Field 1
                length = payload[1] if len(payload) > 1 else 0
                print(f"  -> Protobuf field 1, length: {length}")

    def handle_data_message(self, data):
        """Handle data messages from the band after handshake."""
        # Parse the 0x81/0x82 message structure
        msg_type = data[1]

        # Only respond once to avoid loops
        if len(self.received_messages) > 3:
            print("  -> (Not responding to avoid loop)")
            return

        if msg_type == 0x82:
            # Band sent 0x82, we should send 0x81
            # Try sending the next message from the capture sequence
            next_message = bytes.fromhex(
                "80810001020000020a40"  # Header for 0x81 response
                "79b73740f70dfa3bd2fea282353f55d45c342f"
                "f41415acdcf5319c6cb44da2e6b7d010c6655222bc"
                "66fdb2ed54e9841f79f5bbcaea55ba754ff01c96"
                "3e3d235312"
                "20ed801e60b4dd740dfe9e512ea5c8655066111d44eb52854d0da233e5814c8a13"
                "1a10b20caa05b10dabdce79b88696fcf5c31"
                "20e8a1a93c2803"
            )
            print(f"\nSending 0x81 response ({len(next_message)} bytes)")
            self.send_l2cap_data(next_message)

        elif msg_type == 0x81:
            # Band sent 0x81, check if we should send something
            # This might be the final handshake step
            print("  -> Received 0x81 from band - handshake may be complete")

            # Try sending a small message from later in capture
            # This was a 26-byte message sent by iOS
            small_msg = bytes.fromhex(
                "40eb34c846c9cb9f77001e30ee62b44831a304a6370bf283c154"
            )
            print(f"\nSending small message ({len(small_msg)} bytes)")
            self.send_l2cap_data(small_msg)

    def send_l2cap_data(self, data):
        """Send data over L2CAP channel."""
        if not self.l2cap_channel:
            print("L2CAP channel not open")
            return False

        output_stream = self.l2cap_channel.outputStream()
        if not output_stream:
            print("No output stream")
            return False

        written = output_stream.write_maxLength_(data, len(data))
        print(f"Sent {written} bytes over L2CAP")
        return written == len(data)


class MetaBandConnection:
    def __init__(self):
        self.delegate = MetaBandDelegate.alloc().init()
        self.central = None

    async def start(self):
        """Initialize CoreBluetooth and wait for power on."""
        print("Initializing CoreBluetooth...")
        self.central = CBCentralManager.alloc().initWithDelegate_queue_(
            self.delegate, None
        )
        self.delegate.central_manager = self.central

        # Wait for Bluetooth to be ready
        await asyncio.wait_for(
            self.wait_for_event(self.delegate.ready_event),
            timeout=5.0
        )

    async def scan_and_connect(self, timeout=10.0):
        """Scan for and connect to Meta Band."""
        print(f"\nScanning for {BAND_NAME_PREFIX}...")

        # Start scanning
        self.central.scanForPeripheralsWithServices_options_(None, None)

        try:
            # Wait for connection
            await asyncio.wait_for(
                self.wait_for_event(self.delegate.connect_event),
                timeout=timeout
            )
        except asyncio.TimeoutError:
            self.central.stopScan()
            print("Scan timeout - no band found")
            return False

        return self.delegate.connected

    async def discover_services(self, timeout=10.0):
        """Wait for service discovery to complete."""
        try:
            await asyncio.wait_for(
                self.wait_for_event(self.delegate.service_event),
                timeout=timeout
            )
        except asyncio.TimeoutError:
            print("Service discovery timeout")
            return False

        return self.delegate.services_discovered

    async def open_l2cap_channel(self, timeout=10.0):
        """Open L2CAP CoC channel."""
        if not self.delegate.peripheral:
            print("Not connected")
            return False

        print(f"\nOpening L2CAP channel on PSM 0x{L2CAP_PSM:04x}...")
        self.delegate.peripheral.openL2CAPChannel_(L2CAP_PSM)

        try:
            await asyncio.wait_for(
                self.wait_for_event(self.delegate.l2cap_event),
                timeout=timeout
            )
        except asyncio.TimeoutError:
            print("L2CAP channel open timeout")
            return False

        return self.delegate.l2cap_channel is not None

    async def wait_for_event(self, event):
        """Wait for an asyncio event while running the run loop."""
        while not event.is_set():
            # Run the macOS run loop briefly
            NSRunLoop.currentRunLoop().runUntilDate_(
                NSDate.dateWithTimeIntervalSinceNow_(0.1)
            )
            await asyncio.sleep(0.05)
        event.clear()

    async def run_loop(self):
        """Keep running to receive callbacks."""
        while self.delegate.connected:
            NSRunLoop.currentRunLoop().runUntilDate_(
                NSDate.dateWithTimeIntervalSinceNow_(0.1)
            )
            await asyncio.sleep(0.05)

    def disconnect(self):
        """Disconnect from the band."""
        if self.delegate.peripheral and self.central:
            self.central.cancelPeripheralConnection_(self.delegate.peripheral)


async def main():
    connection = MetaBandConnection()

    try:
        # Initialize
        await connection.start()

        # Scan and connect
        if not await connection.scan_and_connect(timeout=15.0):
            print("\nFailed to connect to Meta Band")
            return

        # Wait for service discovery
        if not await connection.discover_services(timeout=10.0):
            print("\nService discovery failed")
            return

        # Open L2CAP channel
        if await connection.open_l2cap_channel(timeout=10.0):
            print("\nL2CAP channel ready for data transfer")

            # Example: Build and send a protocol message
            # This is speculative based on capture analysis
            # header = bytes([0x80, 0x60, 0x80, 0x01, 0x81, 0x00, 0x00, 0x05])
            # connection.delegate.send_l2cap_data(header + payload)
        else:
            print("\nL2CAP channel not available")
            print("The band may require the glasses to be worn")

        # Keep running
        print("\n" + "="*50)
        print("Listening for data... (Ctrl+C to stop)")
        print("="*50 + "\n")

        await connection.run_loop()

    except KeyboardInterrupt:
        print("\n\nStopping...")
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
    finally:
        connection.disconnect()


if __name__ == "__main__":
    if sys.platform != "darwin":
        print("This script requires macOS")
        sys.exit(1)

    asyncio.run(main())
