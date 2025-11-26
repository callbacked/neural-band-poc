#!/usr/bin/env python3
"""
Meta Neural Band ECDH Handshake

Generate ephemeral keys and compute shared secret with the band.
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
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESCCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import hashlib

# Meta Band identifiers
BAND_NAME_PREFIX = "Meta Band"

# Service UUIDs
META_PLATFORMS_SERVICE = CBUUID.UUIDWithString_("FEB8")
META_CHARACTERISTIC = CBUUID.UUIDWithString_("2d41da7c-82b6-42aa-b34e-e2e01df8cc1a")

# L2CAP PSM
L2CAP_PSM = 0x00FF

# IRKs from pairing capture
BAND_IRK = bytes.fromhex("e05d0d10a6cbee7f48449ff16c3c6c9b")
IOS_IRK = bytes.fromhex("1a3148b262585b8cbe9ea9bb1b7ac7ed")

# Random values from pairing
IOS_RANDOM = bytes.fromhex("7bcba138ab55140e1736b6f32d426a55")
BAND_RANDOM = bytes.fromhex("bf0bcedc2b939e6728ea8e508c709e74")

# LTK from macOS Keychain - extracted from pairing!
LTK = bytes.fromhex("87a04e3bf1fe379251ed6cd050109707")

# P-256 curve parameter
P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
P256_A = -3
P256_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b


def is_valid_p256_point(x_bytes, y_bytes):
    """Check if point is on P-256 curve."""
    x = int.from_bytes(x_bytes, 'big')
    y = int.from_bytes(y_bytes, 'big')
    left = (y * y) % P256_P
    right = (pow(x, 3, P256_P) + P256_A * x + P256_B) % P256_P
    return left == right


def bytes_to_public_key(x_bytes, y_bytes):
    """Convert raw bytes to EC public key object."""
    # Create uncompressed point format (0x04 + X + Y)
    point_bytes = b'\x04' + x_bytes + y_bytes
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point_bytes)


class MetaBandECDH(NSObject):
    """Handles ECDH key exchange with Meta Band."""

    def init(self):
        self = objc.super(MetaBandECDH, self).init()
        if self is None:
            return None

        self.central_manager = None
        self.peripheral = None
        self.l2cap_channel = None
        self.connected = False
        self.services_discovered = False

        self.ready_event = asyncio.Event()
        self.connect_event = asyncio.Event()
        self.service_event = asyncio.Event()
        self.l2cap_event = asyncio.Event()

        # ECDH state
        self.our_private_key = None
        self.our_public_key = None
        self.band_public_key = None
        self.shared_secret = None
        self.session_key = None

        # Nonce tracking
        self.our_nonce = None
        self.band_nonce = None

        # Heartbeat response flag
        self.respond_to_heartbeats = False
        self.heartbeat_counter = 0

        # Generate our ephemeral keypair
        self.generate_keypair()

        return self

    def generate_keypair(self):
        """Generate our ephemeral P-256 keypair."""
        self.our_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.our_public_key = self.our_private_key.public_key()

        # Get raw bytes
        public_numbers = self.our_public_key.public_numbers()
        x_bytes = public_numbers.x.to_bytes(32, 'big')
        y_bytes = public_numbers.y.to_bytes(32, 'big')

        print(f"Generated ephemeral keypair:")
        print(f"  Our X: {x_bytes.hex()}")
        print(f"  Our Y: {y_bytes.hex()}")

    def compute_shared_secret(self, band_x, band_y):
        """Compute ECDH shared secret with band's public key."""
        # Convert band's public key bytes to key object
        self.band_public_key = bytes_to_public_key(band_x, band_y)

        # Compute shared secret
        self.shared_secret = self.our_private_key.exchange(
            ec.ECDH(),
            self.band_public_key
        )

        print(f"\nComputed ECDH shared secret:")
        print(f"  Shared secret: {self.shared_secret.hex()}")

        # Derive session key using HKDF
        # Try various derivation patterns
        self.derive_session_keys()

        return self.shared_secret

    def derive_session_keys(self):
        """Derive encryption keys from shared secret and LTK."""
        print(f"\n  Deriving session keys with LTK: {LTK.hex()}")

        # Pattern 1: HKDF with LTK as salt (most likely pattern)
        key1 = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=LTK,
            info=b"",
            backend=default_backend()
        ).derive(self.shared_secret)
        print(f"  Key (HKDF salt=LTK): {key1.hex()}")

        # Pattern 2: HKDF with shared secret salted by LTK and "meta" info
        key2 = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=LTK,
            info=b"meta",
            backend=default_backend()
        ).derive(self.shared_secret)
        print(f"  Key (HKDF salt=LTK info='meta'): {key2.hex()}")

        # Pattern 3: SHA256 of shared secret + LTK
        key3 = hashlib.sha256(self.shared_secret + LTK).digest()
        print(f"  Key (SHA256 secret+LTK): {key3.hex()}")

        # Pattern 4: SHA256 of LTK + shared secret
        key4 = hashlib.sha256(LTK + self.shared_secret).digest()
        print(f"  Key (SHA256 LTK+secret): {key4.hex()}")

        # Pattern 5: HKDF with LTK as IKM and shared secret as salt
        key5 = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.shared_secret,
            info=b"",
            backend=default_backend()
        ).derive(LTK)
        print(f"  Key (HKDF IKM=LTK salt=secret): {key5.hex()}")

        # Store the most likely one as default (HKDF with LTK salt)
        self.session_key = key1

    def build_init_message(self):
        """Build our 0x60 init message with our public key."""
        public_numbers = self.our_public_key.public_numbers()
        our_x = public_numbers.x.to_bytes(32, 'big')
        our_y = public_numbers.y.to_bytes(32, 'big')

        header = bytes([
            0x80, 0x60, 0x80, 0x01,
            0x81, 0x00, 0x00, 0x05,
            0x02, 0x00, 0x00, 0x01
        ])

        field1 = bytes([0x0a, 0x40]) + our_x + our_y

        import os
        nonce = os.urandom(16)
        self.our_nonce = nonce
        field2 = bytes([0x12, 0x10]) + nonce

        trailer = bytes([0x18, 0x00, 0x20, 0x03])

        message = header + field1 + field2 + trailer

        print(f"\nBuilt 0x60 init ({len(message)} bytes)")
        print(f"  Our public key: {(our_x + our_y).hex()}")
        print(f"  Nonce: {nonce.hex()}")

        return message

    def build_response_message(self):
        """Build our 0x82 response message."""
        public_numbers = self.our_public_key.public_numbers()
        our_x = public_numbers.x.to_bytes(32, 'big')
        our_y = public_numbers.y.to_bytes(32, 'big')

        header = bytes([
            0x80, 0x82, 0x00, 0x01,
            0x02, 0x00, 0x00, 0x02
        ])

        field1 = bytes([0x0a, 0x40]) + our_x + our_y

        # Get band's public key bytes
        band_numbers = self.band_public_key.public_numbers()
        band_x = band_numbers.x.to_bytes(32, 'big')
        band_y = band_numbers.y.to_bytes(32, 'big')

        # Encrypt confirmation with session key
        # Plaintext is 32 bytes based on captured traffic analysis
        try:
            # Most likely plaintext: combined nonces
            # Try our_nonce + band_nonce (we confirm we received their nonce)
            if self.band_nonce and self.our_nonce:
                plaintext = self.our_nonce + self.band_nonce
                print(f"  Plaintext (our+band nonces): {plaintext.hex()}")
            else:
                # Fallback: hash of shared secret
                plaintext = hashlib.sha256(self.shared_secret).digest()
                print(f"  Plaintext (hash): {plaintext.hex()}")

            # Nonce: try zero nonce first (most common)
            nonce = b'\x00' * 12

            # Encrypt with session key (HKDF derived)
            aesgcm = AESGCM(self.session_key)
            ciphertext = aesgcm.encrypt(nonce, plaintext, None)

            # AES-GCM output: 32 bytes ciphertext + 16 bytes tag = 48 bytes
            field2 = bytes([0x12, 0x20]) + ciphertext[:32]
            field3 = bytes([0x1a, 0x10]) + ciphertext[32:48]

            print(f"  Key: {self.session_key.hex()}")
            print(f"  Nonce: {nonce.hex()}")
            print(f"  Ciphertext: {ciphertext[:32].hex()}")
            print(f"  Auth tag: {ciphertext[32:48].hex()}")

        except Exception as e:
            print(f"  Encryption error: {e}")
            import traceback
            traceback.print_exc()
            field2 = bytes([0x12, 0x20]) + b'\x00' * 32
            field3 = bytes([0x1a, 0x10]) + b'\x00' * 16

        trailer = bytes([0x20, 0xb6, 0xa2, 0xd9, 0xd5, 0x01, 0x28, 0x03])

        message = header + field1 + field2 + field3 + trailer

        print(f"Built 0x82 response ({len(message)} bytes)")

        return message

    def build_handshake_response(self):
        """Build our handshake response - returns init message."""
        return self.build_init_message()

    def handle_nested_handshake(self, data):
        """Handle a nested 0x60 handshake request (re-keying)."""
        print(f"\n*** HANDLING NESTED HANDSHAKE ***")

        # Extract band's new public key from the inner 0x60 message
        if len(data) >= 78 and data[12] == 0x0a and data[13] == 0x40:
            band_x = data[14:46]
            band_y = data[46:78]

            # Extract new nonce
            new_band_nonce = None
            if len(data) >= 96 and data[78] == 0x12 and data[79] == 0x10:
                new_band_nonce = data[80:96]
                print(f"  New band nonce: {new_band_nonce.hex()}")

            if is_valid_p256_point(band_x, band_y):
                print(f"  New band pubkey X: {band_x.hex()}")
                print(f"  New band pubkey Y: {band_y.hex()}")

                # Generate new ephemeral keypair for this channel
                new_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
                new_public_key = new_private_key.public_key()

                # Compute new shared secret
                new_band_pubkey = bytes_to_public_key(band_x, band_y)
                new_shared_secret = new_private_key.exchange(ec.ECDH(), new_band_pubkey)
                print(f"  New shared secret: {new_shared_secret.hex()}")

                # Derive new session key
                new_session_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=LTK,
                    info=b"",
                    backend=default_backend()
                ).derive(new_shared_secret)
                print(f"  New session key: {new_session_key.hex()}")

                # Build and send our response
                public_numbers = new_public_key.public_numbers()
                our_x = public_numbers.x.to_bytes(32, 'big')
                our_y = public_numbers.y.to_bytes(32, 'big')

                import os
                new_our_nonce = os.urandom(16)

                # Build 0x60 init wrapped in field 3 (0x1a)
                header = bytes([
                    0x80, 0x60, 0x80, 0x01,
                    0x81, 0x00, 0x00, 0x05,
                    0x02, 0x00, 0x00, 0x01
                ])
                field1 = bytes([0x0a, 0x40]) + our_x + our_y
                field2 = bytes([0x12, 0x10]) + new_our_nonce
                trailer = bytes([0x18, 0x00, 0x20, 0x03])
                init_msg = header + field1 + field2 + trailer

                # Wrap in field 3 (0x1a + length as single byte for <128)
                wrapped_init = bytes([0x1a, len(init_msg)]) + init_msg

                print(f"  Sending wrapped 0x60 init ({len(wrapped_init)} bytes)")
                self.send_l2cap_data(wrapped_init)

                import time
                time.sleep(0.1)

                # Build and send 0x82 response
                if new_band_nonce:
                    plaintext = new_our_nonce + new_band_nonce
                else:
                    plaintext = hashlib.sha256(new_shared_secret).digest()

                nonce = b'\x00' * 12
                aesgcm = AESGCM(new_session_key)
                ciphertext = aesgcm.encrypt(nonce, plaintext, None)

                resp_header = bytes([
                    0x80, 0x82, 0x00, 0x01,
                    0x02, 0x00, 0x00, 0x02
                ])
                resp_field1 = bytes([0x0a, 0x40]) + our_x + our_y
                resp_field2 = bytes([0x12, 0x20]) + ciphertext[:32]
                resp_field3 = bytes([0x1a, 0x10]) + ciphertext[32:48]
                resp_trailer = bytes([0x20, 0xb6, 0xa2, 0xd9, 0xd5, 0x01, 0x28, 0x03])
                resp_msg = resp_header + resp_field1 + resp_field2 + resp_field3 + resp_trailer

                # Wrap in field 3
                # For 134 bytes, need varint encoding: 134 = 0x86 0x01
                wrapped_resp = bytes([0x1a, 0x86, 0x01]) + resp_msg

                print(f"  Sending wrapped 0x82 response ({len(wrapped_resp)} bytes)")
                self.send_l2cap_data(wrapped_resp)

                # Store new keys for this channel
                self.nested_session_key = new_session_key
                print(f"  Nested handshake complete!")

            else:
                print(f"  Invalid P-256 point in nested handshake!")

    # MARK: - CBCentralManagerDelegate

    def centralManagerDidUpdateState_(self, central):
        if central.state() == CBCentralManagerStatePoweredOn:
            print("Bluetooth is powered on")
            self.ready_event.set()

    def centralManager_didDiscoverPeripheral_advertisementData_RSSI_(
        self, central, peripheral, ad_data, rssi
    ):
        name = peripheral.name()
        if name and BAND_NAME_PREFIX in name:
            print(f"Found: {name} [{peripheral.identifier().UUIDString()}] RSSI: {rssi}")
            self.peripheral = peripheral
            central.stopScan()
            central.connectPeripheral_options_(peripheral, None)

    def centralManager_didConnectPeripheral_(self, central, peripheral):
        print(f"Connected to {peripheral.name()}")
        self.connected = True
        peripheral.setDelegate_(self)
        self.connect_event.set()
        peripheral.discoverServices_(None)

    def centralManager_didFailToConnectPeripheral_error_(self, central, peripheral, error):
        print(f"Failed to connect: {error}")
        self.connect_event.set()

    def centralManager_didDisconnectPeripheral_error_(self, central, peripheral, error):
        print(f"Disconnected: {error if error else 'clean'}")
        self.connected = False

    # MARK: - CBPeripheralDelegate

    def peripheral_didDiscoverServices_(self, peripheral, error):
        if error:
            return
        for service in peripheral.services():
            peripheral.discoverCharacteristics_forService_(None, service)

    def peripheral_didDiscoverCharacteristicsForService_error_(self, peripheral, service, error):
        if error:
            return
        for char in service.characteristics():
            if char.UUID().isEqual_(META_CHARACTERISTIC):
                if char.properties() & 0x10:
                    peripheral.setNotifyValue_forCharacteristic_(True, char)
        self.services_discovered = True
        self.service_event.set()

    def peripheral_didUpdateValueForCharacteristic_error_(self, peripheral, char, error):
        if error:
            return
        value = char.value()
        if value:
            data = bytes(value)
            print(f"Notification: {data.hex()}")

    def peripheral_didUpdateNotificationStateForCharacteristic_error_(self, peripheral, char, error):
        if char.isNotifying():
            print(f"Notifications enabled for {char.UUID().UUIDString()}")

    def peripheral_didOpenL2CAPChannel_error_(self, peripheral, channel, error):
        if error:
            print(f"L2CAP error: {error}")
            self.l2cap_event.set()
            return

        print(f"\nL2CAP channel opened on PSM 0x{channel.PSM():04x}")
        self.l2cap_channel = channel

        input_stream = channel.inputStream()
        output_stream = channel.outputStream()

        if input_stream:
            input_stream.setDelegate_(self)
            input_stream.scheduleInRunLoop_forMode_(
                NSRunLoop.currentRunLoop(), "kCFRunLoopDefaultMode"
            )
            input_stream.open()

        if output_stream:
            output_stream.setDelegate_(self)
            output_stream.scheduleInRunLoop_forMode_(
                NSRunLoop.currentRunLoop(), "kCFRunLoopDefaultMode"
            )
            output_stream.open()

        self.l2cap_event.set()

    # MARK: - NSStreamDelegate

    def stream_handleEvent_(self, stream, event):
        if event == 1:  # Opened
            print(f"Stream opened")
        elif event == 2:  # Has bytes
            buffer = bytearray(1024)
            result = stream.read_maxLength_(buffer, len(buffer))
            length = result[0] if isinstance(result, tuple) else result
            if length > 0:
                data = bytes(buffer[:length])
                print(f"\nL2CAP received ({length} bytes): {data.hex()}")
                self.handle_l2cap_data(data)
        elif event == 8:  # Error
            print(f"Stream error: {stream.streamError()}")
        elif event == 16:  # End
            print("Stream ended")

    def handle_l2cap_data(self, data):
        """Handle incoming L2CAP data."""
        if len(data) < 4:
            return

        # Check if data starts with marker 0x80
        # The band sends raw messages without length prefix
        marker = data[0]
        msg_type = data[1]
        print(f"  Message type: 0x{msg_type:02x}")

        if marker == 0x80 and msg_type == 0x60:
            # Init message - extract band's public key
            if len(data) >= 78 and data[12] == 0x0a and data[13] == 0x40:
                band_x = data[14:46]
                band_y = data[46:78]

                # Extract band's nonce from field 2 (after public key)
                if len(data) >= 96 and data[78] == 0x12 and data[79] == 0x10:
                    self.band_nonce = data[80:96]
                    print(f"  Band nonce: {self.band_nonce.hex()}")

                if is_valid_p256_point(band_x, band_y):
                    print(f"  Band public key X: {band_x.hex()}")
                    print(f"  Band public key Y: {band_y.hex()}")

                    # Compute shared secret
                    self.compute_shared_secret(band_x, band_y)

                    import time
                    time.sleep(0.1)

                    # Send our 0x60 init message
                    init_msg = self.build_init_message()
                    success = self.send_l2cap_data(init_msg)

                    if success:
                        time.sleep(0.05)
                        # Send our 0x82 response message
                        response_msg = self.build_response_message()
                        self.send_l2cap_data(response_msg)
                    else:
                        print("  Failed to send init message")
                else:
                    print("  Invalid P-256 point!")

        elif marker == 0x80 and msg_type == 0x82:
            print(f"  Got 0x82 response from band!")
            # Try to decrypt with our session key
            if len(data) > 14:
                self.decrypt_band_response(data)

            # Handshake complete
            print(f"\n*** HANDSHAKE COMPLETE ***")

            import time
            time.sleep(0.3)

            # Send initial configuration (similar to frame 105 pattern)
            # This is a protobuf message requesting data streams
            print(f"Sending configuration request...")

            # Try a simple request - field 11 with minimal payload
            # Format: 5a [total_len] [payload_len] [protobuf_data]
            config_msgs = [
                # Simple status request
                "5a0006000200080118",
                # Request sensor data
                "5a0008000400080110011800",
                # Enable notifications
                "5a000800040008021001",
            ]

            for msg_hex in config_msgs:
                msg = bytes.fromhex(msg_hex)
                print(f"  Sending: {msg_hex}")
                self.send_l2cap_data(msg)
                time.sleep(0.3)

            print(f"Monitoring for band responses...")
            print(f"(Press Ctrl+C to stop)")

        elif marker == 0x1a:
            # Wrapped message (field 3)
            print(f"  Wrapped message (0x1a)")
            # Check if it contains a 0x60 init
            if len(data) > 4 and data[2] == 0x80 and data[3] == 0x60:
                print(f"  Contains nested 0x60 handshake - re-keying request")
                # Extract the inner message
                inner_data = data[2:]
                # Handle as a new ECDH handshake
                self.handle_nested_handshake(inner_data)
            else:
                print(f"  Inner data: {data[2:].hex()[:64]}...")

        elif msg_type == 0x63:
            # Post-handshake message - encrypted data channel
            print(f"  Got 0x63 message (encrypted channel)")
            # This appears to be encrypted application data
            if len(data) > 10:
                self.handle_encrypted_data(data)

        elif marker == 0x40:
            # Encrypted data message
            print(f"  Encrypted data (0x40)")
            self.decrypt_data_message(data)

        elif marker == 0x00:
            # Heartbeat/keepalive
            print(f"  Heartbeat")

        elif marker == 0x0d:
            # Band's status/heartbeat request (like frame 614)
            print(f"  Band status request (0x0d format)")
            print(f"    Data: {data.hex()}")

            if self.respond_to_heartbeats:
                # Send heartbeat response
                self.heartbeat_counter += 1
                response = bytes.fromhex("0d001a001600520052110e0c48000019583000000900035728000061d002")
                print(f"    Sending heartbeat response #{self.heartbeat_counter}")
                self.send_l2cap_data(response)

        elif marker == 0x5a:
            # Protobuf message (like frame 102)
            print(f"  Protobuf message (0x5a)")
            print(f"    Data: {data.hex()[:80]}...")

        else:
            print(f"  Unknown message: marker=0x{marker:02x} type=0x{msg_type:02x}")
            print(f"  Data: {data.hex()[:64]}...")

    def decrypt_data_message(self, data):
        """Decrypt a 0x40 encrypted data message."""
        if not self.session_key or len(data) < 17:  # 1 byte marker + 16 byte min tag
            return

        # Message format: 0x40 + ciphertext_with_tag
        ciphertext_with_tag = data[1:]

        # Try different counter nonces
        for counter in range(10):
            nonce = bytes(11) + bytes([counter])
            try:
                aesgcm = AESGCM(self.session_key)
                plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
                print(f"  Decrypted (counter={counter}): {plaintext.hex()}")

                # Parse protobuf-like content
                if plaintext:
                    self.parse_command(plaintext)
                return
            except:
                pass

        print(f"  Failed to decrypt 0x40 message")

    def parse_command(self, data):
        """Parse protobuf-like command data."""
        # Protobuf field parsing
        pos = 0
        while pos < len(data):
            if pos >= len(data):
                break
            byte = data[pos]
            field_num = byte >> 3
            wire_type = byte & 0x07

            if wire_type == 0:  # Varint
                pos += 1
                value = 0
                shift = 0
                while pos < len(data):
                    b = data[pos]
                    value |= (b & 0x7f) << shift
                    pos += 1
                    if not (b & 0x80):
                        break
                    shift += 7
                print(f"    Field {field_num}: {value}")
            elif wire_type == 2:  # Length-delimited
                pos += 1
                if pos < len(data):
                    length = data[pos]
                    pos += 1
                    value = data[pos:pos + length]
                    pos += length
                    print(f"    Field {field_num}: {value.hex()} ({length} bytes)")
            else:
                pos += 1

    def try_decrypt_message(self, data):
        """Try to decrypt a message using our derived session key."""
        if not self.session_key:
            return

        # Parse the message fields
        # After 8-byte header + 4-byte (02 00 00 02):
        # Field 1 (0a 40): 64 bytes - public key
        # Field 2 (12 20): 32 bytes - ciphertext?
        # Field 3 (1a 10): 16 bytes - auth tag?

        if len(data) < 78:
            return

        print(f"  Parsing encrypted message...")

        # Extract fields
        # 0x82 message header is: 80 82 00 01 02 00 00 02 (8 bytes)
        pos = 8  # Skip header
        field1 = None
        field2 = None
        field3 = None

        while pos < len(data):
            if pos >= len(data):
                break
            tag = data[pos]

            if tag == 0x0a and pos + 1 < len(data):
                length = data[pos + 1]
                field1 = data[pos + 2:pos + 2 + length]
                pos += 2 + length
                print(f"  Field 1 (public key): {len(field1)} bytes")
            elif tag == 0x12 and pos + 1 < len(data):
                length = data[pos + 1]
                field2 = data[pos + 2:pos + 2 + length]
                pos += 2 + length
                print(f"  Field 2 (encrypted?): {field2.hex()}")
            elif tag == 0x1a and pos + 1 < len(data):
                length = data[pos + 1]
                field3 = data[pos + 2:pos + 2 + length]
                pos += 2 + length
                print(f"  Field 3 (auth tag?): {field3.hex()}")
            elif tag in (0x18, 0x20, 0x28):
                pos += 2  # Skip varint fields
            else:
                pos += 1

        if not field1:
            print(f"  Warning: field1 not found, using band's init public key")
            # Use the band's public key we received earlier
            if self.band_public_key:
                band_numbers = self.band_public_key.public_numbers()
                field1 = band_numbers.x.to_bytes(32, 'big') + band_numbers.y.to_bytes(32, 'big')

        if field2 and field3:
            # Try AES-GCM decryption
            # Ciphertext + tag format
            ciphertext_with_tag = field2 + field3

            # Try different nonce sources
            nonces = [
                b'\x00' * 12,  # Zero nonce
                field3[:12],  # First 12 bytes of field3
                self.shared_secret[:12],  # From shared secret
            ]

            # Add band's nonce if we captured it
            if self.band_nonce:
                nonces.extend([
                    self.band_nonce[:12],  # Band's nonce truncated
                    self.band_nonce,  # Full 16 bytes (if algo supports it)
                ])

            # Add our nonce if we sent one
            if self.our_nonce:
                nonces.extend([
                    self.our_nonce[:12],
                    self.our_nonce,
                ])

            # Try counter-based nonces
            nonces.extend([
                bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),  # Counter = 1
                bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]),  # Counter = 2
            ])

            # Get our public key bytes for key derivation
            public_numbers = self.our_public_key.public_numbers()
            our_x = public_numbers.x.to_bytes(32, 'big')
            our_y = public_numbers.y.to_bytes(32, 'big')

            # Try different key derivations - LTK-based keys first (most likely)
            keys = [
                # LTK-based derivations (highest priority)
                self.session_key,  # HKDF(shared_secret, salt=LTK) - set in derive_session_keys
                HKDF(algorithm=hashes.SHA256(), length=32, salt=LTK, info=b"", backend=default_backend()).derive(self.shared_secret),
                HKDF(algorithm=hashes.SHA256(), length=32, salt=LTK, info=b"meta", backend=default_backend()).derive(self.shared_secret),
                HKDF(algorithm=hashes.SHA256(), length=32, salt=self.shared_secret, info=b"", backend=default_backend()).derive(LTK),
                hashlib.sha256(self.shared_secret + LTK).digest(),
                hashlib.sha256(LTK + self.shared_secret).digest(),
                # LTK with public keys
                hashlib.sha256(self.shared_secret + LTK + field1).digest(),
                hashlib.sha256(self.shared_secret + LTK + our_x + our_y).digest(),
                HKDF(algorithm=hashes.SHA256(), length=32, salt=LTK, info=field1, backend=default_backend()).derive(self.shared_secret),
                HKDF(algorithm=hashes.SHA256(), length=32, salt=LTK, info=our_x + our_y, backend=default_backend()).derive(self.shared_secret),
                # LTK extended to 32 bytes
                LTK + LTK,
                hashlib.sha256(LTK).digest(),
                # LTK combined with IRK
                hashlib.sha256(LTK + BAND_IRK).digest(),
                hashlib.sha256(LTK + IOS_IRK).digest(),
                HKDF(algorithm=hashes.SHA256(), length=32, salt=BAND_IRK, info=b"", backend=default_backend()).derive(LTK),
                # Both public keys in the derivation (sorted order common in protocols)
                HKDF(algorithm=hashes.SHA256(), length=32, salt=LTK, info=field1 + our_x + our_y, backend=default_backend()).derive(self.shared_secret),
                HKDF(algorithm=hashes.SHA256(), length=32, salt=LTK, info=our_x + our_y + field1, backend=default_backend()).derive(self.shared_secret),
                hashlib.sha256(self.shared_secret + field1 + our_x + our_y + LTK).digest(),
                # Nonce in derivation
                HKDF(algorithm=hashes.SHA256(), length=32, salt=LTK, info=self.band_nonce if self.band_nonce else b"", backend=default_backend()).derive(self.shared_secret) if self.band_nonce else hashlib.sha256(self.shared_secret).digest(),
                # Simple patterns without LTK (fallback)
                hashlib.sha256(self.shared_secret).digest(),
                HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"", backend=default_backend()).derive(self.shared_secret),
                HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"meta", backend=default_backend()).derive(self.shared_secret),
                # Using public keys as salt
                HKDF(algorithm=hashes.SHA256(), length=32, salt=field1, info=b"", backend=default_backend()).derive(self.shared_secret),
                HKDF(algorithm=hashes.SHA256(), length=32, salt=our_x + our_y, info=b"", backend=default_backend()).derive(self.shared_secret),
                # Combined public keys
                hashlib.sha256(self.shared_secret + field1).digest(),
                hashlib.sha256(self.shared_secret + our_x + our_y).digest(),
                # Raw shared secret
                self.shared_secret[:32] if len(self.shared_secret) >= 32 else self.shared_secret.ljust(32, b'\x00'),
                # IRK-based keys
                BAND_IRK + BAND_IRK,
                IOS_IRK + IOS_IRK,
                hashlib.sha256(BAND_IRK + IOS_IRK).digest(),
                hashlib.sha256(self.shared_secret + BAND_IRK).digest(),
                HKDF(algorithm=hashes.SHA256(), length=32, salt=BAND_IRK, info=b"", backend=default_backend()).derive(self.shared_secret),
            ]

            # Maybe field2 is 16 bytes ciphertext + 16 bytes in field3 is tag
            # Or maybe field2[:16] is nonce and field2[16:] is ciphertext
            print(f"  Also trying field2 as nonce+ciphertext...")
            alt_nonce = field2[:12]
            alt_ciphertext = field2[12:] + field3

            for key in keys:
                try:
                    aesgcm = AESGCM(key)
                    plaintext = aesgcm.decrypt(alt_nonce, alt_ciphertext, None)
                    print(f"\n  *** ALT DECRYPTED: {plaintext.hex()} ***")
                    return plaintext
                except:
                    pass

            # Try field2 split as 16-byte ciphertext + 16-byte tag (ignore field3)
            print(f"  Trying field2 as 16-byte ciphertext + 16-byte tag...")
            ct_16 = field2[:16] + field2[16:]  # This is same as field2, but try with all nonces
            for key in keys[:15]:
                for nonce in nonces:
                    try:
                        aesgcm = AESGCM(key)
                        plaintext = aesgcm.decrypt(nonce, ct_16, None)
                        print(f"\n  *** 16+16 DECRYPTED: {plaintext.hex()} ***")
                        return plaintext
                    except:
                        pass

            # Try with field3 as the nonce
            print(f"  Trying field3 as nonce...")
            f3_nonce = field3[:12]
            for key in keys[:15]:
                try:
                    aesgcm = AESGCM(key)
                    # field2 is 32 bytes - try as 16 CT + 16 tag
                    plaintext = aesgcm.decrypt(f3_nonce, field2, None)
                    print(f"\n  *** F3-NONCE DECRYPTED: {plaintext.hex()} ***")
                    return plaintext
                except:
                    pass

            # Also try more nonce patterns
            nonces.extend([
                hashlib.sha256(field1).digest()[:12],  # Hash of public key
                hashlib.sha256(our_x + our_y).digest()[:12],  # Hash of our public key
                field2[:12],  # First 12 bytes of ciphertext
                (our_x + field1[:32])[:12],  # Combined X coords
            ])

            for key in keys:
                for nonce in nonces:
                    try:
                        aesgcm = AESGCM(key)
                        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
                        print(f"\n  *** DECRYPTED: {plaintext.hex()} ***")
                        try:
                            print(f"  *** ASCII: {plaintext.decode('utf-8', errors='ignore')} ***")
                        except:
                            pass
                        return plaintext
                    except Exception:
                        pass

            print(f"  Decryption failed with all key/nonce combinations")

            # Maybe it's not encrypted - could be a signature or HMAC
            print(f"\n  Trying HMAC verification...")

            # Common HMAC patterns
            for key in keys:
                # HMAC-SHA256, truncated to 32 bytes
                import hmac as hmac_module
                for msg in [field1, self.shared_secret, field1 + self.shared_secret, our_x + our_y]:
                    h = hmac_module.new(key, msg, hashlib.sha256).digest()
                    if h == field2:
                        print(f"  *** HMAC MATCH! Message was: {msg.hex()[:32]}... ***")
                        return
                    if h[:16] == field3:
                        print(f"  *** HMAC TAG MATCH (truncated)! ***")

            # Try AES-CCM (different tag sizes)
            print(f"\n  Trying AES-CCM...")
            for key in keys[:10]:  # Try top 10 keys
                for nonce in nonces[:5]:  # Try top 5 nonces
                    if len(nonce) > 13:
                        nonce = nonce[:13]
                    elif len(nonce) < 7:
                        nonce = nonce.ljust(13, b'\x00')
                    try:
                        # 16-byte tag
                        aesccm = AESCCM(key, tag_length=16)
                        plaintext = aesccm.decrypt(nonce, ciphertext_with_tag, None)
                        print(f"\n  *** AES-CCM DECRYPTED: {plaintext.hex()} ***")
                        return plaintext
                    except:
                        pass

            # Try ChaCha20-Poly1305
            print(f"\n  Trying ChaCha20-Poly1305...")
            for key in keys[:15]:
                for nonce in nonces:
                    if len(nonce) != 12:
                        nonce = nonce[:12] if len(nonce) > 12 else nonce.ljust(12, b'\x00')
                    try:
                        chacha = ChaCha20Poly1305(key)
                        plaintext = chacha.decrypt(nonce, ciphertext_with_tag, None)
                        print(f"\n  *** CHACHA DECRYPTED: {plaintext.hex()} ***")
                        return plaintext
                    except:
                        pass

            # Try Noise Protocol pattern - key = HKDF(sha256(shared_secret), info="")
            print(f"\n  Trying Noise Protocol patterns...")
            # Noise uses: ck, k = HKDF(ck, input_key_material)
            # Initial chaining key often starts with protocol name hash
            noise_patterns = [
                b"Noise_XX_25519_AESGCM_SHA256",
                b"Noise_KK_25519_AESGCM_SHA256",
                b"Noise_IK_25519_AESGCM_SHA256",
                b"Noise_NK_25519_AESGCM_SHA256",
                b"MetaBand",
                b"meta",
            ]

            for pattern in noise_patterns:
                # Noise uses SHA256 hash of pattern name as initial state
                h = hashlib.sha256(pattern).digest()
                # Then mixes in public keys and DH results
                ck = h  # Chaining key

                # Mix in our public key
                temp = HKDF(algorithm=hashes.SHA256(), length=64, salt=ck, info=b"", backend=default_backend()).derive(our_x + our_y)
                ck, k1 = temp[:32], temp[32:]

                # Mix in their public key
                temp = HKDF(algorithm=hashes.SHA256(), length=64, salt=ck, info=b"", backend=default_backend()).derive(field1)
                ck, k2 = temp[:32], temp[32:]

                # Mix in DH result
                temp = HKDF(algorithm=hashes.SHA256(), length=64, salt=ck, info=b"", backend=default_backend()).derive(self.shared_secret)
                ck, k3 = temp[:32], temp[32:]

                # Also try with LTK mixed in
                temp_ltk = HKDF(algorithm=hashes.SHA256(), length=64, salt=ck, info=b"", backend=default_backend()).derive(LTK)
                ck_ltk, k4 = temp_ltk[:32], temp_ltk[32:]

                for key in [k1, k2, k3, k4, ck, ck_ltk]:
                    for nonce in [b'\x00' * 12, bytes([0]*11 + [1])]:
                        try:
                            aesgcm = AESGCM(key)
                            plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
                            print(f"\n  *** NOISE DECRYPTED with {pattern}: {plaintext.hex()} ***")
                            return plaintext
                        except:
                            pass

            # Try with nonces XOR'd together
            if self.band_nonce and self.our_nonce:
                xor_nonce = bytes(a ^ b for a, b in zip(self.band_nonce, self.our_nonce))[:12]
                print(f"\n  Trying XOR'd nonce: {xor_nonce.hex()}")
                for key in keys[:10]:
                    try:
                        aesgcm = AESGCM(key)
                        plaintext = aesgcm.decrypt(xor_nonce, ciphertext_with_tag, None)
                        print(f"\n  *** XOR NONCE DECRYPTED: {plaintext.hex()} ***")
                        return plaintext
                    except:
                        pass

            # Check if field2 might be ECDSA signature (r || s format)
            print(f"\n  Checking if field2 is ECDSA signature...")
            if len(field2) == 32:
                sig_candidate = field2 + field3
                print(f"  Potential signature (48 bytes): {sig_candidate.hex()}")

            # Try verifying as truncated ECDSA signature
            # The band might sign: shared_secret || our_pubkey || band_pubkey
            from cryptography.hazmat.primitives.asymmetric import ec as ec_module
            from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

            # Possible messages the band might have signed
            messages_to_verify = [
                self.shared_secret,
                self.shared_secret + our_x + our_y,
                self.shared_secret + field1,
                our_x + our_y + field1,
                field1 + our_x + our_y,
                self.shared_secret + LTK,
                hashlib.sha256(self.shared_secret).digest(),
                hashlib.sha256(self.shared_secret + our_x + our_y).digest(),
            ]

            # If the band nonce exists, include it in messages
            if self.band_nonce:
                messages_to_verify.extend([
                    self.shared_secret + self.band_nonce,
                    self.band_nonce + self.shared_secret,
                    hashlib.sha256(self.shared_secret + self.band_nonce).digest(),
                ])

            if self.our_nonce:
                messages_to_verify.extend([
                    self.shared_secret + self.our_nonce,
                    self.band_nonce + self.our_nonce if self.band_nonce else self.our_nonce,
                ])

            print(f"\n  Data that might be signed:")
            print(f"    Shared secret: {self.shared_secret.hex()}")
            print(f"    Band pubkey:   {field1.hex()[:32]}...")
            print(f"    Our pubkey:    {(our_x+our_y).hex()[:32]}...")
            if self.band_nonce:
                print(f"    Band nonce:    {self.band_nonce.hex()}")
            if self.our_nonce:
                print(f"    Our nonce:     {self.our_nonce.hex()}")

    def decrypt_band_response(self, data):
        """Decrypt the band's 0x82 response."""
        if not self.session_key:
            return

        # Parse fields from 0x82 message
        # Header: 80 82 00 01 02 00 00 02 (8 bytes)
        pos = 8
        field2 = None
        field3 = None

        while pos < len(data):
            tag = data[pos]
            if tag == 0x0a and pos + 1 < len(data):
                length = data[pos + 1]
                pos += 2 + length  # Skip public key
            elif tag == 0x12 and pos + 1 < len(data):
                length = data[pos + 1]
                field2 = data[pos + 2:pos + 2 + length]
                pos += 2 + length
            elif tag == 0x1a and pos + 1 < len(data):
                length = data[pos + 1]
                field3 = data[pos + 2:pos + 2 + length]
                pos += 2 + length
            elif tag in (0x18, 0x20, 0x28):
                pos += 2
            else:
                pos += 1

        if field2 and field3:
            # Try to decrypt: ciphertext + tag
            ciphertext_with_tag = field2 + field3
            nonce = b'\x00' * 12

            try:
                aesgcm = AESGCM(self.session_key)
                plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
                print(f"\n  *** BAND 0x82 DECRYPTED ***")
                print(f"  Plaintext: {plaintext.hex()}")

                # Should be our_nonce + band_nonce (reversed order)
                if plaintext == self.our_nonce + self.band_nonce:
                    print(f"  *** HANDSHAKE VERIFIED! ***")
                    print(f"  Band confirmed: our_nonce + band_nonce")
                elif plaintext == self.band_nonce + self.our_nonce:
                    print(f"  *** HANDSHAKE VERIFIED (same order) ***")
                else:
                    print(f"  Expected: {(self.our_nonce + self.band_nonce).hex()}")

            except Exception as e:
                print(f"  Decryption failed with zero nonce: {e}")

                # Get public key bytes
                public_numbers = self.our_public_key.public_numbers()
                our_x = public_numbers.x.to_bytes(32, 'big')
                our_y = public_numbers.y.to_bytes(32, 'big')
                our_pubkey = our_x + our_y

                band_numbers = self.band_public_key.public_numbers()
                band_x = band_numbers.x.to_bytes(32, 'big')
                band_y = band_numbers.y.to_bytes(32, 'big')
                band_pubkey = band_x + band_y

                # Try different key derivations
                keys_to_try = [
                    ("HKDF salt=LTK", self.session_key),
                    ("SHA256(secret+LTK)", hashlib.sha256(self.shared_secret + LTK).digest()),
                    ("SHA256(LTK+secret)", hashlib.sha256(LTK + self.shared_secret).digest()),
                    # Include nonces in key derivation
                    ("HKDF salt=LTK info=nonces", HKDF(algorithm=hashes.SHA256(), length=32, salt=LTK, info=self.band_nonce + self.our_nonce, backend=default_backend()).derive(self.shared_secret)),
                    ("HKDF salt=LTK info=our_nonce", HKDF(algorithm=hashes.SHA256(), length=32, salt=LTK, info=self.our_nonce, backend=default_backend()).derive(self.shared_secret)),
                    ("HKDF salt=LTK info=band_nonce", HKDF(algorithm=hashes.SHA256(), length=32, salt=LTK, info=self.band_nonce, backend=default_backend()).derive(self.shared_secret)),
                    # Include public keys
                    ("HKDF info=pubkeys", HKDF(algorithm=hashes.SHA256(), length=32, salt=LTK, info=band_pubkey + our_pubkey, backend=default_backend()).derive(self.shared_secret)),
                    # SHA256 combinations
                    ("SHA256(secret+nonces)", hashlib.sha256(self.shared_secret + self.band_nonce + self.our_nonce).digest()),
                    ("SHA256(nonces+secret)", hashlib.sha256(self.band_nonce + self.our_nonce + self.shared_secret).digest()),
                    # XOR-based
                    ("SHA256(secret XOR LTK)", hashlib.sha256(bytes(a ^ b for a, b in zip(self.shared_secret, LTK + LTK))).digest()),
                    # Just shared secret
                    ("shared_secret", self.shared_secret),
                    # HKDF no salt
                    ("HKDF no salt", HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"", backend=default_backend()).derive(self.shared_secret)),
                ]

                # Try different nonces
                nonces_to_try = [
                    ("zero", b'\x00' * 12),
                    ("counter=1", bytes(11) + b'\x01'),
                    ("counter=2", bytes(11) + b'\x02'),
                    ("band_nonce[:12]", self.band_nonce[:12]),
                    ("our_nonce[:12]", self.our_nonce[:12]),
                    # Little-endian counters
                    ("LE counter=1", b'\x01' + bytes(11)),
                    ("LE counter=2", b'\x02' + bytes(11)),
                    # Combined nonce patterns
                    ("XOR nonces", bytes(a ^ b for a, b in zip(self.band_nonce[:12], self.our_nonce[:12]))),
                ]

                for key_name, key in keys_to_try:
                    for nonce_name, test_nonce in nonces_to_try:
                        try:
                            test_aesgcm = AESGCM(key)
                            plaintext = test_aesgcm.decrypt(test_nonce, ciphertext_with_tag, None)
                            print(f"\n  *** DECRYPTED with {key_name} + {nonce_name} ***")
                            print(f"  Plaintext: {plaintext.hex()}")

                            # Check what the plaintext is
                            if plaintext == self.our_nonce + self.band_nonce:
                                print(f"  Content: our_nonce + band_nonce")
                            elif plaintext == self.band_nonce + self.our_nonce:
                                print(f"  Content: band_nonce + our_nonce")
                            return
                        except:
                            pass

                print(f"  All decryption attempts failed")
                print(f"  Ciphertext: {field2.hex()}")
                print(f"  Tag: {field3.hex()}")

                # Debug: print what we expect the plaintext to be
                print(f"\n  Expected plaintexts:")
                print(f"    our_nonce + band_nonce: {(self.our_nonce + self.band_nonce).hex()}")
                print(f"    band_nonce + our_nonce: {(self.band_nonce + self.our_nonce).hex()}")
                print(f"    SHA256(shared_secret): {hashlib.sha256(self.shared_secret).digest().hex()}")

    def send_subscription_request(self):
        """Send requests to enable gesture/EMG data streaming."""
        import time

        if not self.session_key:
            print("No session key - cannot send encrypted commands")
            return

        print("\n" + "="*50)
        print("Attempting to enable gesture mode...")
        print("="*50)

        aesgcm = AESGCM(self.session_key)
        counter = 1

        # Try various protobuf-style commands to enable gestures
        # Based on common patterns in wearable protocols

        commands = [
            # Basic subscription commands
            (b'\x08\x01', "Subscribe type 1"),
            (b'\x08\x02', "Subscribe type 2"),
            (b'\x08\x03', "Subscribe type 3"),

            # Enable sensor streams (protobuf field 1 = enum)
            (b'\x08\x01\x10\x01', "Enable stream 1"),
            (b'\x08\x02\x10\x01', "Enable stream 2"),
            (b'\x08\x03\x10\x01', "Enable stream 3"),

            # Gesture mode enable
            (b'\x08\x01\x10\x01\x18\x01', "Gesture mode on"),

            # EMG sensor enable
            (b'\x08\x04\x10\x01', "EMG stream on"),
            (b'\x08\x05\x10\x01', "EMG raw data"),

            # Device status request
            (b'\x08\x00', "Status request"),

            # Glasses pairing simulation
            # Field 1=1 might mean "glasses connected"
            (b'\x08\x01\x12\x00', "Glasses connected signal"),
            (b'\x08\x01\x12\x04\x08\x01\x10\x01', "Glasses active + gestures"),

            # Subscription with data types
            (b'\x0a\x02\x08\x01', "Data subscription A"),
            (b'\x0a\x02\x08\x02', "Data subscription B"),
            (b'\x0a\x04\x08\x01\x10\x01', "Data subscription C"),

            # Mode switches
            (b'\x10\x01', "Mode 1"),
            (b'\x10\x02', "Mode 2"),
            (b'\x10\x03', "Mode 3"),

            # Feature enable (common pattern)
            (b'\x08\x64\x10\x01', "Feature 100 on"),
            (b'\x08\x65\x10\x01', "Feature 101 on"),
        ]

        for plaintext, desc in commands:
            nonce = bytes(11) + bytes([counter])
            try:
                ciphertext = aesgcm.encrypt(nonce, plaintext, None)
                message = bytes([0x40]) + ciphertext

                print(f"\n[{counter}] {desc}")
                print(f"    Plaintext: {plaintext.hex()}")
                print(f"    Sending: {message.hex()[:40]}...")

                self.send_l2cap_data(message)
                counter += 1
                time.sleep(0.2)

            except Exception as e:
                print(f"    Error: {e}")

        print("\n" + "="*50)
        print("Sent all test commands. Monitoring for responses...")
        print("If you see gesture data, note which command triggered it.")
        print("="*50 + "\n")

        # Try sending raw protobuf messages (unencrypted like 5a format)
        time.sleep(0.3)
        print("Trying unencrypted protobuf commands...")

        raw_commands = [
            # Sensor subscription variants
            ("5a0006000200089c0118", "Sensor enable"),
            ("5a0008000400089c011001", "Sensor stream on"),
            ("5a000a00060008011001180100", "Full enable"),
            # IMU/gesture specific
            ("5a0008000400089c021001", "IMU enable"),
            ("5a0008000400089c031001", "Gesture enable"),
            ("5a0008000400089c041001", "EMG enable"),
        ]

        for hex_data, desc in raw_commands:
            msg = bytes.fromhex(hex_data)
            print(f"  {desc}: {hex_data}")
            self.send_l2cap_data(msg)
            time.sleep(0.15)

    def handle_encrypted_data(self, data):
        """Handle post-handshake encrypted data (0x63 messages)."""
        print(f"  Encrypted data ({len(data)} bytes): {data.hex()[:64]}...")

        # The 0x63 message structure needs analysis
        # It appears to have similar structure to 0x60 but encrypted payload
        # First byte after marker might indicate data type

        if len(data) > 2:
            # Check if there's a sub-type after 0x63
            sub_type = data[2] if len(data) > 2 else 0
            print(f"  Sub-type: 0x{sub_type:02x}")

            # Extract any visible structure
            if len(data) > 12 and data[2] == 0x80 and data[3] == 0x60:
                # This looks like a wrapped 0x60 message
                print(f"  Contains wrapped 0x60 init message")
                # Extract the inner message
                inner = data[2:]
                print(f"  Inner: {inner.hex()[:64]}...")

    def send_l2cap_data(self, data):
        """Send data over L2CAP."""
        if not self.l2cap_channel:
            print("  No L2CAP channel!")
            return False
        output_stream = self.l2cap_channel.outputStream()
        if not output_stream:
            print("  No output stream!")
            return False

        # Check if stream has space
        if not output_stream.hasSpaceAvailable():
            print("  Stream not ready, waiting...")
            import time
            time.sleep(0.1)

        written = output_stream.write_maxLength_(data, len(data))
        print(f"Sent {written} bytes")
        return written > 0


class MetaBandConnection:
    def __init__(self):
        self.delegate = MetaBandECDH.alloc().init()
        self.central = None

    async def start(self):
        print("Initializing CoreBluetooth...")
        self.central = CBCentralManager.alloc().initWithDelegate_queue_(
            self.delegate, None
        )
        self.delegate.central_manager = self.central
        await asyncio.wait_for(self.wait_for_event(self.delegate.ready_event), timeout=5.0)

    async def scan_and_connect(self, timeout=10.0):
        print(f"\nScanning for {BAND_NAME_PREFIX}...")
        self.central.scanForPeripheralsWithServices_options_(None, None)
        try:
            await asyncio.wait_for(
                self.wait_for_event(self.delegate.connect_event),
                timeout=timeout
            )
        except asyncio.TimeoutError:
            self.central.stopScan()
            return False
        return self.delegate.connected

    async def discover_services(self, timeout=10.0):
        try:
            await asyncio.wait_for(
                self.wait_for_event(self.delegate.service_event),
                timeout=timeout
            )
        except asyncio.TimeoutError:
            return False
        return self.delegate.services_discovered

    async def open_l2cap_channel(self, timeout=10.0):
        if not self.delegate.peripheral:
            return False
        print(f"\nOpening L2CAP channel on PSM 0x{L2CAP_PSM:04x}...")
        self.delegate.peripheral.openL2CAPChannel_(L2CAP_PSM)
        try:
            await asyncio.wait_for(
                self.wait_for_event(self.delegate.l2cap_event),
                timeout=timeout
            )
        except asyncio.TimeoutError:
            return False
        return self.delegate.l2cap_channel is not None

    async def wait_for_event(self, event):
        while not event.is_set():
            NSRunLoop.currentRunLoop().runUntilDate_(
                NSDate.dateWithTimeIntervalSinceNow_(0.1)
            )
            await asyncio.sleep(0.05)
        event.clear()

    async def run_loop(self):
        while self.delegate.connected:
            NSRunLoop.currentRunLoop().runUntilDate_(
                NSDate.dateWithTimeIntervalSinceNow_(0.1)
            )
            await asyncio.sleep(0.05)

    def disconnect(self):
        if self.delegate.peripheral and self.central:
            self.central.cancelPeripheralConnection_(self.delegate.peripheral)


async def main():
    connection = MetaBandConnection()

    try:
        await connection.start()

        if not await connection.scan_and_connect(timeout=15.0):
            print("\nFailed to connect")
            return

        await connection.discover_services(timeout=10.0)

        if await connection.open_l2cap_channel(timeout=10.0):
            print("\n" + "="*50)
            print("ECDH handshake in progress...")
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
        print("Requires macOS")
        sys.exit(1)
    asyncio.run(main())
