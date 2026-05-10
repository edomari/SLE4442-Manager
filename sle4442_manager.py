#!/usr/bin/env python3
"""
sle4442_manager.py
SLE4442 Manager (GUI + CLI)
Supports: read memory, write memory, read protection memory, read security memory,
unlock with PSC (3-byte PIN), change PIN, hexdump/base64 views, import/export .hex files.

Author: Lorenzo Di Fuccia
Requirements: pyscard, PyQt5 (optional for GUI)
"""

import sys
import argparse
import base64
import hashlib
from datetime import datetime

# pyscard
from smartcard.scard import *

# GUI (optional)
try:
    from PyQt5 import QtWidgets, QtGui, QtCore
    HAS_QT = True
except Exception:
    HAS_QT = False



# ACS APDUs
SELECT = [0xFF, 0xA4, 0x00, 0x00, 0x01, 0x06]
READ_APDU = [0xFF, 0xB0, 0x00]                   # + addr + length
UNLOCK_APDU = [0xFF, 0x20, 0x00, 0x00, 0x03]     # + 3 bytes PSC
WRITE_APDU = [0xFF, 0xD0, 0x00]                  # + addr + length + data

READ_PROT_APDU = [0xFF, 0xB2, 0x00, 0x00, 0x04]  # read protection 32 bits
READ_SEC_APDU = [0xFF, 0xB2, 0x01, 0x00, 0x04]   # read security memory
WRITE_SEC_APDU = [0xFF, 0xD2, 0x01, 0x00, 0x03]  # + 3 bytes new PSC

# OMNIKEY APDUs
# https://www.hidglobal.com/sites/default/files/documentlibrary/plt-03099_a.5_-_omnikey_sw_dev_guide_0.pdf
OMNIKEY_WRITE_APDU = [0xFF, 0xD6, 0x00]          # + addr + length + data
OMNIKEY_CHANGE_PIN_APDU = [0xFF, 0x21, 0x00, 0x00, 0x06] # + 3 bytes old PSC + 3 bytes new PSC
OMNIKEY_READ_PROT_APDU = [0xFF, 0xB0, 0x01, 0x00, 0x04]  # READ BINARY at 0x0100
OMNIKEY_READ_SEC_APDU  = [0xFF, 0xB0, 0x01, 0x04, 0x04]  # READ BINARY at 0x0104


# Card constants
MAIN_MEM_SIZE = 256            # main EEPROM bytes
PROT_BITS = 32                 # first 32 bytes have protection bits
PSC_LENGTH = 3                 # 3-byte programmable security code
DEFAULT_WRITE_CHUNK_SIZE = 16  # default chunk size for write operations (bytes)


# Custom exceptions
class INSNotSupportedError(RuntimeError):
    """Raised when reader returns 6D 00 - Instruction Not Supported"""
    pass


class CommandNotAllowedError(RuntimeError):
    """Raised when reader returns 69 86 - Command not allowed / Security condition not satisfied (raised by reader)"""
    pass


class SecurityNotSatisfiedError(RuntimeError):
    """Raised when reader returns 69 82 - Security condition not satisfied (raised by card)"""
    pass


class WrongPINError(RuntimeError):
    """Raised when reader returns 63 Cx - Wrong PIN with retries remaining"""
    pass


# Utility helpers
def hexdump(data: bytes, width=16):
    """Create hex dump with ASCII representation"""
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hexa = ' '.join(f"{b:02X}" for b in chunk)
        ascii_part = ''.join((chr(b) if 32 <= b < 127 else '.') for b in chunk)
        lines.append(f"{i:04X}  {hexa:<{width*3}}  {ascii_part}")
    return '\n'.join(lines)


def format_apdu(apdu):
    """Format APDU as hex string"""
    return ' '.join(f"{b:02X}" for b in apdu)


# Card interface class
class SLE4442Interface:
    def __init__(self, log_callback=None, write_chunk_size=DEFAULT_WRITE_CHUNK_SIZE):
        """Initialize SLE4442 interface

        Args:
            log_callback: Optional callback function for logging
            write_chunk_size: Size of chunks for write operations (default: 16 bytes)
                             Some readers may support larger values for better performance
        """
        self.hcontext = None
        self.hcard = None
        self.protocol = None
        self.reader = None
        self.log_callback = log_callback
        self.log_apdus = False
        self.is_omnikey = False  # Track if reader is OMNIKEY
        self.write_chunk_size = write_chunk_size  # Configurable write chunk size

    def establish(self):
        """Establish PC/SC context"""
        hresult, hcontext = SCardEstablishContext(SCARD_SCOPE_USER)
        if hresult != SCARD_S_SUCCESS:
            raise RuntimeError("Failed to establish context: " + SCardGetErrorMessage(hresult))
        self.hcontext = hcontext

    def list_readers(self):
        """List available smart card readers"""
        if self.hcontext is None:
            self.establish()
        hresult, readers = SCardListReaders(self.hcontext, [])
        if hresult != SCARD_S_SUCCESS:
            raise RuntimeError("Failed to list readers: " + SCardGetErrorMessage(hresult))
        return readers

    def connect(self, reader_name):
        """Connect to a specific reader"""
        hresult, hcard, dwActiveProtocol = SCardConnect(
            self.hcontext, reader_name, SCARD_SHARE_SHARED,
            SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1
        )
        if hresult != SCARD_S_SUCCESS:
            raise RuntimeError("Unable to connect: " + SCardGetErrorMessage(hresult))

        self.hcard = hcard
        self.protocol = dwActiveProtocol
        self.reader = reader_name

        # Detect reader type
        self.is_omnikey = self._detect_omnikey_reader(reader_name)
        if self.log_callback:
            reader_type = "OMNIKEY" if self.is_omnikey else "Standard"
            self.log_callback(f"Detected reader type: {reader_type}")

        # Select wrapper for SLE
        hresult, resp = SCardTransmit(self.hcard, self.protocol, SELECT)
        if hresult != SCARD_S_SUCCESS:
            raise RuntimeError("SELECT failed: " + SCardGetErrorMessage(hresult))
        return resp

    def _detect_omnikey_reader(self, reader_name):
        """Detect if reader is an OMNIKEY device"""
        reader_name_lower = reader_name.lower()
        omnikey_identifiers = [
            'omnikey',
            'hid global',
            'hid omnikey',
        ]
        return any(identifier in reader_name_lower for identifier in omnikey_identifiers)

    def disconnect(self, release_context=True):
        """Disconnect from reader and optionally release context

        Args:
            release_context: If True, release the PC/SC context (default: True)
                           Set to False to keep context for reconnecting to another reader
        """
        if self.hcard:
            hresult = SCardDisconnect(self.hcard, SCARD_UNPOWER_CARD)
            if hresult != SCARD_S_SUCCESS:
                raise RuntimeError("Failed to disconnect: " + SCardGetErrorMessage(hresult))
            self.hcard = None
        if release_context and self.hcontext:
            hresult = SCardReleaseContext(self.hcontext)
            if hresult != SCARD_S_SUCCESS:
                raise RuntimeError("Failed to release context: " + SCardGetErrorMessage(hresult))
            self.hcontext = None
        self.is_omnikey = False

    def transmit(self, apdu):
        """Transmit APDU and handle response"""
        if not self.hcard:
            raise RuntimeError("Not connected")

        # Log sent APDU
        if self.log_apdus and self.log_callback:
            self.log_callback(f">> APDU: {format_apdu(apdu)}")

        hresult, resp = SCardTransmit(self.hcard, self.protocol, apdu)
        if hresult != SCARD_S_SUCCESS:
            raise RuntimeError("Transmit failed: " + SCardGetErrorMessage(hresult))

        # Log received response
        if self.log_apdus and self.log_callback:
            self.log_callback(f"<< RESP: {format_apdu(resp)} ({len(resp)} bytes)")

        # Check for INS not supported error (6D 00)
        if len(resp) >= 2 and resp[-2] == 0x6D and resp[-1] == 0x00:
            raise INSNotSupportedError(
                f"INS Not Supported (6D 00)\n"
                f"APDU: {format_apdu(apdu)}\n\n"
                f"This reader does not support this command.\n"
                f"Try using 'Tools → Send Raw APDU' for reader-specific commands."
            )

        # Check for command not allowed (69 86) - reader level
        elif len(resp) >= 2 and resp[-2] == 0x69 and resp[-1] == 0x86:
            raise CommandNotAllowedError(
                f"Command Not Allowed (69 86)\n"
                f"APDU: {format_apdu(apdu)}\n\n"
                f"The reader/card rejected this command due to security restrictions.\n\n"
                f"Possible reasons:\n"
                f"• Card needs to be unlocked with correct PSC (PIN)\n"
                f"• Operation requires authentication\n"
                f"• Card is permanently blocked (error counter = 0)\n"
                f"• Write-protected memory area\n\n"
                f"Try:\n"
                f"1. Check security memory to see error counter\n"
                f"2. Unlock card with correct PSC\n"
                f"3. Check protection bits for write operations"
            )

        # Check for security not satisfied (69 82) - card level
        elif len(resp) >= 2 and resp[-2] == 0x69 and resp[-1] == 0x82:
            raise SecurityNotSatisfiedError(
                f"Security Condition Not Satisfied (69 82)\n"
                f"APDU: {format_apdu(apdu)}\n\n"
                f"The card security requirements are not met.\n\n"
                f"Possible reasons:\n"
                f"• Card needs to be unlocked with correct PSC (PIN)\n"
                f"• Authentication required before this operation\n"
                f"• Security conditions not satisfied\n\n"
                f"Try:\n"
                f"1. Unlock card with correct PSC\n"
                f"2. Check security memory status"
            )

        # Check for wrong PIN (63 Cx) - wrong PIN with retries remaining
        elif len(resp) >= 2 and resp[-2] == 0x63 and resp[-1] & 0xF0 == 0xC0:
            retries = resp[-1] & 0x0F
            raise WrongPINError(
                f"Wrong PIN (63 C{retries:X})\n"
                f"APDU: {format_apdu(apdu)}\n\n"
                f"Incorrect PSC (PIN) provided.\n\n"
                f"Remaining attempts: {retries}\n"
                f"{'⚠️ WARNING: Card will be permanently blocked at 0 attempts!' if retries <= 2 else ''}\n\n"
                f"Try:\n"
                f"1. Verify you have the correct PSC\n"
                f"2. Check security memory to see error counter\n"
                f"3. Be careful - limited attempts remaining!"
            )

        return resp

    def _check_response(self, resp, operation="Operation"):
        """Check response status words"""
        if len(resp) < 2:
            raise RuntimeError(f"{operation} failed: Short response")

        sw1, sw2 = resp[-2], resp[-1]
        if sw1 != 0x90:
            raise RuntimeError(f"{operation} failed: SW1={sw1:02X}, SW2={sw2:02X}")

        return bytes(resp[:-2])

    # High-level operations
    def read(self, addr=0, length=MAIN_MEM_SIZE):
        """Read data from card memory"""
        if length <= 0:
            return b''

        apdu = READ_APDU + [addr, length]
        resp = self.transmit(apdu)
        return self._check_response(resp, "Read")

    def write(self, addr, data):
        """Write data to card memory (with reader-specific APDU support)"""
        if not isinstance(data, (bytes, bytearray)):
            raise ValueError("Data must be bytes or bytearray")

        if addr < 0 or addr >= MAIN_MEM_SIZE:
            raise ValueError(f"Invalid address: {addr}")

        if addr + len(data) > MAIN_MEM_SIZE:
            raise ValueError(f"Write would exceed memory size")

        # Choose APDU based on reader type
        if self.is_omnikey:
            if self.log_callback:
                self.log_callback("Using OMNIKEY write command (FF D6)")
            write_apdu_base = OMNIKEY_WRITE_APDU
        else:
            if self.log_callback:
                self.log_callback("Using standard write command (FF D0)")
            write_apdu_base = WRITE_APDU

        # Write in chunks (configurable size, default 16 bytes)
        # SLE4442 supports byte-by-byte writes, but chunking improves performance
        # Some readers may support larger chunks (32, 64, or even 256 bytes)
        bytes_written = 0

        for i in range(0, len(data), self.write_chunk_size):
            chunk = data[i:i+self.write_chunk_size]
            current_addr = addr + i

            apdu = write_apdu_base + [current_addr, len(chunk)] + list(chunk)
            resp = self.transmit(apdu)
            self._check_response(resp, f"Write at address {current_addr:02X}")

            bytes_written += len(chunk)

        if self.log_callback:
            self.log_callback(f"Wrote {bytes_written} bytes in {(len(data) + self.write_chunk_size - 1) // self.write_chunk_size} chunks")

        return bytes_written

    def read_protection_bits(self):
        """Read protection bits (32 bits)

        Returns 4 bytes representing protection status of first 32 bytes of memory.

        Bit mapping (LSB-first):
            - Byte 0, bit 0 (LSB) = protection for address 0x00
            - Byte 0, bit 1       = protection for address 0x01
            - ...
            - Byte 0, bit 7       = protection for address 0x07
            - Byte 1, bit 0       = protection for address 0x08
            - ...
            - Byte 3, bit 7       = protection for address 0x1F (31)

        Protection bit values:
            - 1 = byte is writable (not protected)
            - 0 = byte is write-protected (cannot be written)

        Note: Protection bits themselves can be written to protect memory,
              but once set to 0 (protected), they cannot be changed back to 1.
        """
        apdu = OMNIKEY_READ_PROT_APDU if self.is_omnikey else READ_PROT_APDU
        resp = self.transmit(apdu)
        return self._check_response(resp, "Read protection")

    def read_security(self):
        """Read security memory (4 bytes)

        Returns 4 bytes:
            - Byte 0: Error counter (7 = unlocked, 0 = permanently blocked)
            - Bytes 1-3: PSC (Programmable Security Code / PIN)

        Error counter values:
            - 7: Card is unlocked (correct PSC provided)
            - 6-1: Number of remaining unlock attempts
            - 0: Card permanently blocked (no more attempts)

        Note: Some readers (notably OMNIKEY) may not support this command.
              In that case, an INSNotSupportedError will be raised.
        """
        apdu = OMNIKEY_READ_SEC_APDU if self.is_omnikey else READ_SEC_APDU
        resp = self.transmit(apdu)
        return self._check_response(resp, "Read security")

    def is_byte_protected(self, address):
        """Check if a specific byte is write-protected

        Args:
            address: Memory address (0-31) to check

        Returns:
            True if byte is write-protected (bit = 0)
            False if byte is writable (bit = 1)

        Raises:
            ValueError: If address is outside protected range (0-31)
        """
        if address < 0 or address >= PROT_BITS:
            raise ValueError(f"Address {address} is outside protected range (0-{PROT_BITS-1})")

        prot = self.read_protection_bits()

        # Calculate byte and bit position
        byte_index = address // 8
        bit_position = address % 8

        # Extract bit (LSB-first)
        bit_value = (prot[byte_index] >> bit_position) & 1

        # Return True if protected (bit = 0), False if writable (bit = 1)
        return bit_value == 0

    def unlock_with_pin_bytes(self, pin_bytes: bytes):
        """Unlock card with 3-byte PSC

        Returns:
            "unlocked" - PSC correct, card unlocked (error counter = 7)
            "wrong" - PSC incorrect, error counter decremented
            "blocked" - Card permanently blocked (error counter = 0)

        Note: On some readers (OMNIKEY), reading security memory may not be supported.
              In that case, the method relies solely on APDU response codes.
        """
        if len(pin_bytes) != PSC_LENGTH:
            raise ValueError(f"PSC must be exactly {PSC_LENGTH} bytes")

        apdu = UNLOCK_APDU + list(pin_bytes)
        resp = self.transmit(apdu)
        
        if len(resp) < 2:
            raise RuntimeError("Invalid unlock response")

        # Check for standard success response
        if resp[-2] == 0x90 and resp[-1] == 0x00:
            # Try to verify by reading security memory (may not work on all readers)
            try:
                sec = self.read_security()
                error_counter = sec[0]
                if error_counter == 7:
                    return "unlocked"
                elif error_counter == 0:
                    return "blocked"
                else:
                    # Shouldn't happen - 90 00 but counter not 7
                    return "wrong"
            except INSNotSupportedError:
                # Reader doesn't support read security (e.g., OMNIKEY)
                # Trust the 90 00 response
                if self.log_callback:
                    self.log_callback("Note: Reader doesn't support reading security memory, trusting APDU response")
                return "unlocked"

        # Check for wrong PIN with retries remaining (63 Cx)
        elif resp[-2] == 0x63 and resp[-1] & 0xF0 == 0xC0:
            retries = resp[-1] & 0x0F
            if retries == 0:
                return "blocked"
            else:
                return "wrong"

        # For any other response, try to read security memory to get actual state
        else:
            try:
                sec = self.read_security()
                error_counter = sec[0]
                if error_counter == 7:
                    return "unlocked"
                elif error_counter == 0:
                    return "blocked"
                else:
                    return "wrong"
            except INSNotSupportedError:
                # Can't determine state, assume wrong PIN
                return "wrong"

    def change_pin(self, new_pin_bytes: bytes, old_pin_bytes: bytes = None):
        """Change PSC to new 3-byte value

        Args:
            new_pin_bytes: New 3-byte PSC
            old_pin_bytes: Old 3-byte PSC (required for OMNIKEY readers)

        For OMNIKEY readers:
            - Requires old PIN, card doesn't need to be unlocked first
            - Uses FF 21 command with authentication

        For standard readers:
            - Card MUST be unlocked with current PSC first
            - Uses FF D2 command to write security memory
        """
        if len(new_pin_bytes) != PSC_LENGTH:
            raise ValueError(f"New PSC must be exactly {PSC_LENGTH} bytes")

        # Use OMNIKEY-specific change PIN command if available and old PIN provided
        if self.is_omnikey and old_pin_bytes is not None:
            if len(old_pin_bytes) != PSC_LENGTH:
                raise ValueError(f"Old PSC must be exactly {PSC_LENGTH} bytes")

            if self.log_callback:
                self.log_callback("Using OMNIKEY change PIN command (FF 21)")

            # OMNIKEY APDU: FF 21 00 00 06 [old PSC 3 bytes] [new PSC 3 bytes]
            # This command authenticates with old PSC, no unlock required
            apdu = OMNIKEY_CHANGE_PIN_APDU + list(old_pin_bytes) + list(new_pin_bytes)
            resp = self.transmit(apdu)
            self._check_response(resp, "Change PIN (OMNIKEY)")

            # Note: Cannot verify by reading security memory on OMNIKEY
            # The command either succeeds (90 00) or fails with error
            if self.log_callback:
                self.log_callback("Note: OMNIKEY readers don't support reading security memory for verification")

        else:
            # Standard change PIN command (requires card to be already unlocked)
            if self.log_callback:
                self.log_callback("Using standard change PIN command (FF D2)")

            # Verify card is unlocked before attempting PIN change
            # (only possible on readers that support read_security)
            try:
                sec = self.read_security()
                error_counter = sec[0]
                if error_counter != 7:
                    raise SecurityNotSatisfiedError(
                        f"Card must be unlocked before changing PIN.\n"
                        f"Current error counter: {error_counter} (should be 7)\n\n"
                        f"Please unlock the card with the current PSC first."
                    )
            except INSNotSupportedError:
                # Reader doesn't support read_security
                # Proceed anyway and let the write command fail if not unlocked
                if self.log_callback:
                    self.log_callback("Warning: Cannot verify unlock state - reader doesn't support read_security")

            apdu = WRITE_SEC_APDU + list(new_pin_bytes)
            resp = self.transmit(apdu)
            self._check_response(resp, "Change PIN")

        return True

    def get_reader_info(self):
        """Get reader information"""
        return {
            'name': self.reader,
            'type': 'OMNIKEY' if self.is_omnikey else 'Standard',
            'is_omnikey': self.is_omnikey,
            'write_apdu': format_apdu(OMNIKEY_WRITE_APDU) if self.is_omnikey else format_apdu(WRITE_APDU)
        }


# CLI Implementation
class CLIManager:
    """Command-line interface manager for SLE4442"""

    def __init__(self, verbose=False):
        self.verbose = verbose
        self.intf = SLE4442Interface(log_callback=self.log if verbose else None)

    def log(self, message):
        """Print log message if verbose mode enabled"""
        if self.verbose:
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"[{timestamp}] {message}", file=sys.stderr)

    def connect_to_reader(self, reader_index=0):
        """Connect to a reader by index (default: first reader)"""
        self.intf.establish()
        readers = self.intf.list_readers()

        if not readers:
            raise RuntimeError("No smart card readers found")

        if reader_index >= len(readers):
            raise RuntimeError(f"Reader index {reader_index} out of range (0-{len(readers)-1})")

        reader = readers[reader_index]
        self.log(f"Available readers: {', '.join(readers)}")
        self.log(f"Connecting to: {reader}")

        self.intf.connect(reader)
        return reader

    def cmd_list_readers(self):
        """List all available readers"""
        self.intf.establish()
        readers = self.intf.list_readers()

        if not readers:
            print("No readers found")
            return 1

        print(f"Found {len(readers)} reader(s):")
        for i, reader in enumerate(readers):
            print(f"  [{i}] {reader}")
        return 0

    def cmd_info(self, args):
        """Show card information"""
        self.connect_to_reader(args.reader)

        sec = self.intf.read_security()
        prot = self.intf.read_protection_bits()
        reader_info = self.intf.get_reader_info()

        print("=== Card Information ===")
        print(f"Card Type: SLE4442")
        print(f"Main Memory: {MAIN_MEM_SIZE} bytes")
        print(f"Protection Bits: {PROT_BITS} bits")
        print()
        print(f"Security Memory: {sec.hex().upper()}")
        print(f"  Error Counter: 0x{sec[0]:02X} ({sec[0]} attempts left)")
        print(f"  PSC Bytes: {sec[1:].hex().upper()}")
        print()
        print(f"Protection Bits: {prot.hex().upper()}")
        print()
        print(f"Reader: {reader_info['name']}")
        print(f"Reader Type: {reader_info['type']}")

        self.intf.disconnect()
        return 0

    def cmd_read(self, args):
        """Read card memory"""
        self.connect_to_reader(args.reader)

        data = self.intf.read(0, MAIN_MEM_SIZE)

        if args.format == 'hex':
            print(data.hex().upper())
        elif args.format == 'base64':
            print(base64.b64encode(data).decode())
        else:  # hexdump
            print(hexdump(data))

        self.intf.disconnect()
        return 0

    def cmd_write(self, args):
        """Write data to card"""
        # Read input data
        if args.input == '-':
            # Read from stdin
            import sys
            hex_data = sys.stdin.read().strip()
        else:
            # Read from file
            with open(args.input, 'r') as f:
                hex_data = f.read().strip()

        # Clean hex data
        hex_data = hex_data.replace(' ', '').replace('\n', '').replace('\r', '')

        # Validate
        if len(hex_data) != MAIN_MEM_SIZE * 2:
            raise ValueError(
                f"Data must be exactly {MAIN_MEM_SIZE*2} hex characters "
                f"({MAIN_MEM_SIZE} bytes), got {len(hex_data)}"
            )

        data = bytes.fromhex(hex_data)

        # Connect and write
        self.connect_to_reader(args.reader)

        if not args.force:
            print(f"WARNING: About to write {len(data)} bytes to card")
            print(f"SHA-256: {hashlib.sha256(data).hexdigest()}")
            response = input("Continue? [y/N]: ")
            if response.lower() != 'y':
                print("Aborted")
                self.intf.disconnect()
                return 1

        self.log("Writing data to card...")
        bytes_written = self.intf.write(0, data)

        # Verify
        self.log("Verifying written data...")
        verify_data = self.intf.read(0, MAIN_MEM_SIZE)

        if verify_data == data:
            print(f"SUCCESS: {bytes_written} bytes written and verified")
            self.intf.disconnect()
            return 0
        else:
            diff_count = sum(1 for i in range(len(data)) if verify_data[i] != data[i])
            print(f"ERROR: Verification failed - {diff_count} bytes differ")
            self.intf.disconnect()
            return 1

    def cmd_export(self, args):
        """Export card data to file"""
        self.connect_to_reader(args.reader)

        data = self.intf.read(0, MAIN_MEM_SIZE)

        output_file = args.output
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"sle4442_dump_{timestamp}.hex"

        with open(output_file, 'w') as f:
            f.write(data.hex().upper())

        print(f"Exported {len(data)} bytes to: {output_file}")
        print(f"SHA-256: {hashlib.sha256(data).hexdigest()}")

        self.intf.disconnect()
        return 0

    def cmd_unlock(self, args):
        """Unlock card with PSC"""
        pin_hex = args.psc.strip().replace(' ', '').upper()

        if len(pin_hex) != 6:
            raise ValueError("PSC must be 6 hex characters (3 bytes)")

        pin_bytes = bytes.fromhex(pin_hex)

        self.connect_to_reader(args.reader)

        result = self.intf.unlock_with_pin_bytes(pin_bytes)

        print(f"Unlock result: {result}")

        self.intf.disconnect()
        return 0 if result == "unlocked" else 1

    def cmd_change_pin(self, args):
        """Change card PSC"""
        new_pin_hex = args.new_psc.strip().replace(' ', '').upper()

        if len(new_pin_hex) != 6:
            raise ValueError("New PSC must be 6 hex characters (3 bytes)")

        new_pin_bytes = bytes.fromhex(new_pin_hex)

        old_pin_bytes = None
        if args.old_psc:
            old_pin_hex = args.old_psc.strip().replace(' ', '').upper()
            if len(old_pin_hex) != 6:
                raise ValueError("Old PSC must be 6 hex characters (3 bytes)")
            old_pin_bytes = bytes.fromhex(old_pin_hex)

        self.connect_to_reader(args.reader)

        if not args.force:
            print("WARNING: This will permanently change the card PSC!")
            response = input("Continue? [y/N]: ")
            if response.lower() != 'y':
                print("Aborted")
                self.intf.disconnect()
                return 1

        # Change PIN
        self.intf.change_pin(new_pin_bytes, old_pin_bytes)

        # Verify
        sec = self.intf.read_security()
        if sec[1:] == new_pin_bytes:
            print("SUCCESS: PSC changed successfully")
            print(f"New PSC: {sec[1:].hex().upper()}")
            self.intf.disconnect()
            return 0
        else:
            print("ERROR: PSC verification failed")
            self.intf.disconnect()
            return 1


def run_cli_with_args(args):
    """Run CLI based on parsed arguments"""
    try:
        cli = CLIManager(verbose=args.verbose)

        if args.command == 'list':
            return cli.cmd_list_readers()
        elif args.command == 'info':
            return cli.cmd_info(args)
        elif args.command == 'read':
            return cli.cmd_read(args)
        elif args.command == 'write':
            return cli.cmd_write(args)
        elif args.command == 'export':
            return cli.cmd_export(args)
        elif args.command == 'unlock':
            return cli.cmd_unlock(args)
        elif args.command == 'change-pin':
            return cli.cmd_change_pin(args)
        else:
            print(f"Unknown command: {args.command}", file=sys.stderr)
            return 1

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def build_cli_parser():
    """Build argument parser for CLI"""
    parser = argparse.ArgumentParser(
        description="SLE4442 Smart Card Manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List readers
  %(prog)s list

  # Show card info
  %(prog)s info

  # Read card (hexdump)
  %(prog)s read

  # Read card (raw hex)
  %(prog)s read --format hex

  # Export to file
  %(prog)s export -o backup.hex

  # Unlock card
  %(prog)s unlock FFFFFF

  # Write from file (requires unlock first)
  %(prog)s write data.hex

  # Change PIN (OMNIKEY readers)
  %(prog)s change-pin --old FFFFFF --new 123456

  # Change PIN (standard readers, must unlock first)
  %(prog)s change-pin --new 123456
"""
    )

    parser.add_argument('--nogui', action='store_true',
                       help='Force CLI mode (no GUI)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose logging')
    parser.add_argument('-r', '--reader', type=int, default=0,
                       help='Reader index (default: 0)')

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # list command
    subparsers.add_parser('list', help='List available readers')

    # info command
    subparsers.add_parser('info', help='Show card information')

    # read command
    read_parser = subparsers.add_parser('read', help='Read card memory')
    read_parser.add_argument('-f', '--format',
                            choices=['hexdump', 'hex', 'base64'],
                            default='hexdump',
                            help='Output format (default: hexdump)')

    # write command
    write_parser = subparsers.add_parser('write', help='Write data to card')
    write_parser.add_argument('input', help='Input file (use - for stdin)')
    write_parser.add_argument('--force', action='store_true',
                            help='Skip confirmation prompt')

    # export command
    export_parser = subparsers.add_parser('export', help='Export card data to file')
    export_parser.add_argument('-o', '--output', help='Output file (default: auto-generated)')

    # unlock command
    unlock_parser = subparsers.add_parser('unlock', help='Unlock card with PSC')
    unlock_parser.add_argument('psc', help='3-byte PSC in hex (e.g., FFFFFF)')

    # change-pin command
    change_pin_parser = subparsers.add_parser('change-pin', help='Change card PSC')
    change_pin_parser.add_argument('--old', dest='old_psc',
                                   help='Old PSC (required for OMNIKEY readers)')
    change_pin_parser.add_argument('--new', dest='new_psc', required=True,
                                   help='New PSC (6 hex characters)')
    change_pin_parser.add_argument('--force', action='store_true',
                                  help='Skip confirmation prompt')

    return parser


# PyQt GUI
if __name__ == "__main__":
    parser = build_cli_parser()
    args = parser.parse_args()

    # If a command is specified, run CLI mode
    if args.command:
        sys.exit(run_cli_with_args(args))

    # Otherwise, try to launch GUI
    if args.nogui or not HAS_QT:
        if not HAS_QT and not args.nogui:
            print("PyQt5 not available. Use CLI commands or install PyQt5 for GUI.")
            print("\nTry: python sle4442_manager.py --help")
        else:
            print("Use CLI commands. Try: python sle4442_manager.py --help")
        sys.exit(0)

    # GUI application
    class MainWindow(QtWidgets.QMainWindow):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("SLE4442 Manager")
            self.resize(1000, 700)

            self.intf = SLE4442Interface(log_callback=self.log)
            self.intf.establish()
            self.current_reader = None
            self.loaded_data = None  # Store imported data

            # Create menu bar
            self.create_menus()

            # Layout
            w = QtWidgets.QWidget()
            self.setCentralWidget(w)
            v = QtWidgets.QVBoxLayout(w)

            # Top controls
            top = QtWidgets.QHBoxLayout()

            self.read_btn = QtWidgets.QPushButton("Read All")
            self.unlock_btn = QtWidgets.QPushButton("Unlock (PSC)")
            self.export_btn = QtWidgets.QPushButton("Export to .hex")

            self.import_btn = QtWidgets.QPushButton("Import .hex")
            self.write_btn = QtWidgets.QPushButton("Write to Card")
            self.write_btn.setEnabled(False)

            # Style buttons
            self.write_btn.setStyleSheet(
                "QPushButton:enabled { background-color: #ff9800; color: white; font-weight: bold; }"
            )

            top.addWidget(self.read_btn)
            top.addWidget(self.unlock_btn)
            top.addWidget(self.export_btn)
            separator = QtWidgets.QLabel(" | ")
            top.addWidget(separator)
            top.addWidget(self.import_btn)
            top.addWidget(self.write_btn)
            top.addStretch()
            v.addLayout(top)

            # Main memory view
            mem_label = QtWidgets.QLabel("Main Memory (256 bytes):")
            v.addWidget(mem_label)
            self.hex_view = QtWidgets.QPlainTextEdit()
            self.hex_view.setFont(QtGui.QFont("Courier", 10))
            self.hex_view.setReadOnly(True)
            v.addWidget(self.hex_view, 2)

            # Log view
            log_label = QtWidgets.QLabel("Log:")
            v.addWidget(log_label)
            self.log_view = QtWidgets.QPlainTextEdit()
            self.log_view.setFont(QtGui.QFont("Courier", 9))
            self.log_view.setReadOnly(True)
            self.log_view.setMaximumHeight(150)
            v.addWidget(self.log_view, 1)

            # Bottom status
            bottom = QtWidgets.QHBoxLayout()
            self.status_label = QtWidgets.QLabel("Disconnected")
            bottom.addWidget(self.status_label)
            v.addLayout(bottom)

            # Connect signals
            self.read_btn.clicked.connect(self.do_read_all)
            self.import_btn.clicked.connect(self.do_import_hex)
            self.write_btn.clicked.connect(self.do_write_to_card)
            self.export_btn.clicked.connect(self.do_export_hex)
            self.unlock_btn.clicked.connect(self.do_unlock)

            # Initialize
            self.log("Application started")
            self.log("⚠️ WARNING: Write operations can permanently modify card data!")

            # Check for readers at startup
            QtCore.QTimer.singleShot(100, self.check_readers_at_startup)

        def check_readers_at_startup(self):
            """Check for readers at startup and show alert if none found"""
            try:
                readers = self.intf.list_readers()
                if not readers:
                    self.show_no_readers_alert()
                else:
                    self.refresh_readers_menu()
            except Exception as e:
                self.log(f"Startup check error: {e}")
                self.show_no_readers_alert(error_msg=str(e))

        def show_no_readers_alert(self, error_msg=None):
            """Show alert when no readers are found"""
            msg = "⚠️ No Smart Card Readers Found\n\n"

            if error_msg:
                msg += f"Error: {error_msg}\n\n"
            else:
                msg += "No PC/SC compatible smart card readers detected.\n\n"

            msg += "Please ensure:\n"
            msg += "• Your card reader is properly connected\n"
            msg += "• Reader drivers are installed\n"
            msg += "• PC/SC service is running"

            msg_box = QtWidgets.QMessageBox.warning(
                self, "No Readers Found", msg,
                QtWidgets.QMessageBox.Retry | QtWidgets.QMessageBox.Cancel
            )

            if msg_box == QtWidgets.QMessageBox.Retry:
                self.log("User requested reader re-check")
                try:
                    readers = self.intf.list_readers()
                    if not readers:
                        self.log("Re-check: Still no readers found")
                        self.show_no_readers_alert()
                    else:
                        self.log(f"Re-check: Found {len(readers)} reader(s)")
                        self.refresh_readers_menu()
                        QtWidgets.QMessageBox.information(
                            self, "Readers Found",
                            f"✅ Found {len(readers)} reader(s):\n" + "\n".join(f"- {r}" for r in readers)
                        )
                except Exception as e:
                    self.log(f"Re-check error: {e}")
                    self.show_no_readers_alert(error_msg=str(e))
            else:
                self.log("User cancelled reader check")
                self.set_status("No readers available")

        def create_menus(self):
            """Create application menu bar"""
            menubar = self.menuBar()

            # Reader menu
            self.reader_menu = menubar.addMenu("&Readers")
            self.reader_group = QtWidgets.QActionGroup(self)
            self.reader_group.triggered.connect(self.on_reader_selected)

            # Card menu
            card_menu = menubar.addMenu("&Card")

            actions = [
                ("&Read All", self.do_read_all, None),
                None,  # Separator
                ("&Unlock (PSC)", self.do_unlock, None),
                ("&Change PIN", self.do_change_pin, "Ctrl+P"),
                None,  # Separator
                ("&Export HEX", self.do_export_hex, "Ctrl+E"),
                ("&Import HEX", self.do_import_hex, "Ctrl+I"),
                ("&Write to Card", self.do_write_to_card, "Ctrl+W"),
                None,  # Separator
                ("Card &Information", self.show_card_info, None),
                ("&Security Memory", self.show_security_memory, None),
                ("P&rotection Bits", self.show_protection_bits, None),
            ]

            for item in actions:
                if item is None:
                    card_menu.addSeparator()
                else:
                    name, handler, shortcut = item
                    action = QtWidgets.QAction(name, self)
                    action.triggered.connect(handler)
                    if shortcut:
                        action.setShortcut(shortcut)
                    card_menu.addAction(action)

            # Tools menu
            tools_menu = menubar.addMenu("&Tools")
            raw_apdu_action = QtWidgets.QAction("Send Raw &APDU", self)
            raw_apdu_action.setShortcut("Ctrl+R")
            raw_apdu_action.triggered.connect(self.do_send_raw_apdu)
            tools_menu.addAction(raw_apdu_action)

            # Settings menu
            settings_menu = menubar.addMenu("&Settings")

            self.apdu_log_action = QtWidgets.QAction("Log &APDUs", self)
            self.apdu_log_action.setCheckable(True)
            self.apdu_log_action.setChecked(False)
            self.apdu_log_action.triggered.connect(self.toggle_apdu_logging)
            settings_menu.addAction(self.apdu_log_action)

            settings_menu.addSeparator()

            clear_log_action = QtWidgets.QAction("&Clear Log", self)
            clear_log_action.triggered.connect(self.clear_log)
            settings_menu.addAction(clear_log_action)

            # Help menu
            help_menu = menubar.addMenu("&Help")
            about_action = QtWidgets.QAction("&About", self)
            about_action.triggered.connect(self.show_about)
            help_menu.addAction(about_action)

        def toggle_apdu_logging(self):
            """Toggle APDU logging on/off"""
            self.intf.log_apdus = self.apdu_log_action.isChecked()
            status = "enabled" if self.intf.log_apdus else "disabled"
            self.log(f"APDU logging {status}")

        def clear_log(self):
            """Clear log view"""
            self.log_view.clear()
            self.log("Log cleared")

        def refresh_readers_menu(self):
            """Refresh the Readers menu"""
            self.reader_menu.clear()

            # Add Refresh action at top
            refresh_action = QtWidgets.QAction("Refresh Readers", self)
            refresh_action.triggered.connect(self.refresh_readers_menu)
            self.reader_menu.addAction(refresh_action)
            self.reader_menu.addSeparator()

            # Recreate reader group
            self.reader_group = QtWidgets.QActionGroup(self)
            self.reader_group.triggered.connect(self.on_reader_selected)

            try:
                readers = self.intf.list_readers()
                if not readers:
                    no_reader = QtWidgets.QAction("No readers found", self)
                    no_reader.setEnabled(False)
                    self.reader_menu.addAction(no_reader)
                    self.log("No readers found")
                else:
                    for reader in readers:
                        action = QtWidgets.QAction(reader, self)
                        action.setCheckable(True)
                        action.setData(reader)
                        self.reader_group.addAction(action)
                        self.reader_menu.addAction(action)
                        if self.current_reader == reader:
                            action.setChecked(True)
                    self.log(f"Found {len(readers)} reader(s)")
            except Exception as e:
                self.log(f"Error listing readers: {e}")

        def on_reader_selected(self, action):
            """Handle reader selection"""
            reader_name = action.data()
            try:
                if self.intf.hcard:
                    self.intf.disconnect(release_context=False)
                self.intf.connect(reader_name)
                self.current_reader = reader_name
                self.set_status(f"Connected: {reader_name}")
                self.log(f"Connected to reader: {reader_name}")
            except Exception as e:
                self.set_status("Connection failed")
                self.log(f"Error connecting to {reader_name}: {e}")
                QtWidgets.QMessageBox.critical(self, "Connection Error", str(e))

        def handle_card_error(self, error, operation_name, offer_unlock=False, offer_raw_apdu=False):
            """Generic handler for card errors that uses the exception message from .transmit()

            Args:
                error: The exception object containing the detailed message
                operation_name: Name of the operation that failed
                offer_unlock: If True, show "Unlock Card" and "Check Security" buttons
                offer_raw_apdu: If True, show "Open Raw APDU" option for INS not supported errors
            """
            msg = QtWidgets.QMessageBox(self)

            # Set icon based on error type
            if isinstance(error, WrongPINError):
                msg.setIcon(QtWidgets.QMessageBox.Critical)
                msg.setWindowTitle("Wrong PIN")
            elif isinstance(error, INSNotSupportedError):
                msg.setIcon(QtWidgets.QMessageBox.Critical)
                msg.setWindowTitle("APDU Not Supported")
            elif isinstance(error, (CommandNotAllowedError, SecurityNotSatisfiedError)):
                msg.setIcon(QtWidgets.QMessageBox.Warning)
                msg.setWindowTitle("Security Error")
            else:
                msg.setIcon(QtWidgets.QMessageBox.Critical)
                msg.setWindowTitle(f"{operation_name} Error")

            msg.setText(f"{operation_name} failed")
            # Use the full error message from .transmit() - this is the key optimization
            msg.setInformativeText(str(error))

            # Handle buttons based on error type
            if offer_raw_apdu and isinstance(error, INSNotSupportedError):
                msg.addButton("Open Raw APDU Tool", QtWidgets.QMessageBox.YesRole)
                msg.addButton(QtWidgets.QMessageBox.Close)

                if msg.exec_() == 0:  # Yes role clicked
                    self.do_send_raw_apdu()
            elif offer_unlock:
                unlock_btn = msg.addButton("Unlock Card", QtWidgets.QMessageBox.ActionRole)
                security_btn = msg.addButton("Check Security", QtWidgets.QMessageBox.ActionRole)
                msg.addButton(QtWidgets.QMessageBox.Close)

                msg.setDefaultButton(unlock_btn)
                msg.exec_()

                clicked = msg.clickedButton()
                if clicked == unlock_btn:
                    self.do_unlock()
                elif clicked == security_btn:
                    self.show_security_memory()
            else:
                msg.exec_()

        def handle_exception(self, e, operation_name):
            """Handle exceptions with specific error type detection"""
            self.log(f"{operation_name} error: {e}")
            self.set_status(f"{operation_name} failed")

            # Use unified handler with error-specific options
            if isinstance(e, INSNotSupportedError):
                self.handle_card_error(e, operation_name, offer_raw_apdu=True)
            elif isinstance(e, (CommandNotAllowedError, SecurityNotSatisfiedError, WrongPINError)):
                self.handle_card_error(e, operation_name, offer_unlock=True)
            else:
                # Generic error without special handling
                QtWidgets.QMessageBox.critical(self, f"{operation_name} Error", str(e))

        def log(self, message):
            """Add message to log with timestamp"""
            timestamp = datetime.now().strftime("%H:%M:%S")
            self.log_view.appendPlainText(f"[{timestamp}] {message}")

        def set_status(self, text):
            """Set status bar text"""
            self.status_label.setText(text)

        def do_read_all(self):
            """Read all card memory"""
            if not self.intf.hcard:
                QtWidgets.QMessageBox.warning(
                    self, "Not Connected",
                    "Please select a reader from the Readers menu first."
                )
                self.log("Read failed: not connected")
                return

            try:
                self.log("Reading main memory...")
                data = self.intf.read(0, MAIN_MEM_SIZE)
                self.hex_view.setPlainText(hexdump(data))
                self.log(f"Read {len(data)} bytes successfully")
                self.set_status(f"Read OK — {len(data)} bytes")
            except Exception as e:
                self.handle_exception(e, "Read")

        def do_import_hex(self):
            """Import raw HEX file (512 hex characters = 256 bytes)"""
            filename, _ = QtWidgets.QFileDialog.getOpenFileName(
                self, "Import HEX File", "",
                "HEX Files (*.hex *.txt);;All Files (*.*)"
            )
            if not filename:
                self.log("Import cancelled by user")
                return

            try:
                self.log(f"Importing file: {filename}")
                with open(filename, "r") as f:
                    hexstr = f.read().strip().replace(" ", "").replace("\n", "").replace("\r", "")

                if len(hexstr) != MAIN_MEM_SIZE * 2:
                    raise ValueError(
                        f"HEX file must contain exactly {MAIN_MEM_SIZE*2} hex characters "
                        f"({MAIN_MEM_SIZE} bytes), found {len(hexstr)}"
                    )

                data = bytes.fromhex(hexstr)
                self.loaded_data = data
                self.hex_view.setPlainText(hexdump(data))
                self.write_btn.setEnabled(True)

                info = (
                    f"✅ File imported successfully!\n\n"
                    f"File: {filename}\n"
                    f"Data loaded: {len(data)} bytes\n\n"
                    f"SHA-256: {hashlib.sha256(data).hexdigest()[:32]}...\n\n"
                    f"Ready to write to card.\n"
                    f"⚠️ Make sure the card is unlocked first!"
                )

                QtWidgets.QMessageBox.information(self, "Import Successful", info)
                self.log(f"Imported {len(data)} bytes from {filename}")
                self.set_status(f"Data loaded - ready to write")
            except Exception as e:
                self.log(f"Import error: {e}")
                QtWidgets.QMessageBox.critical(
                    self, "Import Error",
                    f"Failed to import file:\n\n{str(e)}"
                )

        def do_write_to_card(self):
            """Write loaded data to card"""
            if not self.intf.hcard:
                QtWidgets.QMessageBox.warning(
                    self, "Not Connected",
                    "Please select a reader and connect to a card first."
                )
                self.log("Write failed: not connected")
                return

            if self.loaded_data is None:
                QtWidgets.QMessageBox.warning(
                    self, "No Data",
                    "Please import a .hex file first."
                )
                self.log("Write failed: no data loaded")
                return

            # Show confirmation dialog
            msg = (
                "⚠️ WARNING: Write Operation\n\n"
                "You are about to write data to the card.\n"
                "This operation will PERMANENTLY modify the card!\n\n"
                f"Data size: {len(self.loaded_data)} bytes\n"
                f"SHA-256: {hashlib.sha256(self.loaded_data).hexdigest()[:32]}...\n\n"
                "Prerequisites:\n"
                "• Card must be unlocked with correct PSC\n"
                "• Protected bytes cannot be written\n"
                "• Operation cannot be undone\n\n"
                "Do you want to continue?"
            )

            reply = QtWidgets.QMessageBox.warning(
                self, "Confirm Write Operation", msg,
                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
                QtWidgets.QMessageBox.No
            )

            if reply != QtWidgets.QMessageBox.Yes:
                self.log("Write cancelled by user")
                return

            try:
                self.log("Starting write operation...")
                self.set_status("Writing to card...")

                # Write data
                self.log(f"Writing {len(self.loaded_data)} bytes...")
                bytes_written = self.intf.write(0, self.loaded_data)

                # Verify
                self.log("Verifying written data...")
                verify_data = self.intf.read(0, MAIN_MEM_SIZE)

                if verify_data == self.loaded_data:
                    info = (
                        f"✅ Write Operation Successful!\n\n"
                        f"Bytes written: {bytes_written}\n"
                        f"Verification: PASSED\n\n"
                        f"All data written and verified successfully."
                    )

                    QtWidgets.QMessageBox.information(self, "Write Successful", info)
                    self.log(f"✅ Write completed: {bytes_written} bytes")
                    self.log("✅ Verification PASSED")
                    self.set_status(f"Write successful - {bytes_written} bytes")

                    # Update display with new data
                    self.hex_view.setPlainText(hexdump(verify_data))
                else:
                    # Find differences
                    diff_count = sum(
                        1 for i in range(len(verify_data))
                        if verify_data[i] != self.loaded_data[i]
                    )

                    info = (
                        f"⚠️ Write Verification Failed!\n\n"
                        f"Bytes written: {bytes_written}\n"
                        f"Differences found: {diff_count} bytes\n\n"
                        f"Possible reasons:\n"
                        f"• Some bytes are write-protected\n"
                        f"• Card was not unlocked\n"
                        f"• Write operation failed\n\n"
                        f"Check protection bits and PSC status."
                    )

                    QtWidgets.QMessageBox.warning(self, "Verification Failed", info)
                    self.log(f"⚠️ Write verification FAILED: {diff_count} bytes differ")
                    self.set_status(f"Write completed with errors")

            except Exception as e:
                self.handle_exception(e, "Write")

        def do_export_hex(self):
            """Export card data as raw HEX (512 hex characters)"""
            if not self.intf.hcard:
                QtWidgets.QMessageBox.warning(
                    self, "Not Connected",
                    "Please select a reader from the Readers menu first."
                )
                self.log("Export failed: not connected")
                return

            try:
                self.log("Reading card data for export...")
                main_memory = self.intf.read(0, MAIN_MEM_SIZE)

                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                default_filename = f"sle4442_dump_{timestamp}.hex"

                filename, _ = QtWidgets.QFileDialog.getSaveFileName(
                    self, "Export Card Data", default_filename,
                    "HEX Files (*.hex *.txt);;All Files (*.*)"
                )

                if not filename:
                    self.log("Export cancelled by user")
                    return

                # Write as continuous hex string
                with open(filename, "w") as f:
                    f.write(main_memory.hex().upper())

                self.log(f"Card data exported to: {filename}")
                self.set_status(f"Exported to {filename}")

                info = (
                    f"✅ Card data successfully exported!\n\n"
                    f"File: {filename}\n"
                    f"Format: Raw HEX (512 characters)\n"
                    f"Data: {len(main_memory)} bytes\n\n"
                    f"SHA-256: {hashlib.sha256(main_memory).hexdigest()[:32]}...\n\n"
                    f"The file can be imported and written to another card."
                )

                QtWidgets.QMessageBox.information(self, "Export Successful", info)

            except Exception as e:
                self.handle_exception(e, "Export")

        def do_unlock(self):
            """Unlock card with 3-byte PSC (6 hex digits)"""
            if not self.intf.hcard:
                QtWidgets.QMessageBox.warning(
                    self, "Not Connected",
                    "Please select a reader first."
                )
                self.log("Unlock failed: not connected")
                return

            pin, ok = QtWidgets.QInputDialog.getText(
                self, "Unlock (PSC)",
                "Enter 3-byte PSC (6 hex digits, e.g. FFFFFF - common default):"
            )

            if not ok:
                return

            pin = pin.strip().replace(" ", "").upper()

            if len(pin) != 6 or not all(c in "0123456789ABCDEF" for c in pin):
                QtWidgets.QMessageBox.warning(
                    self, "Invalid PIN",
                    "PSC must be exactly 6 hex digits (0-9, A-F).\nExample: FFFFFF"
                )
                self.log("Unlock failed: invalid PSC format")
                return

            try:
                pin_bytes = bytes.fromhex(pin)
                self.log(f"Attempting unlock with PSC: {pin}")
                res = self.intf.unlock_with_pin_bytes(pin_bytes)

                QtWidgets.QMessageBox.information(self, "Unlock Result", f"Result: {res}")
                self.set_status(f"Unlock result: {res}")
                self.log(f"Unlock result: {res}")
            except Exception as e:
                self.handle_exception(e, "Unlock")

        def do_change_pin(self):
            """Change card PSC (PIN)"""
            if not self.intf.hcard:
                QtWidgets.QMessageBox.warning(
                    self, "Not Connected",
                    "Please select a reader first."
                )
                self.log("Change PIN failed: not connected")
                return

            # Check if OMNIKEY reader
            reader_info = self.intf.get_reader_info()
            is_omnikey = reader_info['is_omnikey']

            # Warning dialog
            msg = (
                "⚠️ WARNING: Change PIN Operation\n\n"
                "You are about to change the card's PSC (PIN).\n"
                "This operation is PERMANENT and CANNOT be undone!\n\n"
            )

            if is_omnikey:
                msg += (
                    "OMNIKEY Reader Detected:\n"
                    "• You will need to provide BOTH old and new PSC\n"
                    "• Card does NOT need to be unlocked first\n"
                    "• Old PSC will be verified before change\n\n"
                )
            else:
                msg += (
                    "Standard Reader:\n"
                    "• Card MUST be unlocked with current PSC first\n"
                    "• Only new PSC is required\n\n"
                )

            msg += (
                "Prerequisites:\n"
                "• New PSC will immediately replace old PSC\n"
                "• Make sure to remember the new PSC!\n\n"
                "⚠️ If you forget the new PSC, the card may become unusable!\n\n"
                "Do you want to continue?"
            )

            reply = QtWidgets.QMessageBox.warning(
                self, "Change PIN Warning", msg,
                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
                QtWidgets.QMessageBox.No
            )

            if reply != QtWidgets.QMessageBox.Yes:
                self.log("Change PIN cancelled by user")
                return

            old_pin_bytes = None

            # Get old PIN if OMNIKEY reader
            if is_omnikey:
                old_pin, ok = QtWidgets.QInputDialog.getText(
                    self, "Change PIN - Old PSC",
                    "Enter CURRENT 3-byte PSC (6 hex digits, e.g. FFFFFF):"
                )

                if not ok:
                    return

                old_pin = old_pin.strip().replace(" ", "").upper()

                if len(old_pin) != 6 or not all(c in "0123456789ABCDEF" for c in old_pin):
                    QtWidgets.QMessageBox.warning(
                        self, "Invalid PIN",
                        "Current PSC must be exactly 6 hex digits (0-9, A-F).\nExample: FFFFFF"
                    )
                    self.log("Change PIN failed: invalid old PSC format")
                    return

                old_pin_bytes = bytes.fromhex(old_pin)
                self.log(f"Old PSC provided: {old_pin}")
            else:
                # For standard readers, remind to unlock first
                msg_box = QtWidgets.QMessageBox(self)
                msg_box.setIcon(QtWidgets.QMessageBox.Warning)
                msg_box.setWindowTitle("Unlock Required")
                msg_box.setText("Card must be unlocked first")
                msg_box.setInformativeText(
                    "Standard readers require the card to be unlocked "
                    "with the current PSC before changing it.\n\n"
                    "Would you like to unlock the card now?"
                )

                unlock_btn = msg_box.addButton("Unlock Card", QtWidgets.QMessageBox.ActionRole)
                continue_btn = msg_box.addButton("Continue (Already Unlocked)", QtWidgets.QMessageBox.AcceptRole)
                cancel_btn = msg_box.addButton(QtWidgets.QMessageBox.Cancel)

                msg_box.exec_()
                clicked = msg_box.clickedButton()

                if clicked == unlock_btn:
                    self.do_unlock()
                    # Ask if they want to continue after unlocking
                    retry = QtWidgets.QMessageBox.question(
                        self, "Continue?",
                        "Card unlock attempted. Do you want to continue with PIN change?",
                        QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No
                    )
                    if retry != QtWidgets.QMessageBox.Yes:
                        return
                elif clicked == cancel_btn:
                    self.log("Change PIN cancelled by user")
                    return

            # Get new PIN
            new_pin, ok = QtWidgets.QInputDialog.getText(
                self, "Change PIN - New PSC",
                "Enter NEW 3-byte PSC (6 hex digits, e.g. 123456):"
            )

            if not ok:
                return

            new_pin = new_pin.strip().replace(" ", "").upper()

            if len(new_pin) != 6 or not all(c in "0123456789ABCDEF" for c in new_pin):
                QtWidgets.QMessageBox.warning(
                    self, "Invalid PIN",
                    "New PSC must be exactly 6 hex digits (0-9, A-F).\nExample: 123456"
                )
                self.log("Change PIN failed: invalid new PSC format")
                return

            # Confirm new PIN
            confirm_pin, ok = QtWidgets.QInputDialog.getText(
                self, "Confirm New PIN",
                "Re-enter NEW PSC to confirm:"
            )

            if not ok:
                return

            confirm_pin = confirm_pin.strip().replace(" ", "").upper()

            if new_pin != confirm_pin:
                QtWidgets.QMessageBox.critical(
                    self, "PIN Mismatch",
                    "The PINs you entered do not match!\n\nOperation cancelled for safety."
                )
                self.log("Change PIN cancelled: PIN mismatch")
                return

            try:
                new_pin_bytes = bytes.fromhex(new_pin)

                if is_omnikey:
                    self.log(f"Attempting OMNIKEY PIN change: {old_pin} -> {new_pin}")
                else:
                    self.log(f"Attempting standard PIN change to: {new_pin}")
                    # Try to read current security memory (may not be supported)
                    try:
                        sec_before = self.intf.read_security()
                        self.log(f"Current PSC: {sec_before[1:].hex().upper()}")
                    except INSNotSupportedError:
                        self.log("Note: Reader doesn't support reading security memory")

                # Change PIN (with old PIN for OMNIKEY)
                self.intf.change_pin(new_pin_bytes, old_pin_bytes)

                # Try to verify change by reading security memory
                verification_supported = True
                try:
                    sec_after = self.intf.read_security()
                    self.log(f"New PSC: {sec_after[1:].hex().upper()}")
                    verified = (sec_after[1:] == new_pin_bytes)
                except INSNotSupportedError:
                    self.log("Note: Cannot verify PIN change - reader doesn't support reading security memory")
                    verification_supported = False
                    verified = True  # Assume success based on command response

                if verified:
                    info = (
                        f"✅ PIN Changed Successfully!\n\n"
                        f"⚠️ IMPORTANT: Write down your new PSC!\n"
                        f"New PSC: {new_pin}\n\n"
                    )

                    if verification_supported:
                        info += f"Verified PSC: {sec_after[1:].hex().upper()}\n\n"
                    else:
                        info += f"Note: Reader doesn't support verification by reading security memory.\n"
                        info += f"PIN change command succeeded (90 00 response).\n\n"

                    if is_omnikey:
                        info += (
                            f"OMNIKEY reader used - PIN changed with authentication.\n"
                            f"Card may still be unlocked depending on reader behavior."
                        )
                    else:
                        info += (
                            f"The card is now locked with the new PSC.\n"
                            f"You will need to unlock it again to write data."
                        )

                    QtWidgets.QMessageBox.information(self, "PIN Changed", info)
                    self.log("✅ PIN change successful" + (" and verified" if verification_supported else ""))
                    self.set_status("PIN changed successfully")
                else:
                    QtWidgets.QMessageBox.warning(
                        self, "Verification Failed",
                        "PIN change completed but verification failed.\n"
                        "Please check the security memory."
                    )
                    self.log("⚠️ PIN change verification failed")

            except Exception as e:
                self.handle_exception(e, "Change PIN")

        def show_card_info(self):
            """Show card information"""
            if not self.intf.hcard:
                QtWidgets.QMessageBox.warning(
                    self, "Not Connected",
                    "Please select a reader first."
                )
                return

            try:
                self.log("Reading card information...")
                sec = self.intf.read_security()
                prot = self.intf.read_protection_bits()
                data = self.intf.read(0, MAIN_MEM_SIZE)
                reader_info = self.intf.get_reader_info()

                info = (
                    f"Card Type: SLE4442\n"
                    f"Main Memory: {MAIN_MEM_SIZE} bytes\n"
                    f"Protection Bits: {PROT_BITS} bits\n\n"
                    f"Security Memory: {sec.hex().upper()}\n"
                    f"  Error Counter: 0x{sec[0]:02X} ({sec[0]} attempts left)\n"
                    f"  PSC Bytes: {sec[1:].hex().upper()}\n\n"
                    f"Protection Bits: {prot.hex().upper()}\n\n"
                    f"Reader: {reader_info['name']}\n"
                    f"Reader Type: {reader_info['type']}\n"
                    f"Write APDU: {reader_info['write_apdu']}"
                )

                QtWidgets.QMessageBox.information(self, "Card Information", info)
                self.log("Card information displayed")
            except Exception as e:
                self.handle_exception(e, "Card information")

        def show_security_memory(self):
            """Show security memory"""
            if not self.intf.hcard:
                QtWidgets.QMessageBox.warning(
                    self, "Not Connected",
                    "Please select a reader first."
                )
                return

            try:
                self.log("Reading security memory...")
                sec = self.intf.read_security()

                info = (
                    f"Security Memory (4 bytes):\n\n"
                    f"Hex: {sec.hex().upper()}\n"
                    f"Bytes: {list(sec)}\n\n"
                    f"Error Counter: 0x{sec[0]:02X} ({sec[0]} attempts left)\n"
                    f"  • 7 = unlocked\n"
                    f"  • 0 = blocked (card locked permanently)\n\n"
                    f"PSC (3-byte PIN):\n"
                    f"  Byte 1: 0x{sec[1]:02X}\n"
                    f"  Byte 2: 0x{sec[2]:02X}\n"
                    f"  Byte 3: 0x{sec[3]:02X}\n"
                    f"  Combined: {sec[1:].hex().upper()}\n"
                )

                QtWidgets.QMessageBox.information(self, "Security Memory", info)
                self.log("Security memory displayed")
            except Exception as e:
                self.handle_exception(e, "Security memory")

        def show_protection_bits(self):
            """Show protection bits"""
            if not self.intf.hcard:
                QtWidgets.QMessageBox.warning(
                    self, "Not Connected",
                    "Please select a reader first."
                )
                return

            try:
                self.log("Reading protection bits...")
                prot = self.intf.read_protection_bits()

                # Convert to binary representation
                bits = []
                for byte in prot:
                    for i in range(8):
                        bits.append((byte >> i) & 1)

                info = (
                    f"Protection Bits (32 bits):\n\n"
                    f"Hex: {prot.hex().upper()}\n"
                    f"Binary: {' '.join(f'{b:08b}' for b in prot)}\n\n"
                    f"Bit = 1: Byte is writable\n"
                    f"Bit = 0: Byte is write-protected\n\n"
                )

                # Show status of first 32 bytes
                protected_count = sum(1 for b in bits if b == 0)
                info += (
                    f"Protected bytes: {protected_count}/32\n"
                    f"Writable bytes: {32 - protected_count}/32\n"
                )

                QtWidgets.QMessageBox.information(self, "Protection Bits", info)
                self.log("Protection bits displayed")
            except Exception as e:
                self.handle_exception(e, "Protection bits")

        def do_send_raw_apdu(self):
            """Send raw APDU command to card"""
            if not self.intf.hcard:
                QtWidgets.QMessageBox.warning(
                    self, "Not Connected",
                    "Please select a reader first."
                )
                self.log("Send APDU failed: not connected")
                return

            # Get reader info
            reader_info = self.intf.get_reader_info()

            # Create dialog for APDU input
            dialog = QtWidgets.QDialog(self)
            dialog.setWindowTitle("Send Raw APDU")
            dialog.setMinimumWidth(600)

            layout = QtWidgets.QVBoxLayout(dialog)

            # Info label with reader-specific information
            info_text = (
                "Enter APDU command as hex bytes (space-separated or continuous)\n"
                "Example: FF B0 00 00 10  or  FFB0000010\n\n"
                f"Current Reader: {reader_info['name']}\n"
                f"Reader Type: {reader_info['type']}\n"
            )

            if reader_info['is_omnikey']:
                info_text += (
                    f"Write APDU: {reader_info['write_apdu']} [ADDR] [LEN] [DATA...]\n"
                    f"Change PIN: FF 21 00 00 06 [OLD_PSC 3 bytes] [NEW_PSC 3 bytes]\n\n"
                )
            else:
                info_text += "\n"

            info_text += (
                "Common APDUs:\n"
                "• Read memory: FF B0 [ADDR] [LEN]\n"
            )

            if reader_info['is_omnikey']:
                info_text += (
                    "• Write memory: FF D6 [ADDR] [LEN] [DATA...]\n"
                    "• Read protection: FF B0 01 00 04\n"
                    "• Read security: FF B0 01 04 04\n"
                    "• Change PIN: FF 21 00 00 06 [OLD PSC] [NEW PSC]\n"
                )
            else:
                info_text += (
                    "• Write memory: FF D0 [ADDR] [LEN] [DATA...]\n"
                    "• Read protection: FF B2 00 00 04\n"
                    "• Read security: FF B2 01 00 04\n"
                    "• Change PIN: FF D2 01 00 03 [NEW PSC 3 bytes] (must unlock first)\n"
                )

            info_text += (
                "• Unlock: FF 20 00 00 03 [PSC 3 bytes]"
            )

            info_label = QtWidgets.QLabel(info_text)
            info_label.setWordWrap(True)
            layout.addWidget(info_label)

            # APDU input
            apdu_label = QtWidgets.QLabel("APDU Command:")
            layout.addWidget(apdu_label)

            apdu_input = QtWidgets.QLineEdit()
            apdu_input.setFont(QtGui.QFont("Courier", 11))
            apdu_input.setPlaceholderText("FF B0 00 00 10")
            layout.addWidget(apdu_input)

            # Quick templates
            templates_label = QtWidgets.QLabel("Quick Templates:")
            layout.addWidget(templates_label)

            templates_layout = QtWidgets.QHBoxLayout()

            if reader_info['is_omnikey']:
                templates = [
                    ("Read 256 bytes", "FF B0 00 00 FF"),
                    ("Read Protection", "FF B0 01 00 04"),
                    ("Read Security", "FF B0 01 04 04"),
                    ("Write 1 byte", "FF D6 00 00 01 FF"),
                    ("Change PIN", "FF 21 00 00 06 FFFFFF 123456"),
                ]
            else:
                templates = [
                    ("Read 256 bytes", "FF B0 00 00 FF"),
                    ("Read Protection", "FF B2 00 00 04"),
                    ("Read Security", "FF B2 01 00 04"),
                    ("Write 1 byte", "FF D0 00 00 01 FF"),
                ]

            for name, apdu in templates:
                btn = QtWidgets.QPushButton(name)
                btn.clicked.connect(lambda checked, a=apdu: apdu_input.setText(a))
                templates_layout.addWidget(btn)

            templates_layout.addStretch()
            layout.addLayout(templates_layout)

            # Response display
            response_label = QtWidgets.QLabel("Response (will appear after sending):")
            layout.addWidget(response_label)

            response_view = QtWidgets.QPlainTextEdit()
            response_view.setFont(QtGui.QFont("Courier", 10))
            response_view.setReadOnly(True)
            response_view.setMaximumHeight(150)
            layout.addWidget(response_view)

            # Buttons
            button_layout = QtWidgets.QHBoxLayout()

            send_btn = QtWidgets.QPushButton("Send APDU")
            send_btn.setDefault(True)
            send_btn.setStyleSheet(
                "QPushButton { background-color: #4CAF50; color: white; "
                "font-weight: bold; padding: 5px 15px; }"
            )

            close_btn = QtWidgets.QPushButton("Close")

            button_layout.addStretch()
            button_layout.addWidget(send_btn)
            button_layout.addWidget(close_btn)
            layout.addLayout(button_layout)

            # Connect buttons
            close_btn.clicked.connect(dialog.accept)

            def send_apdu():
                apdu_str = apdu_input.text().strip().replace(" ", "").upper()

                if not apdu_str:
                    QtWidgets.QMessageBox.warning(dialog, "Empty APDU", "Please enter an APDU command.")
                    return

                # Validate hex
                if not all(c in "0123456789ABCDEF" for c in apdu_str):
                    QtWidgets.QMessageBox.warning(
                        dialog, "Invalid APDU",
                        "APDU must contain only hex digits (0-9, A-F)."
                    )
                    return

                if len(apdu_str) % 2 != 0:
                    QtWidgets.QMessageBox.warning(
                        dialog, "Invalid APDU",
                        "APDU must have an even number of hex digits."
                    )
                    return

                try:
                    # Convert to bytes
                    apdu_bytes = bytes.fromhex(apdu_str)
                    apdu_list = list(apdu_bytes)

                    self.log(f"Sending raw APDU: {format_apdu(apdu_list)}")

                    # Send APDU (without exception checks) - bypass the interface method
                    if self.intf.log_apdus:
                        self.log(f">> APDU: {format_apdu(apdu_list)}")

                    hresult, response = SCardTransmit(self.intf.hcard, self.intf.protocol, apdu_list)
                    if hresult != SCARD_S_SUCCESS:
                        raise RuntimeError("Transmit failed: " + SCardGetErrorMessage(hresult))

                    if self.intf.log_apdus:
                        self.log(f"<< RESP: {format_apdu(response)} ({len(response)} bytes)")

                    # Format response
                    response_text = f"Raw Response ({len(response)} bytes):\n"
                    response_text += format_apdu(response) + "\n\n"

                    # Parse status words
                    if len(response) >= 2:
                        sw1, sw2 = response[-2], response[-1]
                        response_text += f"Status Words:\n"
                        response_text += f"  SW1: 0x{sw1:02X}\n"
                        response_text += f"  SW2: 0x{sw2:02X}\n"

                        if sw1 == 0x90 and sw2 == 0x00:
                            response_text += "  Status: SUCCESS ✅\n\n"
                        elif sw1 == 0x6D and sw2 == 0x00:
                            response_text += "  Status: INS NOT SUPPORTED ⚠️\n\n"
                        elif sw1 == 0x69 and sw2 == 0x86:
                            response_text += "  Status: COMMAND NOT ALLOWED 🔒\n"
                            response_text += "  (Security restriction / Card locked)\n\n"
                        elif sw1 == 0x69 and sw2 == 0x82:
                            response_text += "  Status: SECURITY NOT SATISFIED 🔒\n"
                            response_text += "  (Authentication required)\n\n"
                        else:
                            response_text += f"  Status: ERROR ⚠️\n\n"

                        # Data bytes (if any)
                        if len(response) > 2:
                            data_bytes = response[:-2]
                            response_text += f"Data ({len(data_bytes)} bytes):\n"
                            response_text += format_apdu(data_bytes) + "\n\n"

                            # Hex dump for larger data
                            if len(data_bytes) > 8:
                                response_text += "Hex Dump:\n"
                                response_text += hexdump(bytes(data_bytes)) + "\n\n"

                            # ASCII representation
                            ascii_repr = ''.join(
                                chr(b) if 32 <= b < 127 else '.'
                                for b in data_bytes
                            )
                            response_text += f"ASCII: {ascii_repr}\n"
                    else:
                        response_text += "Invalid response (too short)\n"

                    response_view.setPlainText(response_text)
                    self.log(f"APDU response: {format_apdu(response)}")

                except Exception as e:
                    error_msg = f"Error sending APDU:\n{str(e)}"
                    response_view.setPlainText(error_msg)
                    self.log(f"APDU error: {e}")
                    QtWidgets.QMessageBox.critical(dialog, "APDU Error", error_msg)

            send_btn.clicked.connect(send_apdu)

            # Allow Enter key to send
            apdu_input.returnPressed.connect(send_apdu)

            dialog.exec_()

        def show_about(self):
            """Show about dialog"""
            about_text = """SLE4442 Manager

A tool for reading and writing SLE4442 memory cards.

Features:
• Read main memory (256 bytes)
• Write to card memory
• Import/Export raw HEX format
• Read security memory
• Read protection bits
• Unlock with 3-byte PSC (PIN)
• Change PSC (PIN)
• Send raw APDU commands
• Multiple reader support
• APDU logging (optional)
• Full CLI support

⚠️ WARNING: Write and PIN change operations are permanent!
Always backup your cards before making changes."""
            QtWidgets.QMessageBox.about(self, "About SLE4442 Manager", about_text)

        def closeEvent(self, event):
            """Handle window close event"""
            try:
                if self.intf.hcard:
                    self.intf.disconnect()
                    self.log("Disconnected from reader")
            except:
                pass
            event.accept()

    app = QtWidgets.QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())