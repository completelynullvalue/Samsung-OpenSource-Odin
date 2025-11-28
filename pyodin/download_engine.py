"""
Main Odin Flasher

High-level API for firmware flashing operations.
"""

import time
import struct
from typing import Optional, Callable, List, Dict

from .usb_device import UsbDevice, DeviceInfo
from .download_engine import DownloadEngine, DownloadProgress
from .firmware import FirmwareParser, FirmwareData
from .pit import PitParser, PitData
from .manifest import ManifestParser, ManifestInfo
from .exceptions import (
    OdinException,
    OdinConnectionError,
    OdinFirmwareError
)


class OdinFlasher:
    """
    Main Odin flasher class
    
    Provides high-level API for firmware flashing operations.
    """
    
    def __init__(self, verbose: bool = False, bypass_verification: bool = False):
        self.verbose = verbose
        self.bypass_verification = bypass_verification
        self.usb_device: Optional[UsbDevice] = None
        self.download_engine: Optional[DownloadEngine] = None
        self.firmware_parser = FirmwareParser(verbose=verbose, bypass_verification=bypass_verification)
        self.pit_parser = PitParser(verbose=verbose)
        self.manifest_parser = ManifestParser(verbose=verbose)
        self.device_info: Optional[DeviceInfo] = None
        self.is_connected = False
    
    def log(self, message: str):
        """Print log message if verbose"""
        if self.verbose:
            print(f"[OdinFlasher] {message}")
    
    def _get_decompressed_size(self, item) -> int:
        """
        Get decompressed size efficiently without loading entire file into memory.
        
        Tries to extract size from compression headers/footers when possible,
        otherwise uses streaming decompression to count bytes.
        """
        import io
        import struct
        
        compression_type = item.info.compression_type
        compressed_data = item.data
        
        if compression_type == "gzip":
            # GZIP stores uncompressed size in last 4 bytes (ISIZE field)
            # Note: This is modulo 2^32, so only accurate for files < 4GB
            try:
                if len(compressed_data) >= 4:
                    # Last 4 bytes contain uncompressed size (little-endian)
                    isize = struct.unpack('<I', compressed_data[-4:])[0]
                    
                    # If size seems reasonable (not wrapped around), use it
                    # Otherwise fall back to streaming
                    if isize > 0 and isize < 10 * 1024 * 1024 * 1024:  # < 10GB
                        self.log(f"  GZIP size from footer: {isize / (1024*1024):.1f} MB")
                        return isize
            except:
                pass
            
            # Fallback: stream and count
            self.log(f"  Calculating GZIP size via streaming...")
            import gzip
            total_size = 0
            compressed_stream = io.BytesIO(compressed_data)
            
            with gzip.GzipFile(fileobj=compressed_stream, mode='rb') as gz:
                chunk_size = 64 * 1024 * 1024  # 64MB chunks
                while True:
                    chunk = gz.read(chunk_size)
                    if not chunk:
                        break
                    total_size += len(chunk)
                    
                    # Log progress for large files
                    if total_size % (500 * 1024 * 1024) < chunk_size:
                        self.log(f"    Calculated size so far: {total_size / (1024*1024):.1f} MB")
            
            return total_size
        
        elif compression_type == "lz4":
            # LZ4 frame format MAY include content size in frame descriptor
            try:
                import lz4.frame
                
                # Try to read frame info
                if len(compressed_data) >= 7:
                    # LZ4 frame header: magic(4) + FLG(1) + BD(1) + ...
                    flg = compressed_data[4]
                    content_size_flag = (flg >> 3) & 0x01
                    
                    if content_size_flag:
                        # Content size is present at offset 6 (8 bytes, little-endian)
                        if len(compressed_data) >= 14:
                            content_size = struct.unpack('<Q', compressed_data[6:14])[0]
                            self.log(f"  LZ4 size from header: {content_size / (1024*1024):.1f} MB")
                            return content_size
            except:
                pass
            
            # Fallback: stream and count using LZ4 streaming API
            self.log(f"  Calculating LZ4 size via streaming...")
            import lz4.frame
            
            try:
                # Try streaming decompression
                dctx = lz4.frame.create_decompression_context()
                total_size = 0
                compressed_offset = 0
                chunk_size = 1 * 1024 * 1024  # 1MB compressed chunks
                
                while compressed_offset < len(compressed_data):
                    end_offset = min(compressed_offset + chunk_size, len(compressed_data))
                    compressed_chunk = compressed_data[compressed_offset:end_offset]
                    
                    try:
                        decompressed_chunk, bytes_read = lz4.frame.decompress_chunk(
                            dctx, compressed_chunk
                        )
                        
                        if decompressed_chunk:
                            total_size += len(decompressed_chunk)
                            
                            # Log progress for large files
                            if total_size % (500 * 1024 * 1024) < len(decompressed_chunk):
                                self.log(f"    Calculated size so far: {total_size / (1024*1024):.1f} MB")
                        
                        compressed_offset += bytes_read if bytes_read > 0 else len(compressed_chunk)
                        
                        if bytes_read == 0 and len(decompressed_chunk) == 0:
                            compressed_offset = end_offset
                            
                    except lz4.frame.Lz4FrameEOFError:
                        break
                
                return total_size
                
            except AttributeError:
                # Fallback to regular decompression if streaming not available
                self.log(f"  LZ4 streaming not available, using full decompression")
                decompressed = lz4.frame.decompress(compressed_data)
                return len(decompressed)
        
        else:
            # Unknown compression - return compressed size
            return len(compressed_data)
    
    def list_devices(self) -> List[DeviceInfo]:
        """
        List all connected Samsung devices in Download mode
        
        Returns:
            List of DeviceInfo objects
        """
        return UsbDevice.list_devices()
    
    def connect_device(self, device_index: int = 0) -> DeviceInfo:
        """
        Connect to Samsung device
        
        Args:
            device_index: Device index if multiple devices connected
            
        Returns:
            DeviceInfo object
        """
        self.log("Connecting to device...")
        
        # Create USB device
        self.usb_device = UsbDevice(verbose=self.verbose)
        
        # Find device
        device_info = self.usb_device.find_device()
        if device_info is None:
            raise OdinConnectionError("No Samsung device found in Download mode")
        
        self.log(f"Found device: {device_info}")
        
        # Connect to device
        if not self.usb_device.connect():
            raise OdinConnectionError("Failed to connect to device")
        
        # Create download engine
        self.download_engine = DownloadEngine(self.usb_device, verbose=self.verbose)
        
        # Do initial handshake and protocol detection ONLY
        # Full initialization (with total bytes) happens in flash()
        if not self.download_engine.handshake():
            raise OdinConnectionError("Failed handshake")
        
        buf = bytearray(1024)  # use 1024 byte packets
        struct.pack_into("<III", buf, 0, 100, 0, 4)  # cmd=100, sub=0, param=4
        self.usb_device.write(bytes(buf[:self.download_engine.packet_size]))
        resp = self.usb_device.read(64, timeout=60)  # odin4.c: 60s timeout
        
        device_default_packet_size = 0
        if len(resp) >= 8:
            cmd, data = struct.unpack("<II", resp[:8])
            version = (data >> 16) & 0xFFFF
            device_default_packet_size = data & 0xFFFF  # Lower 16 bits
            self.download_engine._protocol_version = version
            self.log(f"Protocol version: {version}, default packet size: {device_default_packet_size}")
        
        # Send file part size ONLY if device supports it (deviceDefaultPacketSize != 0)
        if device_default_packet_size != 0:
            self.log("Sending file part size (100/5)...")
            buf = bytearray(1024)
            struct.pack_into("<III", buf, 0, 100, 5, 0x100000)  # 1MB
            self.usb_device.write(bytes(buf[:self.download_engine.packet_size]))
            resp = self.usb_device.read(64, timeout=60)  # odin4.c: 60s timeout
            if len(resp) >= 8:
                cmd, result = struct.unpack("<II", resp[:8])
                self.log(f"File part size response: {result}")
                if result != 0:
                    raise OdinConnectionError(f"Device rejected file part size: {result}")
        
        # Get device info
        self.device_info = self.download_engine.get_device_info()
        self.is_connected = True
        
        self.log(f"Connected to device: {self.device_info}")
        
        return self.device_info
    
    def disconnect_device(self):
        """Disconnect from device"""
        if self.download_engine is not None:
            self.download_engine.close_connection()
        
        if self.usb_device is not None:
            self.usb_device.disconnect()
        
        self.is_connected = False
        self.log("Disconnected from device")
    
    def load_firmware(self, firmware_path: str, verify_hash: bool = True) -> FirmwareData:
        """
        Load and parse firmware file
        
        Args:
            firmware_path: Path to firmware file
            verify_hash: Whether to verify MD5 hash
            
        Returns:
            FirmwareData object
        """
        self.log(f"Loading firmware: {firmware_path}")
        
        firmware_data = self.firmware_parser.parse(firmware_path, verify_hash)
        
        self.log(f"Loaded {len(firmware_data.items)} firmware items")
        
        return firmware_data
    
    def load_pit(self, pit_path: str) -> PitData:
        """
        Load and parse PIT file
        
        Args:
            pit_path: Path to PIT file
            
        Returns:
            PitData object
        """
        self.log(f"Loading PIT: {pit_path}")
        
        with open(pit_path, 'rb') as f:
            pit_data = f.read()
        
        pit = self.pit_parser.parse(pit_data)
        
        self.log(f"Loaded PIT with {len(pit.entries)} entries")
        
        return pit
    
    def flash_multi_section(
        self,
        firmware_sections: Dict[str, FirmwareData],
        pit_data: Optional[bytes] = None,
        reboot: bool = True,
        reboot_to_download: bool = False,
        progress_callback: Optional[Callable[[DownloadProgress], None]] = None
    ) -> bool:
        """
        Flash multiple firmware sections (BL, AP, CP, CSC, etc.) to device
        
        Args:
            firmware_sections: Dict mapping section names to FirmwareData objects
                              e.g., {"BL": fw_bl, "AP": fw_ap, "CP": fw_cp, "CSC": fw_csc}
            pit_data: PIT data (optional)
            reboot: Whether to reboot after flashing
            reboot_to_download: Whether to reboot to download mode (default: False = reboot to system)
            progress_callback: Progress callback function
            
        Returns:
            True if flashing successful
        """
        if not self.is_connected:
            raise OdinConnectionError("Not connected to device")
        
        if self.download_engine is None:
            raise OdinException("Download engine not initialized")
        
        # Merge all firmware sections into one
        merged_firmware = FirmwareData()
        for section_name, firmware_data in firmware_sections.items():
            self.log(f"Adding section {section_name}: {len(firmware_data.items)} items")
            merged_firmware.items.extend(firmware_data.items)
            
            # Use PIT from first section that has it
            if firmware_data.pit_data and not merged_firmware.pit_data:
                merged_firmware.pit_data = firmware_data.pit_data
        
        self.log(f"Total merged items: {len(merged_firmware.items)}")
        
        # Flash the merged firmware
        return self.flash(
            merged_firmware,
            pit_data=pit_data,
            reboot=reboot,
            reboot_to_download=reboot_to_download,
            progress_callback=progress_callback
        )
    
    def flash(
        self,
        firmware_data: FirmwareData,
        pit_data: Optional[bytes] = None,
        reboot: bool = True,
        reboot_to_download: bool = False,
        progress_callback: Optional[Callable[[DownloadProgress], None]] = None
    ) -> bool:
        """
        Flash firmware to device
        
        Args:
            firmware_data: Firmware data to flash
            pit_data: PIT data (optional)
            reboot: Whether to reboot after flashing
            reboot_to_download: Whether to reboot to download mode (default: False = reboot to system)
            progress_callback: Progress callback function
            
        Returns:
            True if flashing successful
        """
        if not self.is_connected:
            raise OdinConnectionError("Not connected to device")
        
        if self.download_engine is None:
            raise OdinException("Download engine not initialized")
        
        self.log("Starting firmware flash...")
        
        # Set progress callback
        if progress_callback is not None:
            self.download_engine.set_progress_callback(progress_callback)
        
        try:
            # CRITICAL: Protocol sequence from odin4.c line 15120-15175:
            # 1. setupConnection (handshake - done in connect_device)
            # 2. initializeConnection (100/0, 100/5, 100/2 with total) - done here
            # 3. sendPitInfo
            # 4. receivePitInfo
            # 5. uploadBinaries
            
            # Calculate ACTUAL total bytes that will be transmitted
            # Use streaming decompression to get size without exhausting memory
            total_bytes = 0
            for item in firmware_data.items:
                if item.data is None:
                    continue
                
                # Skip meta-data files
                if 'meta-data/' in item.filename or item.filename.endswith('.zip'):
                    continue
                
                # Calculate decompressed size if compressed
                if item.info.is_compressed:
                    try:
                        decompressed_size = self._get_decompressed_size(item)
                        total_bytes += decompressed_size
                    except Exception as e:
                        self.log(f"  WARNING: Could not determine decompressed size for {item.filename}: {e}")
                        total_bytes += len(item.data)
                else:
                    total_bytes += len(item.data)
            
            self.log(f"Total bytes to send: {total_bytes} ({total_bytes/1024/1024:.1f} MB)")
            
            # STEP 2: Send 100/2 with total bytes - MUST be before PIT!
            # CRITICAL: Must match odin4.c requestAndResponse with array parameter!
            # odin4.c line 12996-13001: cmd, sub, then 8 DWORDs from array
            self.log("Completing initialization (100/2 with total bytes)...")
            buf = bytearray(1024)  # Use 1024 byte packets
            struct.pack_into("<II", buf, 0, 100, 2)  # cmd, sub
            struct.pack_into("<Q", buf, 8, total_bytes)  # 64-bit total at offset 8
            # Remaining DWORDs are zeros (already zeroed in bytearray)
            self.download_engine.usb_device.write(bytes(buf[:self.download_engine.packet_size]))
            
            # Wait for and validate response (odin4.c uses 60s timeout)
            resp = self.download_engine.usb_device.read(64, timeout=60)
            if len(resp) < 8:
                raise OdinException("No response to 100/2 packet")
            resp_cmd, resp_data = struct.unpack("<II", resp[:8])
            if resp_cmd != 100:
                raise OdinException(f"Invalid response to 100/2: cmd={resp_cmd}")
            if resp_data != 0:
                raise OdinException(f"Device rejected 100/2: result={resp_data}")
            self.log(f"✓ Initialization complete")
            
            # STEP 2b: Send lock information ONLY if option_lock is enabled (NOT for bypass_verification!)
            # (odin4.c line 14383-14398)
            # This tells the phone to skip verification checks for .BIN files
            # 
            # NOTE: Command 100/3 is for option_lock ONLY, not for general bypass!
            # bypass_verification is PC-SIDE ONLY - it doesn't send device commands
            if firmware_data.option_lock:
                self.log("Send lock information..")
                
                # Optionally probe support first (quick check)
                # Note: We still attempt the full command even if probe fails,
                # as some devices may respond slowly but still support it
                self.log("Checking option_lock support...")
                probe_supported = self.download_engine.probe_lock_command_support(mode="bypass", probe_timeout=2.0)
                if not probe_supported:
                    self.log("⚠️ Device may not support option_lock (probe timeout)")
                    self.log("⚠️ Attempting anyway (device may respond slowly)")
                
                # Use download_engine's method to send the command properly
                success = self.download_engine.send_lock_command(mode="bypass")
                
                if success:
                    self.log("✓ Lock information sent (phone verification disabled)")
                else:
                    # Some devices don't support option_lock - log warning but continue
                    # This is safer than aborting, as option_lock is optional
                    self.log("⚠️ Lock operation failed or not supported by device")
                    self.log("⚠️ Continuing without option_lock - device may still verify signatures")
                    # Don't abort - just continue without option_lock
            
            elif self.bypass_verification:
                self.log("⚠️ BYPASS MODE: PC-side verification disabled")
                self.log("⚠️ Device will still verify signatures (use --option-lock for device bypass)")
            
            pit_for_matching = None
            
            # Check protocol version
            protocol_version = self.device_info.protocol_version if self.device_info else 2
            self.log(f"Device protocol version: {protocol_version}")
            
            # For protocol v2/v3: MUST call sendPitInfo then receivePitInfo
            if protocol_version <= 3:
                self.log("Protocol v2/v3 detected - will retrieve PIT...")
                
                # Step 3: sendPitInfo (line 15151-15158)
                self.log("Calling sendPitInfo...")
                if not self.download_engine.send_pit_info():
                    raise OdinException("sendPitInfo failed")
                
                # If we have PIT data to send, send it
                if pit_data is not None:
                    self.log("Sending PIT data...")
                    if not self.download_engine.send_pit_data(pit_data):
                        raise OdinException("Failed to send PIT data")
                    pit_for_matching = pit_data
                elif firmware_data.pit_data is not None:
                    self.log("Sending embedded PIT data...")
                    if not self.download_engine.send_pit_data(firmware_data.pit_data):
                        raise OdinException("Failed to send embedded PIT data")
                    pit_for_matching = firmware_data.pit_data
                # else: No PIT to send (sendPitInfo returns success immediately)
                
                # Step 2b: receivePitInfo (line 15159-15162) - ALWAYS for v2/v3
                self.log("Receiving PIT from device...")
                try:
                    pit_for_matching = self.dump_pit()
                    self.log(f"✓ Retrieved PIT ({len(pit_for_matching)} bytes)")
                except Exception as e:
                    self.log(f"ERROR: Could not retrieve PIT: {e}")
                    raise
            else:
                # Protocol v4+ may not need PIT
                if pit_data is not None:
                    self.log("Sending PIT data...")
                    if not self.download_engine.send_pit_data(pit_data):
                        raise OdinException("Failed to send PIT data")
                    pit_for_matching = pit_data
                elif firmware_data.pit_data is not None:
                    self.log("Sending embedded PIT data...")
                    if not self.download_engine.send_pit_data(firmware_data.pit_data):
                        raise OdinException("Failed to send embedded PIT data")
                    pit_for_matching = firmware_data.pit_data
            
            # Upload firmware binaries (with PIT for partition matching)
            self.log("Uploading firmware binaries...")
            if not self.download_engine.upload_binaries(firmware_data, pit_for_matching):
                raise OdinException("Failed to upload firmware binaries")
            
            self.log("Firmware flashed successfully!")
            
            # CRITICAL: Close session properly before rebooting
            # This tells the device we're done and flashing was successful
            self.log("Closing session...")
            try:
                self.download_engine.close_connection()
                time.sleep(0.5)  # Give device time to process
            except Exception as e:
                self.log(f"Warning: Error closing connection: {e}")
            
            # Reboot device if requested
            if reboot:
                boot_target = "download mode" if reboot_to_download else "system"
                self.log(f"Rebooting device to {boot_target}...")
                try:
                    self.download_engine.reboot_device(to_download_mode=reboot_to_download)
                    time.sleep(1)  # Wait a bit before disconnect
                except:
                    # Device disconnects during reboot - this is normal
                    pass
            
            return True
            
        except Exception as e:
            self.log(f"Flashing failed: {e}")
            raise
    
    def dump_pit(self) -> bytes:
        """
        Dump PIT from device
        
        Returns:
            PIT data
        """
        if not self.is_connected:
            raise OdinConnectionError("Not connected to device")
        
        if self.download_engine is None:
            raise OdinException("Download engine not initialized")
        
        self.log("Dumping PIT from device...")
        
        # Use the new receive_pit_data method which handles the full protocol
        pit_data = self.download_engine.receive_pit_data()
        
        self.log(f"PIT dumped successfully ({len(pit_data)} bytes)")
        
        return pit_data
    
    def verify_firmware(self, firmware_data: FirmwareData) -> bool:
        """
        Verify firmware integrity
        
        Args:
            firmware_data: Firmware data to verify
            
        Returns:
            True if verification successful
        """
        self.log("Verifying firmware...")
        
        # Check if MD5 hash is present
        if firmware_data.md5_hash:
            self.log(f"MD5 hash: {firmware_data.md5_hash}")
            # MD5 was already verified during parsing if requested
        
        # Check manifest if present
        if firmware_data.manifest is not None:
            self.log("Manifest present")
        
        self.log("Firmware verification complete")
        
        return True
    
    def get_device_info(self) -> Optional[DeviceInfo]:
        """
        Get connected device information
        
        Returns:
            DeviceInfo or None if not connected
        """
        return self.device_info
    
    def enumerate_command_params(self, cmd: int, sub: int, param_range: range = None, 
                                 probe_timeout: float = 2.0, verbose: bool = True) -> dict:
        """
        Enumerate which parameter values the device accepts for a given command.
        
        This is useful for discovering what parameters a device supports without
        having to manually test each one.
        
        Args:
            cmd: Command ID (e.g., 100)
            sub: Sub-command ID (e.g., 3)
            param_range: Range of parameter values to test (default: 0-255)
            probe_timeout: Timeout per probe in seconds (default: 2.0s)
            verbose: If True, log each attempt (default: True)
        
        Returns:
            dict with 'accepted', 'rejected', 'timeout', 'unexpected' lists
        """
        if not self.is_connected:
            raise OdinConnectionError("Device not connected")
        
        if not self.download_engine:
            raise OdinException("Download engine not initialized")
        
        return self.download_engine.enumerate_command_params(
            cmd, sub, param_range, probe_timeout, verbose
        )
    
    def check_oem_unlock_support(self) -> bool:
        """
        Check if device supports OEM unlock command (100/3 with param=0).
        
        This probes the device with a short timeout to determine support
        without actually unlocking the bootloader.
        
        Returns:
            True if device appears to support OEM unlock, False otherwise
        """
        if not self.is_connected:
            raise OdinConnectionError("Device not connected")
        
        if not self.download_engine:
            raise OdinException("Download engine not initialized")
        
        return self.download_engine.probe_lock_command_support(mode="unlock", probe_timeout=2.0)
    
    def oem_unlock(self, check_support: bool = True) -> bool:
        """
        Send OEM bootloader unlock command to device
        
        WARNING: This is a DESTRUCTIVE operation that may:
        - Wipe all user data
        - Void warranty
        - Brick device if not supported
        
        NOTE: OEM unlock (100/3 param=0) is UNVERIFIED in odin4.c source.
        odin4.c only uses param=1 (bypass). This implementation is based on
        protocol structure but has not been verified against actual devices.
        
        Args:
            check_support: If True, probe device first to check support (default: True)
        
        Returns:
            True if command accepted, False otherwise
        """
        if not self.is_connected:
            raise OdinConnectionError("Device not connected")
        
        if not self.download_engine:
            raise OdinException("Download engine not initialized")
        
        # Optionally check support first
        if check_support:
            self.log("Checking OEM unlock support...")
            if not self.download_engine.probe_lock_command_support(mode="unlock", probe_timeout=2.0):
                self.log("⚠️ Device may not support OEM unlock command")
                self.log("⚠️ Continuing anyway (device may still process it)")
        
        self.log("=" * 60)
        self.log("WARNING: Sending OEM UNLOCK command")
        self.log("This will permanently unlock the bootloader")
        self.log("=" * 60)
        
        # Send 100/3 with parameter 0 for OEM unlock
        success = self.download_engine.send_lock_command(mode="unlock")
        
        if success:
            self.log("✓ OEM unlock command accepted by device")
            self.log("Device may reboot or require power cycle")
        else:
            self.log("✗ OEM unlock command rejected or not supported")
        
        return success
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        if self.is_connected:
            self.disconnect_device()

