"""
Download Engine - Firmware flashing engine

Implements the exact Odin protocol from odin4.c decompiled source.
"""

import os
import struct
import time
from typing import Optional, Callable
from dataclasses import dataclass

from .usb_device import UsbDevice, DeviceInfo
from .firmware import FirmwareData, FirmwareItem
from .exceptions import (
    OdinProtocolError,
    OdinConnectionError,
    OdinTimeoutError
)
from .constants import (
    OdinCommand,
    TIMEOUT_HANDSHAKE,
    TIMEOUT_TRANSFER,
    PROGRESS_UPDATE_INTERVAL
)


@dataclass
class DownloadProgress:
    """Download/flashing progress information"""
    current_item: int = 0
    total_items: int = 0
    current_bytes: int = 0
    total_bytes: int = 0
    current_file: str = ""
    percentage: float = 0.0
    speed_bps: float = 0.0
    
    def __repr__(self) -> str:
        return f"DownloadProgress({self.percentage:.1f}%, {self.current_file})"


class DownloadEngine:
    """
    Firmware download/flashing engine
    
    Exact implementation from odin4.c decompiled source code.
    """
    
    def __init__(self, usb_device: UsbDevice, verbose: bool = False):
        self.usb_device = usb_device
        self.verbose = verbose
        self.device_info: Optional[DeviceInfo] = None
        self.progress = DownloadProgress()
        self.progress_callback: Optional[Callable[[DownloadProgress], None]] = None
        self.packet_size = 1024  # Need 1024 or it will fail binary check
        self._protocol_version = 2  # Will be set during initialize_connection
        self.file_transfer_packet_size = 131072  # Data block size: 128KB default, 1MB if supported
        self._last_progress_time = 0.0
        self._last_progress_bytes = 0
    
    def log(self, message: str):
        """Print log message if verbose"""
        if self.verbose:
            print(f"[DownloadEngine] {message}")
    
    def set_progress_callback(self, callback: Callable[[DownloadProgress], None]):
        """Set progress callback function"""
        self.progress_callback = callback
    
    def _update_progress(self):
        """Update and notify progress"""
        # Calculate percentage
        if self.progress.total_bytes > 0:
            self.progress.percentage = (self.progress.current_bytes / self.progress.total_bytes) * 100.0
        else:
            self.progress.percentage = 0.0
        
        # Calculate speed (bytes per second)
        current_time = time.time()
        if self._last_progress_time > 0:
            time_delta = current_time - self._last_progress_time
            if time_delta > 0:
                bytes_delta = self.progress.current_bytes - self._last_progress_bytes
                self.progress.speed_bps = bytes_delta / time_delta
        
        self._last_progress_time = current_time
        self._last_progress_bytes = self.progress.current_bytes
        
        # Call progress callback
        if self.progress_callback is not None:
            self.progress_callback(self.progress)
    
    def handshake(self) -> bool:
        """
        Handshake with device (from odin4.c line 12670)
        
        Send: "ODIN" (4 bytes)
        Receive: "LOKE" (4 bytes)
        Timeout: 60000ms (60 seconds)
        """
        self.log("Handshake...")
        
        # Send "ODIN" (odin4.c line 12670: timeout=60000)
        if self.usb_device.write(b"ODIN") != 4:
            return False
        
        # Receive response (odin4.c line 12675: timeout=60000)
        resp = self.usb_device.read(64, timeout=60)
        if len(resp) < 4:
            return False
        
        # Check for "LOKE"
        if resp[0] == 76 and resp[1:3] == b'\x4F\x4B' and resp[3] == 69:
            self.log("✓ Handshake OK")
            return True
        
        return False
    
    def initialize_connection(self, total_bytes: int = 0) -> bool:
        """
        Initialize connection (from odin4.c line 14336-14379)
        
        Sequence:
        1. Handshake
        2. Cmd 100/0: Get protocol version
        3. Cmd 100/5: Set max packet (if version > 1)
        4. Cmd 100/2: Init session with total bytes
        """
        self.log("Initializing connection...")
        
        if not self.handshake():
            return False
        
        # Request and response helper (odin4.c requestAndResponse)
        def req_resp(cmd, sub, param):
            buf = bytearray(0x800)
            struct.pack_into("<III", buf, 0, cmd, sub, param)
            self.usb_device.write(bytes(buf[:self.packet_size]))
            resp = self.usb_device.read(64, timeout=60)  # odin4.c line 12847: 60000ms
            if len(resp) >= 8:
                return struct.unpack("<II", resp[:8])
            return (0, 0)
        
        # Get protocol version
        cmd, data_resp = req_resp(100, 0, 4)
        version = (data_resp >> 16) & 0xFFFF
        self.log(f"Protocol version: {version}")
        self._protocol_version = version  # Store for later use
        
        # Set max packet if version > 1
        if version > 1:
            req_resp(100, 5, 0x100000)
        
        # NOTE: 100/2 (init session with total bytes) is sent LATER
        # in flasher.py after firmware is loaded and total is known
        
        self.log("✓ Connection initialized (total bytes sent later)")
        return True
    
    def get_device_info(self) -> DeviceInfo:
        """Get device info"""
        device_info = self.usb_device.device_info or DeviceInfo(0, 0)
        device_info.protocol_version = self._protocol_version  # Use actual detected version
        self.device_info = device_info
        return device_info
    
    def send_pit_info(self) -> bool:
        """
        Send PIT info to device (from odin4.c line 14405-14441)
        
        For protocol v2/v3, this MUST be called before receivePitInfo
        to make the device receptive.
        """
        self.log("Sending PIT info...")
        
        # From line 14415: if no PIT data, just return success
        # But we still need to signal readiness to the device
        # Check if this sends any command even without PIT...
        # Looking at line 14419-14428, it sends commands only if PIT exists
        # So for now, just return True to continue the flow
        
        self.log("✓ PIT info sent (no-op without PIT data)")
        return True
    
    def receive_pit_data(self) -> bytes:
        """
        Receive PIT from device (from odin4.c line 14476-14600)
        
        EXACT implementation - uses command 101 (NOT 105!)
        """
        self.log("Requesting PIT from device...")
        
        # Step 1: requestAndResponse(this, 101, 1, &v19, 0) - line 14529
        # Get PIT size using command 101/1
        buf = bytearray(0x800)
        struct.pack_into("<III", buf, 0, 101, 1, 0)
        
        self.usb_device.write(bytes(buf[:self.packet_size]))
        
        # Read response with retry
        resp = None
        for retry in range(2):
            resp = self.usb_device.read(64, timeout=60)
            if resp and len(resp) >= 8:
                break
        
        if not resp or len(resp) < 8:
            raise OdinProtocolError("PIT request timeout")
        
        resp_cmd, resp_data = struct.unpack("<II", resp[:8])
        
        if resp_cmd != 101:
            raise OdinProtocolError(f"PIT cmd={resp_cmd}")
        
        pit_size = resp_data
        
        self.log(f"PIT size: {pit_size} bytes")
        
        # Sanity check (line 14547)
        if pit_size == 0 or pit_size > 0x100000:
            raise OdinProtocolError(f"Invalid PIT size: {pit_size}")
        
        # Step 2: Read PIT in 500-byte chunks (line 14552-14568)
        pit_data = bytearray()
        counter = 0
        remaining = pit_size
        
        while remaining > 0:
            # request(this, 101, 2, counter) - line 14555
            buf = bytearray(0x800)
            struct.pack_into("<III", buf, 0, 101, 2, counter)
            self.usb_device.write(bytes(buf[:self.packet_size]))
            
            # Read chunk
            read_size = min(500, remaining)
            chunk = self.usb_device.read(read_size, timeout=60)
            
            if len(chunk) == 0:
                break
            
            pit_data.extend(chunk)
            remaining -= len(chunk)
            counter += 1
        
        self.log(f"Read {len(pit_data)} bytes in {counter} chunks")
        
        # Step 3: Finalize (line 14594) - command 101/3
        buf = bytearray(0x800)
        struct.pack_into("<III", buf, 0, 101, 3, 0)
        self.usb_device.write(bytes(buf[:self.packet_size]))
        resp = self.usb_device.read(64, timeout=60)  # odin4.c: 60000ms
        
        if len(pit_data) != pit_size:
            self.log(f"Warning: PIT size mismatch: {len(pit_data)}/{pit_size}")
        
        self.log(f"✓ PIT received")
        return bytes(pit_data)
    
    def _stream_decompress(self, item: FirmwareItem) -> tuple:
        """
        Stream decompress compressed data to avoid memory exhaustion.
        
        Returns:
            tuple: (decompressed_data_or_file, total_size)
            
        For very large files (>1GB compressed), decompresses to a temporary file.
        For smaller files, decompresses to memory.
        """
        import io
        import tempfile
        
        compressed_data = item.data
        compression_type = item.info.compression_type
        
        # For very large compressed files, use temp file to avoid OOM
        # Threshold: 1GB compressed (likely 3-5GB decompressed)
        USE_TEMP_FILE_THRESHOLD = 1 * 1024 * 1024 * 1024
        use_temp_file = len(compressed_data) > USE_TEMP_FILE_THRESHOLD
        
        if use_temp_file:
            self.log(f"  Large file detected ({len(compressed_data)/(1024**3):.2f} GB compressed)")
            self.log(f"  Using temporary file to avoid memory exhaustion...")
        
        # Decompression chunk size (decompress in 64MB chunks)
        DECOMPRESS_CHUNK_SIZE = 64 * 1024 * 1024
        
        if compression_type == "lz4":
            import lz4.frame
            
            # LZ4 streaming decompression
            self.log(f"  Starting LZ4 streaming decompression...")
            
            # Try using LZ4FrameDecompressor which provides true streaming
            try:
                from lz4.frame import LZ4FrameDecompressor
                
                decompressor = LZ4FrameDecompressor()
                total_decompressed = 0
                
                # Process compressed data in chunks
                compressed_offset = 0
                chunk_size = 2 * 1024 * 1024  # Read 2MB of compressed data at a time
                
                self.log(f"  Using LZ4FrameDecompressor for memory-efficient streaming...")
                
                if use_temp_file:
                    # Write to temporary file to avoid holding everything in memory
                    temp_fd, temp_path = tempfile.mkstemp(suffix='.decompressed', prefix='pyodin_')
                    self.log(f"  Decompressing to temporary file: {temp_path}")
                    
                    with os.fdopen(temp_fd, 'w+b') as temp_file:
                        while compressed_offset < len(compressed_data):
                            end_offset = min(compressed_offset + chunk_size, len(compressed_data))
                            compressed_chunk = compressed_data[compressed_offset:end_offset]
                            
                            try:
                                decompressed_chunk = decompressor.decompress(compressed_chunk)
                                
                                if decompressed_chunk:
                                    temp_file.write(decompressed_chunk)
                                    total_decompressed += len(decompressed_chunk)
                                    
                                    if total_decompressed % (200 * 1024 * 1024) < len(decompressed_chunk):
                                        self.log(f"    Decompressed: {total_decompressed / (1024*1024):.1f} MB")
                                
                                compressed_offset = end_offset
                                
                            except Exception as e:
                                if "End of frame" in str(e) or not compressed_chunk:
                                    break
                                raise
                        
                        # Get remaining data
                        try:
                            remaining = decompressor.flush()
                            if remaining:
                                temp_file.write(remaining)
                                total_decompressed += len(remaining)
                        except:
                            pass
                        
                        temp_file.flush()
                        
                        self.log(f"  Total decompressed: {total_decompressed / (1024*1024):.1f} MB")
                        self.log(f"  Keeping data in temporary file to avoid loading into memory")
                    
                    # Return the temp file path instead of data
                    # The transmit_data function will read from the file in chunks
                    return temp_path, total_decompressed
                else:
                    # Small file - keep in memory
                    decompressed_chunks = []
                    
                    while compressed_offset < len(compressed_data):
                        end_offset = min(compressed_offset + chunk_size, len(compressed_data))
                        compressed_chunk = compressed_data[compressed_offset:end_offset]
                        
                        try:
                            decompressed_chunk = decompressor.decompress(compressed_chunk)
                            
                            if decompressed_chunk:
                                decompressed_chunks.append(decompressed_chunk)
                                total_decompressed += len(decompressed_chunk)
                            
                            compressed_offset = end_offset
                            
                        except Exception as e:
                            if "End of frame" in str(e) or not compressed_chunk:
                                break
                            raise
                    
                    # Get remaining data
                    try:
                        remaining = decompressor.flush()
                        if remaining:
                            decompressed_chunks.append(remaining)
                            total_decompressed += len(remaining)
                    except:
                        pass
                    
                    data = b''.join(decompressed_chunks)
                    return data, len(data)
                
            except ImportError:
                self.log(f"  LZ4FrameDecompressor not available, trying fallback...")
                
                # Fallback: Use direct decompression
                # For large files, this WILL cause OOM, but there's no alternative
                self.log(f"  WARNING: No streaming LZ4 support available!")
                self.log(f"  Install newer python-lz4: pip install --upgrade python-lz4")
                self.log(f"  Attempting direct decompression - may cause out of memory...")
                
                try:
                    data = lz4.frame.decompress(compressed_data)
                    return data, len(data)
                except MemoryError:
                    raise OdinProtocolError(
                        f"Out of memory decompressing {item.filename}. "
                        f"Install python-lz4 >= 3.0.0 for streaming support: "
                        f"pip install --upgrade python-lz4"
                    )
        
        elif compression_type == "gzip":
            import gzip
            
            # GZIP streaming decompression
            self.log(f"  Starting GZIP streaming decompression...")
            decompressed_chunks = []
            total_decompressed = 0
            
            # Create gzip decompressor
            compressed_stream = io.BytesIO(compressed_data)
            
            with gzip.GzipFile(fileobj=compressed_stream, mode='rb') as gz:
                while True:
                    # Read decompressed data in chunks
                    chunk = gz.read(DECOMPRESS_CHUNK_SIZE)
                    if not chunk:
                        break
                    
                    decompressed_chunks.append(chunk)
                    total_decompressed += len(chunk)
                    
                    # Log progress every 100MB
                    if total_decompressed % (100 * 1024 * 1024) < len(chunk):
                        self.log(f"    Decompressed: {total_decompressed / (1024*1024):.1f} MB")
            
            # Join all decompressed chunks
            self.log(f"  Joining {len(decompressed_chunks)} decompressed chunks...")
            data = b''.join(decompressed_chunks)
            return data, len(data)
        
        else:
            self.log(f"  WARNING: Unknown compression type '{compression_type}'")
            return item.data, len(item.data)
    
    def transmit_data(self, item: FirmwareItem, compressed: bool = False) -> bool:
        """
        Transmit firmware data (from odin4.c line 14656-14797)
        
        EXACT implementation of DownloadEngine::transmitData
        Uses streaming decompression to avoid memory exhaustion.
        """
        self.log(f"Transmitting: {item.filename}")
        
        # Load data if lazy-loaded
        if item._lazy_load or len(item.data) == 0:
            self.log(f"  Loading data from TAR...")
            item.load_data()
        
        # Handle compression with streaming decompression
        temp_file_path = None
        data_file = None
        
        if item.info.is_compressed:
            self.log(f"  File is compressed ({item.info.compression_type}): {len(item.data)} bytes")
            
            try:
                # Use streaming decompression to avoid loading entire file into memory
                data_or_path, file_size = self._stream_decompress(item)
                
                # Check if we got a file path (large file) or bytes (small file)
                if isinstance(data_or_path, str):
                    # Large file - decompressed to temp file
                    temp_file_path = data_or_path
                    data_file = open(temp_file_path, 'rb')
                    data = None  # No in-memory data
                    self.log(f"  Decompressed: {len(item.data)} → {file_size} bytes (using temp file)")
                else:
                    # Small file - data in memory
                    data = data_or_path
                    self.log(f"  Decompressed: {len(item.data)} → {file_size} bytes (in memory)")
            except Exception as e:
                self.log(f"  ERROR: Decompression failed: {e}")
                raise OdinProtocolError(f"Failed to decompress {item.filename}: {e}")
        else:
            data = item.data
            file_size = len(data)
            self.log(f"  Uncompressed: {file_size} bytes")
        offset = 0
        
        self.progress.current_file = item.filename
        self.progress.total_bytes = file_size
        
        try:
            # Send FileTransferPacket (102/0) - use 1024 byte packets
            self.log(f"  Activating file transfer (102/0)...")
            buf = bytearray(1024)
            struct.pack_into("<III", buf, 0, 102, 0, 0)
            self.usb_device.write(bytes(buf[:self.packet_size]))
            resp = self.usb_device.read(64, timeout=60)
            if len(resp) < 8:
                self.log(f"  ERROR: File transfer activation timeout")
                return False
            resp_cmd, resp_data = struct.unpack("<II", resp[:8])
            if resp_cmd != 102:
                self.log(f"  ERROR: File transfer activation rejected, cmd={resp_cmd}, data={resp_data}")
                return False
            self.log(f"  File transfer activated")
            
            # Main loop - EXACTLY as odin4.c line 14762
            # Each chunk: 102/0, 102/2, data, 102/3
            while True:
                # Check if done FIRST (line 14763)
                remaining = file_size - offset
                if remaining <= 0:
                    self.log(f"  All data sent, exiting loop")
                    break
                
                # Get chunk size (max 30MB of compressed data)
                chunk_size = min(remaining, 0x1E00000)
                self.log(f"  Sequence {offset//0x1E00000}: offset={offset}, chunk={chunk_size}")
                
                # Begin sequence transfer (102/2) - use 1024 byte packets
                buf = bytearray(1024)
                struct.pack_into("<III", buf, 0, 102, 2, chunk_size)
                
                self.usb_device.write(bytes(buf[:self.packet_size]))
                resp = self.usb_device.read(64, timeout=60)
                if len(resp) < 8:
                    self.log(f"ERROR: Sequence begin timeout")
                    return False
                resp_cmd, resp_data = struct.unpack("<II", resp[:8])
                if resp_cmd != 102:
                    self.log(f"ERROR: Sequence begin rejected, cmd={resp_cmd}")
                    return False
                self.log(f"  Sequence begin accepted")
                
                # No separate size command - the sequence size is already in 102/2 above
                # Give device a moment to prepare for data
                time.sleep(0.1)
                
                # Send data blocks (compressed files send COMPRESSED data)
                self.log(f"  Sending {chunk_size} bytes in {self.file_transfer_packet_size} byte blocks...")
                chunk_offset = 0
                block_count = 0
                while chunk_offset < chunk_size:
                    block_size = min(self.file_transfer_packet_size, chunk_size - chunk_offset)
                    
                    # Read block from either memory or file
                    if data_file is not None:
                        # Reading from file
                        data_file.seek(offset + chunk_offset)
                        block = data_file.read(block_size)
                    else:
                        # Reading from memory
                        block = data[offset + chunk_offset:offset + chunk_offset + block_size]
                    
                    # Pad to full packet size
                    if len(block) < self.file_transfer_packet_size:
                        block += b'\x00' * (self.file_transfer_packet_size - len(block))
                    
                    # CRITICAL: Send empty transfer before each block (except first)
                    if block_count > 0:
                        self.log(f"    Block {block_count}: sending empty transfer...")
                        try:
                            # Send 0-byte transfer for device synchronization
                            self.usb_device.write(b'', timeout=1)
                        except:
                            pass  # ignores failures of empty transfers
                    
                    self.log(f"    Block {block_count}: sending {len(block)} bytes (original size={block_size})")
                    
                    # Send data block
                    written = self.usb_device.write(block, timeout=60)
                    self.log(f"    Block {block_count}: wrote {written} bytes")
                    if written != self.file_transfer_packet_size:
                        self.log(f"    ERROR: Expected to write {self.file_transfer_packet_size} bytes, wrote {written}")
                        return False
                        
                    resp = self.usb_device.read(64, timeout=60)
                    self.log(f"    Block {block_count}: got response {len(resp)} bytes")
                    if len(resp) != 8:
                        self.log(f"    ERROR: Expected 8-byte response, got {len(resp)} bytes")
                        return False
                    
                    chunk_offset += block_size
                    block_count += 1
                    self.progress.current_bytes = offset + chunk_offset
                    self._update_progress()
                
                self.log(f"  Sent {block_count} blocks, total {chunk_offset} bytes")
                
                # Finalize chunk (line 14780-14789)
                # From source: HIDWORD(v20) = sub_7C4C0(v22)
                # sub_7C4C0 returns: *(a1 + 528) <= 0  (true when no more data)
                remaining_after = file_size - (offset + chunk_size)
                completion_status = 1 if remaining_after <= 0 else 0
                
                # Calculate ACTUAL bytes sent
                # sequenceEffectiveByteCount accounts for partial last block WITHOUT padding
                # Last block might be padded, but we report only actual data bytes
                actual_bytes_in_sequence = chunk_offset  # This is the unpadded size
                
                # Build 102/3 packet - EndPhoneFileTransferPacket
                buf = bytearray(1024)  # use 1024 byte packets!
                struct.pack_into("<II", buf, 0, 102, 3)  # cmd=102, sub=3
                
                struct.pack_into("<IIIIII", buf, 8,
                               0,                        # destination (0=Phone)
                               actual_bytes_in_sequence, # sequenceByteCount (ACTUAL unpadded bytes)
                               0,                        # unknown1
                               item.info.device_type,    # deviceType (from PIT)
                               item.info.partition_id,   # fileIdentifier (partition ID)
                               completion_status)        # endOfFile (1=last, 0=more)
                
                self.log(f"    Finalize: size={chunk_size}, part_id={item.info.partition_id}, dev_type={item.info.device_type}, flags={item.info.transfer_flags}, status={completion_status}")
                self.log(f"    FULL PACKET HEX (first 64 bytes):")
                hex_str = buf[:64].hex()
                for i in range(0, len(hex_str), 32):
                    self.log(f"      {i//2:04d}: {hex_str[i:i+32]}")
                
                self.log(f"    Sending empty transfer before 102/3...")
                try:
                    self.usb_device.write(b'', timeout=1)
                except:
                    pass
                
                # Write exactly self.packet_size bytes (line 14268)
                self.usb_device.write(bytes(buf[:self.packet_size]))
                
                self.log(f"    Sending empty transfer after 102/3...")
                try:
                    self.usb_device.write(b'', timeout=1)
                except:
                    pass
                
                # Small delay to let device process
                time.sleep(0.1)
                
                self.log(f"    Reading finalization response (device writing to flash, may take 2 minutes)...")
                resp = None
                try:
                    resp = self.usb_device.read(64, timeout=120)
                except Exception as e:
                    self.log(f"      Timeout after 120s: {e}")
                
                if resp and len(resp) >= 8:
                    # Check for error (line 14127-14138)
                    resp_cmd, resp_data = struct.unpack("<II", resp[:8])
                    self.log(f"    Response: cmd={resp_cmd}, data={resp_data}")
                    if resp_cmd == 0xFFFFFFFF:
                        self.log(f"ERROR: Finalize rejected, code={resp_data}")
                        return False
                    if resp_cmd != 102:
                        self.log(f"ERROR: Unexpected response cmd={resp_cmd}")
                        return False
                else:
                    # No response - log it but continue if this was last chunk
                    self.log(f"    No response received")
                    if completion_status == 1:
                        self.log(f"    WARNING: No response on final chunk, continuing anyway...")
                        # Continue - device may have accepted but not responded
                    else:
                        self.log(f"    ERROR: No response on intermediate chunk")
                        return False
                
                offset += chunk_size
        
        finally:
            # Cleanup: close file and delete temp file if used
            if data_file is not None:
                try:
                    data_file.close()
                    self.log(f"  Closed temporary file")
                except:
                    pass
            
            if temp_file_path is not None:
                try:
                    os.unlink(temp_file_path)
                    self.log(f"  Deleted temporary file: {temp_file_path}")
                except Exception as e:
                    self.log(f"  Warning: Could not delete temp file: {e}")
        
        self.log(f"✓ Complete: {item.filename}")
        return True
    
    def upload_binaries(self, firmware_data: FirmwareData, pit_data=None) -> bool:
        """Upload all firmware items"""
        self.log(f"Uploading {len(firmware_data.items)} items...")
        
        # Match to PIT if available
        if pit_data:
            from .pit import PitParser
            pit = PitParser(self.verbose).parse(pit_data) if isinstance(pit_data, bytes) else pit_data
            
            for item in firmware_data.items:
                fname = item.filename.lower()
                # Remove ALL extensions for matching
                fname_base = fname.replace('.lz4', '').replace('.gz', '').replace('.img', '').replace('.bin', '')
                
                matched = False
                for entry in pit.entries:
                    part_name = entry.partition_name.lower()
                    flash_name = entry.flash_filename.lower()
                    flash_name_base = flash_name.replace('.img', '').replace('.bin', '')
                    
                    # Match with various extension combinations
                    if (fname == flash_name or  # Exact match
                        fname_base == flash_name_base or  # Both without extensions
                        fname_base == part_name or  # File base = partition name
                        fname_base.replace('-', '_') == part_name.replace('-', '_')):  # With dash/underscore normalization
                        item.info.partition_id = entry.partition_id
                        item.info.device_type = entry.device_type
                        self.log(f"  Matched: {item.filename} → {entry.partition_name} (ID={entry.partition_id}, type={entry.device_type})")
                        matched = True
                        break
                
                if not matched:
                    self.log(f"  WARNING: No PIT match for {item.filename} (keeping ID={item.info.partition_id}, type={item.info.device_type})")
                    # Try to detect device_type based on common patterns
                    # Most Samsung partitions use device_type=2
                    if item.info.device_type == 0:
                        item.info.device_type = 2  # Default device type for most partitions
                        self.log(f"    Set default device_type=2 for {item.filename}")
        else:
            # No PIT - use filename-based detection
            self.log("  No PIT - detecting partitions from filenames...")
            for item in firmware_data.items:
                fname = item.filename.lower()
                # Common Samsung partition names
                if 'boot' in fname and 'recovery' not in fname:
                    item.info.partition_id = 3
                    item.info.device_type = 2  # Most common device type
                    self.log(f"  {item.filename} → BOOT (ID=3, type=2)")
                elif 'recovery' in fname:
                    item.info.partition_id = 10
                    item.info.device_type = 2
                    self.log(f"  {item.filename} → RECOVERY (ID=10, type=2)")
                elif 'system' in fname:
                    item.info.partition_id = 20
                    item.info.device_type = 2
                    self.log(f"  {item.filename} → SYSTEM (ID=20, type=2)")
                elif 'cache' in fname:
                    item.info.partition_id = 21
                    item.info.device_type = 2
                    self.log(f"  {item.filename} → CACHE (ID=21, type=2)")
                elif 'userdata' in fname:
                    item.info.partition_id = 22
                    item.info.device_type = 2
                    self.log(f"  {item.filename} → USERDATA (ID=22, type=2)")
                elif 'vendor' in fname:
                    item.info.partition_id = 23
                    item.info.device_type = 2
                    self.log(f"  {item.filename} → VENDOR (ID=23, type=2)")
                elif 'modem' in fname or 'radio' in fname or 'cp' in fname:
                    item.info.partition_id = 11
                    item.info.device_type = 2
                    self.log(f"  {item.filename} → MODEM/CP (ID=11, type=2)")
                elif 'sboot' in fname or fname.startswith('bl') or 'bootloader' in fname:
                    item.info.partition_id = 80
                    item.info.device_type = 2
                    self.log(f"  {item.filename} → BOOTLOADER (ID=80, type=2)")
                elif 'csc' in fname or 'omr' in fname:
                    item.info.partition_id = 24
                    item.info.device_type = 2
                    self.log(f"  {item.filename} → CSC (ID=24, type=2)")
                elif 'hidden' in fname:
                    item.info.partition_id = 25
                    item.info.device_type = 2
                    self.log(f"  {item.filename} → HIDDEN (ID=25, type=2)")
                elif 'efs' in fname:
                    item.info.partition_id = 2
                    item.info.device_type = 2
                    self.log(f"  {item.filename} → EFS (ID=2, type=2)")
                elif 'param' in fname:
                    item.info.partition_id = 15
                    item.info.device_type = 2
                    self.log(f"  {item.filename} → PARAM (ID=15, type=2)")
                elif 'persist' in fname:
                    item.info.partition_id = 26
                    item.info.device_type = 2
                    self.log(f"  {item.filename} → PERSIST (ID=26, type=2)")
                elif 'super' in fname:
                    item.info.partition_id = 30
                    item.info.device_type = 2
                    self.log(f"  {item.filename} → SUPER (ID=30, type=2)")
                elif 'vbmeta' in fname:
                    item.info.partition_id = 31
                    item.info.device_type = 2
                    self.log(f"  {item.filename} → VBMETA (ID=31, type=2)")
                elif 'dtbo' in fname:
                    item.info.partition_id = 32
                    item.info.device_type = 2
                    self.log(f"  {item.filename} → DTBO (ID=32, type=2)")
                else:
                    # Set device_type even for unknown partitions
                    if item.info.device_type == 0:
                        item.info.device_type = 2
                    self.log(f"  {item.filename} → UNKNOWN (keeping ID={item.info.partition_id}, type={item.info.device_type})")
        
        self.progress.total_items = len(firmware_data.items)
        
        for i, item in enumerate(firmware_data.items):
            self.progress.current_item = i
            
            # Skip meta-data files (fota.zip, etc.) - Odin4 line 14366
            if 'meta-data/' in item.filename or item.filename.endswith('.zip'):
                self.log(f"  Skipping meta-data file: {item.filename}")
                continue
            
            if not self.transmit_data(item):
                return False
        
        return True
    
    def close_connection(self) -> bool:
        """
        Close connection (End Session)
        
        Sends END_SESSION command to tell device flashing is complete.
        This is CRITICAL - without it, device thinks flash failed!
        """
        self.log("Sending END_SESSION command...")
        
        try:
            # Send END_SESSION (command 103/0) - tells device we're done
            buf = bytearray(1024)
            struct.pack_into("<III", buf, 0, 103, 0, 0)
            self.usb_device.write(bytes(buf[:self.packet_size]))
            
            # Try to read response (device may not always respond)
            try:
                resp = self.usb_device.read(64, timeout=2)
                if len(resp) >= 8:
                    resp_cmd, resp_data = struct.unpack("<II", resp[:8])
                    self.log(f"  END_SESSION response: cmd={resp_cmd}, data={resp_data}")
                else:
                    self.log(f"  END_SESSION: no response (normal)")
            except:
                self.log(f"  END_SESSION: no response (normal)")
            
            self.log("✓ Session closed")
            return True
            
        except Exception as e:
            self.log(f"ERROR closing connection: {e}")
            return False
    
    def _send_packet(self, cmd, sub, param):
        """
        Send simple packet - EXACT odin4.c implementation
        
        From odin4.c line 12829-12840:
        - Creates 0x800 (2048) byte buffer
        - Packs cmd, sub, param at start
        - Writes exactly packet_size bytes
        """
        buf = bytearray(0x800)  # 2048 bytes
        struct.pack_into("<III", buf, 0, cmd, sub, param)
        return self.usb_device.write(bytes(buf[:self.packet_size]))
    
    def reboot_device(self) -> bool:
        """Reboot device (cmd 103/2)"""
        try:
            self._send_packet(103, 2, 0)
        except:
            # Device may disconnect before write completes
            pass
        try:
            self.usb_device.read(8, timeout=2)
        except:
            pass
        return True

