"""
Firmware parsing and handling

Supports TAR, TAR.MD5, BIN, and compressed firmware files.
"""

import os
import io
import struct
import tarfile
import gzip
import lz4.frame
from typing import List, Optional, Dict, Any, BinaryIO
from dataclasses import dataclass, field

from .exceptions import OdinFirmwareError
from .crypto_utils import verify_md5, verify_sha256, CryptoVerifier, calculate_md5_file
from .constants import (
    TAR_SIGNATURE,
    GZIP_SIGNATURE,
    LZ4_SIGNATURE,
    MD5_FILE_EXTENSION,
    FIRMWARE_EXTENSIONS
)


@dataclass
class FirmwareInfo:
    """Firmware file information"""
    filename: str
    partition_name: str = ""
    file_type: str = ""
    size: int = 0
    compressed_size: int = 0
    is_compressed: bool = False
    compression_type: str = ""
    checksum: str = ""
    checksum_type: str = ""
    
    # LZ4 frame info
    lz4_block_size: int = 0
    lz4_has_checksum: bool = False
    
    # Odin protocol fields (from odin4.c FirmwareInfo offsets +80, +84, +88)
    # These are sent in the finalization packet (command 102/3)
    # Default values for standalone flashing (without PIT)
    # NOTE: These MUST match actual device partitions or flashing will fail
    partition_id: int = 1      # Offset +80: Partition ID (1 = common default)
    device_type: int = 0       # Offset +84: Device type (0 = default/any)
    transfer_flags: int = 0    # Offset +88: Transfer flags (0 = normal)
    
    def __repr__(self) -> str:
        return f"FirmwareInfo(filename='{self.filename}', size={self.size}, type='{self.file_type}')"


@dataclass
class FirmwareItem:
    """Individual firmware file item"""
    info: FirmwareInfo
    data: bytes = b""
    offset: int = 0
    
    # Lazy loading support for large files
    _source_path: Optional[str] = None
    _tar_member_name: Optional[str] = None
    _lazy_load: bool = False
    
    @property
    def filename(self) -> str:
        return self.info.filename
    
    @property
    def size(self) -> int:
        return len(self.data) if self.data else self.info.size
    
    def load_data(self) -> bytes:
        """Load data on-demand (for lazy-loaded items)"""
        if self.data:
            return self.data
        
        if self._lazy_load and self._source_path and self._tar_member_name:
            # Lazy load from TAR file
            import tarfile
            try:
                with tarfile.open(self._source_path, 'r') as tar:
                    member = tar.getmember(self._tar_member_name)
                    f = tar.extractfile(member)
                    if f:
                        self.data = f.read()
                        return self.data
            except Exception as e:
                raise OdinFirmwareError(f"Failed to lazy-load {self.filename}: {e}")
        
        return b""
    
    def __repr__(self) -> str:
        return f"FirmwareItem(filename='{self.filename}', size={self.size}, lazy={self._lazy_load})"


@dataclass
class FirmwareData:
    """Complete firmware package data"""
    items: List[FirmwareItem] = field(default_factory=list)
    md5_hash: str = ""
    manifest: Optional[Dict[str, Any]] = None
    pit_data: Optional[bytes] = None
    option_lock: bool = False
    
    def get_item_by_name(self, filename: str) -> Optional[FirmwareItem]:
        """Get firmware item by filename"""
        for item in self.items:
            if item.filename == filename:
                return item
        return None
    
    def get_items_by_extension(self, extension: str) -> List[FirmwareItem]:
        """Get all items with specific extension"""
        return [item for item in self.items if item.filename.endswith(extension)]
    
    def __repr__(self) -> str:
        return f"FirmwareData(items={len(self.items)}, md5='{self.md5_hash[:8]}...')"


class FirmwareParser:
    """
    Firmware file parser
    
    Supports:
    - TAR archives
    - TAR.MD5 archives (Samsung format)
    - BIN files
    - Gzip compressed files
    - LZ4 compressed files
    """
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.verifier = CryptoVerifier(verbose=verbose)
    
    def log(self, message: str):
        """Print log message if verbose"""
        if self.verbose:
            print(f"[FirmwareParser] {message}")
    
    def parse(self, firmware_path: str, verify_hash: bool = True) -> FirmwareData:
        """
        Parse firmware file
        
        Args:
            firmware_path: Path to firmware file
            verify_hash: Whether to verify MD5 hash
            
        Returns:
            FirmwareData object
        """
        if not os.path.exists(firmware_path):
            raise OdinFirmwareError(f"Firmware file not found: {firmware_path}")
        
        self.log(f"Parsing firmware: {firmware_path}")
        
        # Determine firmware type
        if firmware_path.endswith(".tar.md5"):
            return self._parse_tar_md5(firmware_path, verify_hash)
        elif firmware_path.endswith(".tar"):
            return self._parse_tar(firmware_path)
        elif firmware_path.endswith(".tar.gz") or firmware_path.endswith(".tgz"):
            return self._parse_tar_gz(firmware_path)
        elif firmware_path.endswith(".bin"):
            return self._parse_bin(firmware_path)
        else:
            # Try to detect format
            return self._parse_auto_detect(firmware_path)
    
    def _parse_tar_md5(self, firmware_path: str, verify_hash: bool = True, lazy_load_threshold: int = 50 * 1024 * 1024) -> FirmwareData:
        """Parse TAR.MD5 file (Samsung format) - memory efficient"""
        self.log("Parsing TAR.MD5 file...")
        
        # Get file size first
        file_size = os.path.getsize(firmware_path)
        self.log(f"File size: {file_size:,} bytes ({file_size / (1024*1024):.1f} MB)")
        
        # Read last 512 bytes to find MD5 line
        md5_hash = ""
        with open(firmware_path, "rb") as f:
            if file_size > 512:
                f.seek(-512, 2)  # Seek to 512 bytes from end
                tail = f.read()
                
                # Find MD5 line (format: "hash  filename\n")
                # The tail might not have \n, so also check the whole string
                tail_str = tail.decode('ascii', errors='ignore')
                
                # Look for MD5 pattern: 32 hex chars followed by spaces
                import re
                md5_pattern = r'([0-9a-fA-F]{32})\s+'
                match = re.search(md5_pattern, tail_str)
                if match:
                    md5_hash = match.group(1)
                    self.log(f"Found MD5 hash: {md5_hash}")
        
        # Calculate TAR size (excluding MD5 line)
        # MD5 line format: "hash  filename\n" (variable length, typically 100-150 bytes)
        # TAR is padded with zeros before MD5 line
        tar_size = file_size
        if md5_hash:
            # Find where MD5 line starts by reading backwards
            with open(firmware_path, 'rb') as f:
                f.seek(-512, 2)
                tail = f.read()
                # Find the MD5 line
                for line in tail.split(b'\n'):
                    if md5_hash.encode('ascii') in line:
                        # TAR ends before this line
                        md5_line_offset = tail.find(line)
                        tar_size = file_size - (512 - md5_line_offset)
                        self.log(f"TAR size: {tar_size} bytes (MD5 line at offset {tar_size})")
                        break
        
        # Verify MD5 using streaming (memory efficient) - optional for large files
        if verify_hash and md5_hash and file_size < 500 * 1024 * 1024:  # Only verify if < 500MB
            self.log("Verifying MD5 hash...")
            
            import hashlib
            md5 = hashlib.md5()
            with open(firmware_path, 'rb') as f:
                bytes_read = 0
                while bytes_read < tar_size:
                    chunk = f.read(min(65536, tar_size - bytes_read))
                    if not chunk:
                        break
                    md5.update(chunk)
                    bytes_read += len(chunk)
            
            calculated = md5.hexdigest()
            if calculated.lower() != md5_hash.lower():
                raise OdinFirmwareError(f"MD5 verification failed")
            self.log("✓ MD5 verified")
        elif verify_hash and md5_hash:
            self.log("Skipping MD5 verification (file too large)")
        
        # Parse TAR directly from file using a limited size view
        tar_size = file_size - (32 if md5_hash else 0)
        
        # Create a file-like object that only reads up to tar_size
        class LimitedFileReader:
            def __init__(self, path, max_size):
                self.f = open(path, 'rb')
                self.max_size = max_size
                self.bytes_read = 0
            
            def read(self, size=-1):
                if self.bytes_read >= self.max_size:
                    return b''
                if size == -1:
                    size = self.max_size - self.bytes_read
                else:
                    size = min(size, self.max_size - self.bytes_read)
                data = self.f.read(size)
                self.bytes_read += len(data)
                return data
            
            def close(self):
                self.f.close()
            
            def __enter__(self):
                return self
            
            def __exit__(self, *args):
                self.close()
        
        # Parse TAR without loading all into memory
        # Use lazy loading for large files
        with LimitedFileReader(firmware_path, tar_size) as limited_file:
            firmware_data = self._parse_tar_from_fileobj(limited_file, 
                                                          source_path=firmware_path,
                                                          lazy_load_threshold=lazy_load_threshold,
                                                          is_tar_md5=True,
                                                          md5_hash=md5_hash)
        
        firmware_data.md5_hash = md5_hash
        
        return firmware_data
    
    def _parse_tar(self, firmware_path: str) -> FirmwareData:
        """Parse TAR file"""
        self.log("Parsing TAR file...")
        
        # Parse directly from file with lazy loading
        with open(firmware_path, "rb") as f:
            return self._parse_tar_from_fileobj(f, source_path=firmware_path)
    
    def _parse_tar_from_fileobj(self, fileobj, source_path: Optional[str] = None, lazy_load_threshold: int = 50 * 1024 * 1024, is_tar_md5: bool = False, md5_hash: str = "") -> FirmwareData:
        """
        Parse TAR from file object (memory efficient with lazy loading)
        
        Args:
            fileobj: File object to read from
            source_path: Path to source TAR file (for lazy loading)
            lazy_load_threshold: Files larger than this (bytes) will be lazy-loaded (default 50MB)
        """
        firmware_data = FirmwareData()
        
        try:
            # Open TAR directly from file object
            tar_file = tarfile.open(fileobj=fileobj, mode='r|')  # Stream mode
            
            for member in tar_file:
                if member.isfile():
                    self.log(f"Found file: {member.name} ({member.size} bytes)")
                    
                    # Extract file data
                    file_obj = tar_file.extractfile(member)
                    if file_obj is None:
                        continue
                    
                    # For large files, use lazy loading to avoid memory exhaustion
                    use_lazy_load = (member.size > lazy_load_threshold and source_path is not None)
                    
                    if use_lazy_load:
                        # Only read header for type detection
                        self.log(f"  Using lazy loading for large file: {member.name}")
                        header = file_obj.read(min(1024, member.size))
                        file_type = self._detect_file_type(header)
                        
                        # Create firmware info without loading full data
                        info = FirmwareInfo(
                            filename=os.path.basename(member.name),
                            size=member.size,
                            file_type=file_type
                        )
                        
                        # Check compression from header
                        if header.startswith(GZIP_SIGNATURE):
                            info.is_compressed = True
                            info.compression_type = "gzip"
                            info.compressed_size = member.size
                        elif header.startswith(LZ4_SIGNATURE):
                            info.is_compressed = True
                            info.compression_type = "lz4"
                            info.compressed_size = member.size
                            self._parse_lz4_header(header, info)
                        
                        # Create firmware item with lazy loading
                        item = FirmwareItem(
                            info=info,
                            data=b"",  # Empty - will be loaded on demand
                            _source_path=source_path,
                            _tar_member_name=member.name,
                            _lazy_load=True
                        )
                    else:
                        # Small file - load immediately
                        file_data = file_obj.read()
                        
                        # Create firmware info
                        info = FirmwareInfo(
                            filename=os.path.basename(member.name),
                            size=member.size,
                            file_type=self._detect_file_type(file_data[:1024] if len(file_data) > 1024 else file_data)
                        )
                        
                        # Check if compressed
                        if file_data.startswith(GZIP_SIGNATURE):
                            info.is_compressed = True
                            info.compression_type = "gzip"
                            info.compressed_size = len(file_data)
                        elif file_data.startswith(LZ4_SIGNATURE):
                            info.is_compressed = True
                            info.compression_type = "lz4"
                            info.compressed_size = len(file_data)
                            self._parse_lz4_header(file_data, info)
                        
                        # Create firmware item with data
                        item = FirmwareItem(info=info, data=file_data)
                    
                    firmware_data.items.append(item)
            
            tar_file.close()
            
        except MemoryError:
            raise OdinFirmwareError("Out of memory - firmware file too large (try reducing lazy_load_threshold)")
        except Exception as e:
            raise OdinFirmwareError(f"Failed to parse TAR: {e}")
        
        # Create MD5 header image for Samsung devices
        # Device uses this to validate the firmware package
        if is_tar_md5 and md5_hash and len(md5_hash) == 32:
            try:
                self.log(f"Creating md5.img from hash: {md5_hash}")
                
                # Create md5.img as binary MD5 (16 bytes)
                md5_binary = bytes.fromhex(md5_hash)
                
                # Create md5hdr firmware item
                md5_info = FirmwareInfo(
                    filename="md5.img",
                    size=len(md5_binary),
                    file_type="bin",
                    partition_id=1  # md5hdr partition
                )
                
                md5_item = FirmwareItem(info=md5_info, data=md5_binary)
                
                # Insert at beginning so it's flashed first!
                firmware_data.items.insert(0, md5_item)
                self.log(f"✓ Created md5.img ({len(md5_binary)} bytes) for md5hdr partition")
            except Exception as e:
                self.log(f"Warning: Could not create MD5 header: {e}")
        
        self.log(f"Parsed {len(firmware_data.items)} firmware items")
        return firmware_data
    
    def _parse_tar_gz(self, firmware_path: str) -> FirmwareData:
        """Parse gzip compressed TAR file"""
        self.log("Parsing TAR.GZ file...")
        
        with gzip.open(firmware_path, "rb") as f:
            tar_data = f.read()
        
        return self._parse_tar_data(tar_data)
    
    def _parse_tar_data(self, tar_data: bytes) -> FirmwareData:
        """Parse TAR data from bytes"""
        firmware_data = FirmwareData()
        
        try:
            # Create TAR file object from bytes
            tar_file = tarfile.open(fileobj=io.BytesIO(tar_data))
            
            for member in tar_file.getmembers():
                if member.isfile():
                    self.log(f"Found file: {member.name} ({member.size} bytes)")
                    
                    # For large files, only read first few bytes to detect type
                    file_obj = tar_file.extractfile(member)
                    
                    # Read first 1KB for type detection
                    header = file_obj.read(min(1024, member.size))
                    file_type = self._detect_file_type(header)
                    
                    # Now read the rest
                    remaining = file_obj.read()
                    file_data = header + remaining
                    
                    # Create firmware info
                    info = FirmwareInfo(
                        filename=os.path.basename(member.name),
                        size=member.size,
                        file_type=file_type
                    )
                    
                    # Check if compressed (only check header)
                    if header.startswith(GZIP_SIGNATURE):
                        info.is_compressed = True
                        info.compression_type = "gzip"
                        info.compressed_size = len(file_data)
                    elif header.startswith(LZ4_SIGNATURE):
                        info.is_compressed = True
                        info.compression_type = "lz4"
                        info.compressed_size = len(file_data)
                        self._parse_lz4_header(header, info)
                    
                    # Create firmware item
                    item = FirmwareItem(info=info, data=file_data)
                    firmware_data.items.append(item)
            
            tar_file.close()
            
        except MemoryError:
            raise OdinFirmwareError("Out of memory - firmware file too large")
        except Exception as e:
            raise OdinFirmwareError(f"Failed to parse TAR data: {e}")
        
        self.log(f"Parsed {len(firmware_data.items)} firmware items")
        return firmware_data
    
    def _parse_bin(self, firmware_path: str) -> FirmwareData:
        """Parse BIN file"""
        self.log("Parsing BIN file...")
        
        firmware_data = FirmwareData()
        
        with open(firmware_path, "rb") as f:
            data = f.read()
        
        filename = os.path.basename(firmware_path)
        
        info = FirmwareInfo(
            filename=filename,
            size=len(data),
            file_type=self._detect_file_type(data)
        )
        
        item = FirmwareItem(info=info, data=data)
        firmware_data.items.append(item)
        
        return firmware_data
    
    def _parse_auto_detect(self, firmware_path: str) -> FirmwareData:
        """Auto-detect firmware format"""
        self.log("Auto-detecting firmware format...")
        
        with open(firmware_path, "rb") as f:
            header = f.read(8)
        
        # Check signatures
        if GZIP_SIGNATURE in header:
            self.log("Detected GZIP format")
            return self._parse_tar_gz(firmware_path)
        elif TAR_SIGNATURE in header:
            self.log("Detected TAR format")
            return self._parse_tar(firmware_path)
        else:
            self.log("Defaulting to BIN format")
            return self._parse_bin(firmware_path)
    
    def _detect_file_type(self, data: bytes) -> str:
        """Detect file type from data"""
        if len(data) < 4:
            return "unknown"
        
        # Check common signatures
        if data.startswith(GZIP_SIGNATURE):
            return "gzip"
        elif data.startswith(LZ4_SIGNATURE):
            return "lz4"
        elif data.startswith(b"\x7FELF"):
            return "elf"
        elif data.startswith(b"ANDROID!"):
            return "android_boot"
        elif data.startswith(b"PK\x03\x04"):
            return "zip"
        elif TAR_SIGNATURE in data[:512]:
            return "tar"
        else:
            return "binary"
    
    def _parse_lz4_header(self, data: bytes, info: FirmwareInfo):
        """Parse LZ4 frame header"""
        try:
            # LZ4 frame format header
            if len(data) < 7:
                return
            
            magic = struct.unpack("<I", data[0:4])[0]
            if magic != 0x184D2204:  # LZ4 magic number
                return
            
            flg = data[4]
            bd = data[5]
            
            # Block size
            block_size_id = (bd >> 4) & 0x07
            block_sizes = [0, 0, 0, 0, 64*1024, 256*1024, 1024*1024, 4*1024*1024]
            info.lz4_block_size = block_sizes[block_size_id] if block_size_id < len(block_sizes) else 0
            
            # Checksum flag
            info.lz4_has_checksum = (flg & 0x04) != 0
            
            self.log(f"LZ4 block size: {info.lz4_block_size}, has checksum: {info.lz4_has_checksum}")
            
        except Exception as e:
            self.log(f"Failed to parse LZ4 header: {e}")
    
    def decompress_item(self, item: FirmwareItem, stream: bool = True) -> bytes:
        """
        Decompress firmware item data
        
        Args:
            item: Firmware item to decompress
            stream: Use streaming decompression to avoid memory exhaustion (default: True)
            
        Returns:
            Decompressed data
        """
        if not item.info.is_compressed:
            return item.data
        
        try:
            if stream and len(item.data) > 50 * 1024 * 1024:  # Use streaming for files > 50MB
                return self._stream_decompress_item(item)
            else:
                # Small files - use direct decompression
                if item.info.compression_type == "gzip":
                    self.log(f"Decompressing gzip: {item.filename}")
                    return gzip.decompress(item.data)
                
                elif item.info.compression_type == "lz4":
                    self.log(f"Decompressing lz4: {item.filename}")
                    return lz4.frame.decompress(item.data)
                
                else:
                    raise OdinFirmwareError(f"Unsupported compression: {item.info.compression_type}")
        
        except Exception as e:
            raise OdinFirmwareError(f"Decompression failed: {e}")
    
    def _stream_decompress_item(self, item: FirmwareItem) -> bytes:
        """
        Stream decompress item to avoid memory issues with large files
        """
        self.log(f"Stream decompressing {item.info.compression_type}: {item.filename}")
        
        compressed_data = item.data
        compression_type = item.info.compression_type
        
        if compression_type == "gzip":
            # GZIP streaming decompression
            decompressed_chunks = []
            compressed_stream = io.BytesIO(compressed_data)
            
            with gzip.GzipFile(fileobj=compressed_stream, mode='rb') as gz:
                chunk_size = 64 * 1024 * 1024  # 64MB chunks
                while True:
                    chunk = gz.read(chunk_size)
                    if not chunk:
                        break
                    decompressed_chunks.append(chunk)
            
            return b''.join(decompressed_chunks)
        
        elif compression_type == "lz4":
            # LZ4 streaming decompression
            decompressed_chunks = []
            
            try:
                dctx = lz4.frame.create_decompression_context()
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
                            decompressed_chunks.append(decompressed_chunk)
                        
                        compressed_offset += bytes_read if bytes_read > 0 else len(compressed_chunk)
                        
                        if bytes_read == 0 and len(decompressed_chunk) == 0:
                            compressed_offset = end_offset
                            
                    except lz4.frame.Lz4FrameEOFError:
                        break
                
                return b''.join(decompressed_chunks)
                
            except AttributeError:
                # Fallback if streaming API not available
                return lz4.frame.decompress(compressed_data)
        
        else:
            raise OdinFirmwareError(f"Unsupported compression: {compression_type}")
    
    def extract_gzip_file(self, data: bytes, stream: bool = True) -> bytes:
        """
        Extract gzip compressed data
        
        Args:
            data: Compressed data
            stream: Use streaming for large files (default: True)
        """
        try:
            if stream and len(data) > 50 * 1024 * 1024:
                # Stream decompress for large files
                decompressed_chunks = []
                compressed_stream = io.BytesIO(data)
                
                with gzip.GzipFile(fileobj=compressed_stream, mode='rb') as gz:
                    chunk_size = 64 * 1024 * 1024  # 64MB chunks
                    while True:
                        chunk = gz.read(chunk_size)
                        if not chunk:
                            break
                        decompressed_chunks.append(chunk)
                
                return b''.join(decompressed_chunks)
            else:
                return gzip.decompress(data)
        except Exception as e:
            raise OdinFirmwareError(f"GZIP extraction failed: {e}")

