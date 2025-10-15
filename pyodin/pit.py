"""
PIT (Partition Information Table) handling

Parses and manages Samsung PIT files.
"""

import struct
from typing import List, Optional
from dataclasses import dataclass

from .exceptions import OdinInvalidDataError
from .constants import PIT_MAGIC, PIT_HEADER_SIZE, PIT_ENTRY_SIZE


@dataclass
class PitEntry:
    """Single PIT partition entry"""
    binary_type: int = 0
    device_type: int = 0
    partition_id: int = 0
    partition_type: int = 0
    filesystem: int = 0
    start_block: int = 0
    num_blocks: int = 0
    file_offset: int = 0
    file_size: int = 0
    partition_name: str = ""
    flash_filename: str = ""
    fota_filename: str = ""
    
    def __repr__(self) -> str:
        return f"PitEntry(name='{self.partition_name}', id={self.partition_id}, blocks={self.num_blocks})"


@dataclass
class PitData:
    """Complete PIT data"""
    magic: int = 0
    count: int = 0
    entries: List[PitEntry] = None
    
    def __post_init__(self):
        if self.entries is None:
            self.entries = []
    
    def get_entry_by_name(self, name: str) -> Optional[PitEntry]:
        """Get PIT entry by partition name"""
        for entry in self.entries:
            if entry.partition_name == name:
                return entry
        return None
    
    def get_entry_by_id(self, partition_id: int) -> Optional[PitEntry]:
        """Get PIT entry by partition ID"""
        for entry in self.entries:
            if entry.partition_id == partition_id:
                return entry
        return None
    
    def __repr__(self) -> str:
        return f"PitData(entries={len(self.entries)})"


class PitParser:
    """
    PIT file parser
    
    Parses Samsung PIT (Partition Information Table) files.
    """
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
    
    def log(self, message: str):
        """Print log message if verbose"""
        if self.verbose:
            print(f"[PitParser] {message}")
    
    def parse(self, pit_data: bytes) -> PitData:
        """
        Parse PIT data
        
        Args:
            pit_data: Raw PIT file data
            
        Returns:
            PitData object
        """
        if len(pit_data) < PIT_HEADER_SIZE:
            raise OdinInvalidDataError("PIT data too small")
        
        self.log(f"Parsing PIT data ({len(pit_data)} bytes)...")
        
        # Parse header
        magic, count, dummy1, dummy2, dummy3 = struct.unpack("<IIIII", pit_data[0:20])
        
        if magic != PIT_MAGIC:
            raise OdinInvalidDataError(f"Invalid PIT magic: 0x{magic:08X} (expected 0x{PIT_MAGIC:08X})")
        
        self.log(f"PIT magic: 0x{magic:08X}, entries: {count}")
        
        pit = PitData(magic=magic, count=count)
        
        # Parse entries
        offset = PIT_HEADER_SIZE
        
        for i in range(count):
            if offset + PIT_ENTRY_SIZE > len(pit_data):
                self.log(f"Warning: Truncated PIT data at entry {i}")
                break
            
            entry_data = pit_data[offset:offset + PIT_ENTRY_SIZE]
            entry = self._parse_entry(entry_data)
            pit.entries.append(entry)
            
            offset += PIT_ENTRY_SIZE
            
            self.log(f"  Entry {i}: {entry.partition_name} (ID={entry.partition_id}, blocks={entry.num_blocks})")
        
        self.log(f"Parsed {len(pit.entries)} PIT entries")
        
        return pit
    
    def _parse_entry(self, entry_data: bytes) -> PitEntry:
        """Parse single PIT entry"""
        # PIT entry structure (132 bytes):
        # - binary_type (4)
        # - device_type (4)
        # - partition_id (4)
        # - partition_type (4)
        # - filesystem (4)
        # - start_block (4)
        # - num_blocks (4)
        # - file_offset (4)
        # - file_size (4)
        # - partition_name (32)
        # - flash_filename (32)
        # - fota_filename (32)
        
        values = struct.unpack("<9I32s32s32s", entry_data[0:132])
        
        entry = PitEntry(
            binary_type=values[0],
            device_type=values[1],
            partition_id=values[2],
            partition_type=values[3],
            filesystem=values[4],
            start_block=values[5],
            num_blocks=values[6],
            file_offset=values[7],
            file_size=values[8],
            partition_name=values[9].decode('utf-8', errors='ignore').rstrip('\x00'),
            flash_filename=values[10].decode('utf-8', errors='ignore').rstrip('\x00'),
            fota_filename=values[11].decode('utf-8', errors='ignore').rstrip('\x00')
        )
        
        return entry
    
    def create(self, entries: List[PitEntry]) -> bytes:
        """
        Create PIT data from entries
        
        Args:
            entries: List of PIT entries
            
        Returns:
            Raw PIT data
        """
        self.log(f"Creating PIT data with {len(entries)} entries...")
        
        # Build header
        header = struct.pack("<IIIII",
                            PIT_MAGIC,
                            len(entries),
                            0,  # dummy1
                            0,  # dummy2
                            0)  # dummy3
        
        # Build entries
        entries_data = b""
        for entry in entries:
            entry_data = struct.pack("<9I32s32s32s",
                                     entry.binary_type,
                                     entry.device_type,
                                     entry.partition_id,
                                     entry.partition_type,
                                     entry.filesystem,
                                     entry.start_block,
                                     entry.num_blocks,
                                     entry.file_offset,
                                     entry.file_size,
                                     entry.partition_name.encode('utf-8').ljust(32, b'\x00'),
                                     entry.flash_filename.encode('utf-8').ljust(32, b'\x00'),
                                     entry.fota_filename.encode('utf-8').ljust(32, b'\x00'))
            entries_data += entry_data
        
        # Combine header and entries
        pit_data = header + b'\x00' * 8 + entries_data  # 8 bytes padding after header
        
        self.log(f"Created PIT data ({len(pit_data)} bytes)")
        
        return pit_data
    
    def dump_info(self, pit: PitData):
        """Print PIT information"""
        print(f"\nPIT Information:")
        print(f"  Magic: 0x{pit.magic:08X}")
        print(f"  Entry Count: {pit.count}")
        print(f"\nPartitions:")
        
        for i, entry in enumerate(pit.entries):
            print(f"\n  [{i}] {entry.partition_name}")
            print(f"    Partition ID: {entry.partition_id}")
            print(f"    Type: {entry.partition_type}")
            print(f"    Start Block: {entry.start_block}")
            print(f"    Block Count: {entry.num_blocks}")
            print(f"    Size: {entry.num_blocks * 512} bytes")
            if entry.flash_filename:
                print(f"    Flash File: {entry.flash_filename}")
            if entry.fota_filename:
                print(f"    FOTA File: {entry.fota_filename}")





