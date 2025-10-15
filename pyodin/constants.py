"""
Constants and opcodes for Odin protocol
"""

# Samsung USB Vendor ID
SAMSUNG_VENDOR_ID = 0x04E8

# Samsung Product IDs for Download Mode
SAMSUNG_DOWNLOAD_MODE_PIDS = [
    0x685D,  # Download mode
    0x68C3,  # Newer devices
]

# USB Endpoints
USB_ENDPOINT_OUT = 0x02
USB_ENDPOINT_IN = 0x81

# USB Transfer sizes
USB_PACKET_SIZE = 512
USB_MAX_PACKET_SIZE = 0x200000  # 2MB

# Odin Protocol Commands/Requests
class OdinCommand:
    """Odin protocol command opcodes"""
    HANDSHAKE = 0x64
    SETUP = 0x65
    PIT_TRANSFER = 0x66
    FILE_TRANSFER = 0x67
    DUMP = 0x68
    END_SESSION = 0x69
    REBOOT = 0x6A
    
    # Sub-commands
    REQUEST_DEVICEINFO = 0x00
    REQUEST_PITINFO = 0x01
    REQUEST_CHIPINFO = 0x02
    REQUEST_DUMP = 0x03
    
    # Responses
    RESPONSE_PASS = 0x00
    RESPONSE_FAIL = 0x01
    RESPONSE_DATA = 0x02


class OdinPacketType:
    """Odin packet types"""
    REQUEST = 0x00
    DATA = 0x01
    RESPONSE = 0x02
    

# Protocol constants
ODIN_PROTOCOL_VERSION = 4
ODIN_MAGIC = b"ODIN"
ODIN_PACKET_HEADER_SIZE = 8

# Firmware file signatures
TAR_SIGNATURE = b"\x75\x73\x74\x61\x72"  # "ustar"
GZIP_SIGNATURE = b"\x1F\x8B"
LZ4_SIGNATURE = b"\x04\x22\x4D\x18"
MD5_FILE_EXTENSION = ".md5"

# PIT (Partition Information Table)
PIT_MAGIC = 0x12349876
PIT_HEADER_SIZE = 28
PIT_ENTRY_SIZE = 132

# Transfer modes
class TransferMode:
    """Transfer mode flags"""
    NORMAL = 0x00
    COMPRESSED = 0x01
    ENCRYPTED = 0x02


# Device response codes
class DeviceResponse:
    """Device response codes"""
    SUCCESS = 0x00
    FAIL = 0x01
    VERIFY_FAIL = 0x02
    WRITE_PROTECTION = 0x03
    INVALID_DATA = 0x04


# Timeouts (in seconds) - EXACT values from odin4.c
TIMEOUT_CONNECT = 5
TIMEOUT_HANDSHAKE = 60  # odin4.c line 12607: 60000ms
TIMEOUT_TRANSFER = 60  # odin4.c line 12607: 60000ms for data
TIMEOUT_WRITE = 60  # odin4.c line 12607: 60000ms
TIMEOUT_READ = 60  # odin4.c line 12613: 60000ms

# Buffer sizes
BUFFER_SIZE = 512 * 1024  # 512KB
MAX_FIRMWARE_SIZE = 8 * 1024 * 1024 * 1024  # 8GB

# Partition types
class PartitionType:
    """Partition type identifiers"""
    BOOTLOADER = 0x00
    PIT = 0x01
    KERNEL = 0x02
    RECOVERY = 0x03
    SYSTEM = 0x04
    CACHE = 0x05
    USERDATA = 0x06
    MODEM = 0x07
    
    NAMES = {
        0x00: "BOOTLOADER",
        0x01: "PIT",
        0x02: "KERNEL",
        0x03: "RECOVERY",
        0x04: "SYSTEM",
        0x05: "CACHE",
        0x06: "USERDATA",
        0x07: "MODEM",
    }


# Known partition names to types mapping
PARTITION_NAME_MAP = {
    "boot.img": PartitionType.KERNEL,
    "recovery.img": PartitionType.RECOVERY,
    "system.img": PartitionType.SYSTEM,
    "cache.img": PartitionType.CACHE,
    "userdata.img": PartitionType.USERDATA,
    "modem.bin": PartitionType.MODEM,
    "sboot.bin": PartitionType.BOOTLOADER,
}

# Firmware file extensions
FIRMWARE_EXTENSIONS = [
    ".tar",
    ".tar.md5",
    ".tar.gz",
    ".bin",
    ".img",
]

# Crypto constants
MD5_HASH_SIZE = 16
SHA256_HASH_SIZE = 32
RSA_KEY_SIZE = 2048

# Progress callback intervals
PROGRESS_UPDATE_INTERVAL = 0.5  # seconds



