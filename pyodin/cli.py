#!/usr/bin/env python3
"""
PyOdin Command-Line Interface

Command-line tool for firmware flashing operations.
"""

import argparse
import sys
import os
from typing import Optional

# Handle both direct execution and module import
try:
    from . import __version__
    from .flasher import OdinFlasher
    from .download_engine import DownloadProgress
    from .pit import PitParser
    from .exceptions import OdinException
except ImportError:
    # Running as script directly, add parent to path
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from pyodin import __version__
    from pyodin.flasher import OdinFlasher
    from pyodin.download_engine import DownloadProgress
    from pyodin.pit import PitParser
    from pyodin.exceptions import OdinException


def progress_callback(progress: DownloadProgress):
    """Print progress information"""
    bar_length = 40
    filled = int(bar_length * progress.percentage / 100)
    bar = '█' * filled + '░' * (bar_length - filled)
    
    speed_mb = progress.speed_bps / (1024 * 1024)
    
    print(f"\r[{bar}] {progress.percentage:.1f}% | {progress.current_file} | {speed_mb:.2f} MB/s", end='', flush=True)


def cmd_list_devices(args):
    """List connected devices"""
    print("Searching for Samsung devices in Download mode...")
    
    flasher = OdinFlasher(verbose=args.verbose)
    devices = flasher.list_devices()
    
    if not devices:
        print("No devices found.")
        return 1
    
    print(f"\nFound {len(devices)} device(s):\n")
    
    for i, device in enumerate(devices):
        print(f"[{i}] {device.product}")
        print(f"    Manufacturer: {device.manufacturer}")
        print(f"    Serial: {device.serial_number}")
        print(f"    VID:PID = 0x{device.vendor_id:04X}:0x{device.product_id:04X}")
        print()
    
    return 0


def cmd_flash(args):
    """Flash firmware to device"""
    if not os.path.exists(args.firmware):
        print(f"Error: Firmware file not found: {args.firmware}")
        return 1
    
    print(f"PyOdin v{__version__} - Firmware Flasher")
    print("=" * 60)
    
    try:
        flasher = OdinFlasher(verbose=args.verbose)
        
        # Load firmware
        print(f"\n[1/4] Loading firmware: {args.firmware}")
        firmware_data = flasher.load_firmware(args.firmware, verify_hash=not args.no_verify)
        print(f"      Loaded {len(firmware_data.items)} firmware items")
        
        if firmware_data.md5_hash:
            print(f"      MD5: {firmware_data.md5_hash}")
        
        # Load PIT if provided
        pit_data = None
        if args.pit:
            print(f"\n      Loading PIT: {args.pit}")
            with open(args.pit, 'rb') as f:
                pit_data = f.read()
        
        # Connect to device
        print(f"\n[2/4] Connecting to device...")
        device_info = flasher.connect_device()
        print(f"      Connected: {device_info.model_name or device_info.product}")
        print(f"      Protocol Version: {device_info.protocol_version}")
        
        # Confirm flashing
        if not args.yes:
            print(f"\n      ⚠️  WARNING: This will flash firmware to your device!")
            print(f"      Device may be bricked if interrupted.")
            response = input("\n      Continue? (yes/no): ")
            if response.lower() not in ['yes', 'y']:
                print("      Flashing cancelled.")
                flasher.disconnect_device()
                return 0
        
        # Flash firmware
        print(f"\n[3/4] Flashing firmware...")
        print()
        
        success = flasher.flash(
            firmware_data,
            pit_data=pit_data,
            reboot=not args.no_reboot,
            reboot_to_download=False,  # Always reboot to system, not download mode
            progress_callback=progress_callback
        )
        
        print()  # New line after progress bar
        
        if success:
            print(f"\n[4/4] ✓ Firmware flashed successfully!")
            
            if not args.no_reboot:
                print(f"      Device is rebooting to system...")
            
            flasher.disconnect_device()
            return 0
        else:
            print(f"\n[4/4] ✗ Flashing failed!")
            flasher.disconnect_device()
            return 1
    
    except OdinException as e:
        print(f"\nError: {e.message}")
        return 1
    except KeyboardInterrupt:
        print(f"\n\nInterrupted by user.")
        return 1
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def cmd_dump_pit(args):
    """Dump PIT from device"""
    print("Dumping PIT from device...")
    
    try:
        flasher = OdinFlasher(verbose=args.verbose)
        
        # Connect to device
        print("Connecting to device...")
        device_info = flasher.connect_device()
        print(f"Connected: {device_info.model_name or device_info.product}")
        
        # Dump PIT
        print("Reading PIT...")
        pit_data = flasher.dump_pit()
        
        # Save PIT
        output_file = args.output or "dump.pit"
        with open(output_file, 'wb') as f:
            f.write(pit_data)
        
        print(f"PIT saved to: {output_file} ({len(pit_data)} bytes)")
        
        # Parse and display PIT info
        if args.verbose:
            pit_parser = PitParser(verbose=True)
            pit = pit_parser.parse(pit_data)
            pit_parser.dump_info(pit)
        
        flasher.disconnect_device()
        return 0
    
    except OdinException as e:
        print(f"Error: {e.message}")
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}")
        return 1


def cmd_parse_firmware(args):
    """Parse and display firmware information"""
    if not os.path.exists(args.firmware):
        print(f"Error: Firmware file not found: {args.firmware}")
        return 1
    
    print(f"Parsing firmware: {args.firmware}\n")
    
    try:
        flasher = OdinFlasher(verbose=args.verbose)
        firmware_data = flasher.load_firmware(args.firmware, verify_hash=False)
        
        print(f"Firmware Information:")
        print(f"  MD5 Hash: {firmware_data.md5_hash or 'N/A'}")
        print(f"  Items: {len(firmware_data.items)}")
        print(f"\nFirmware Items:\n")
        
        total_size = 0
        for i, item in enumerate(firmware_data.items):
            print(f"  [{i}] {item.filename}")
            print(f"      Size: {item.size:,} bytes ({item.size / (1024*1024):.2f} MB)")
            print(f"      Type: {item.info.file_type}")
            
            if item.info.is_compressed:
                print(f"      Compression: {item.info.compression_type}")
                print(f"      Compressed Size: {item.info.compressed_size:,} bytes")
            
            if item.info.checksum:
                print(f"      Checksum: {item.info.checksum}")
            
            print()
            total_size += item.size
        
        print(f"Total Size: {total_size:,} bytes ({total_size / (1024*1024):.2f} MB)")
        
        return 0
    
    except OdinException as e:
        print(f"Error: {e.message}")
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}")
        return 1


def cmd_parse_pit(args):
    """Parse and display PIT information"""
    if not os.path.exists(args.pit):
        print(f"Error: PIT file not found: {args.pit}")
        return 1
    
    print(f"Parsing PIT: {args.pit}\n")
    
    try:
        pit_parser = PitParser(verbose=args.verbose)
        
        with open(args.pit, 'rb') as f:
            pit_data = f.read()
        
        pit = pit_parser.parse(pit_data)
        pit_parser.dump_info(pit)
        
        return 0
    
    except Exception as e:
        print(f"Error: {e}")
        return 1


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description=f"PyOdin v{__version__} - Samsung Firmware Flasher",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('--version', action='version',
                       version=f'PyOdin v{__version__}')
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # List devices command
    list_parser = subparsers.add_parser('list', help='List connected devices')
    list_parser.set_defaults(func=cmd_list_devices)
    
    # Flash command
    flash_parser = subparsers.add_parser('flash', help='Flash firmware to device')
    flash_parser.add_argument('firmware', help='Firmware file (TAR, TAR.MD5, BIN)')
    flash_parser.add_argument('-p', '--pit', help='PIT file (optional)')
    flash_parser.add_argument('-y', '--yes', action='store_true',
                             help='Skip confirmation prompt')
    flash_parser.add_argument('--no-verify', action='store_true',
                             help='Skip hash verification')
    flash_parser.add_argument('--no-reboot', action='store_true',
                             help='Do not reboot device after flashing')
    flash_parser.set_defaults(func=cmd_flash)
    
    # Dump PIT command
    dump_parser = subparsers.add_parser('dump-pit', help='Dump PIT from device')
    dump_parser.add_argument('-o', '--output', help='Output file (default: dump.pit)')
    dump_parser.set_defaults(func=cmd_dump_pit)
    
    # Parse firmware command
    parse_fw_parser = subparsers.add_parser('parse-firmware',
                                            help='Parse and display firmware info')
    parse_fw_parser.add_argument('firmware', help='Firmware file')
    parse_fw_parser.set_defaults(func=cmd_parse_firmware)
    
    # Parse PIT command
    parse_pit_parser = subparsers.add_parser('parse-pit',
                                             help='Parse and display PIT info')
    parse_pit_parser.add_argument('pit', help='PIT file')
    parse_pit_parser.set_defaults(func=cmd_parse_pit)
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    return args.func(args)


if __name__ == '__main__':
    sys.exit(main())
