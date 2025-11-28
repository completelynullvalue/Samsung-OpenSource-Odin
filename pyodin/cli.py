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
    # Collect all firmware files
    files_to_flash = []
    if args.firmware:
        files_to_flash.append(("Main", args.firmware))
    if args.bl:
        files_to_flash.append(("BL", args.bl))
    if args.ap:
        files_to_flash.append(("AP", args.ap))
    if args.cp:
        files_to_flash.append(("CP", args.cp))
    if args.csc:
        files_to_flash.append(("CSC", args.csc))
    if args.ums:
        files_to_flash.append(("UMS", args.ums))
    
    if not files_to_flash:
        print("Error: No firmware files specified.")
        return 1
        
    # Validate files exist
    for name, path in files_to_flash:
        if not os.path.exists(path):
            print(f"Error: {name} file not found: {path}")
            return 1
    
    print(f"PyOdin v{__version__} - Firmware Flasher")
    print("=" * 60)
    
    # Show security warning if bypass enabled
    if args.bypass_verification:
        print("\n" + "!" * 60)
        print("⚠️  WARNING: BOOTLOADER VERIFICATION BYPASS ENABLED ⚠️")
        print("!" * 60)
        print("This replicates the odin4.c security vulnerability that")
        print("allows flashing unsigned/modified firmware.")
        print("Use at your own risk!")
        print("!" * 60 + "\n")
        
        if not args.yes:
            response = input("Are you SURE you want to bypass verification? (yes/no): ")
            if response.lower() != 'yes':
                print("Aborted.")
                return 1
    
    try:
        flasher = OdinFlasher(verbose=args.verbose, bypass_verification=args.bypass_verification)
        
        # Load firmware(s)
        print(f"\n[1/4] Loading firmware...")
        
        # Create a combined firmware data object
        try:
            from .firmware import FirmwareData
        except ImportError:
            from pyodin.firmware import FirmwareData
        combined_firmware = FirmwareData()
        
        for name, path in files_to_flash:
            print(f"      Loading {name}: {path}")
            fw_data = flasher.load_firmware(path, verify_hash=not args.no_verify)
            print(f"      Loaded {len(fw_data.items)} items")
            
            # Merge items
            combined_firmware.items.extend(fw_data.items)
            
            # Use last MD5 found (not ideal but matches Odin behavior roughly)
            if fw_data.md5_hash:
                combined_firmware.md5_hash = fw_data.md5_hash
                print(f"      MD5: {fw_data.md5_hash}")
        
        if args.bypass_verification:
            print(f"      [BYPASS] Signature verification: DISABLED")
        
        # Set option_lock if requested (disables phone verification)
        if args.option_lock:
            combined_firmware.option_lock = True
            print(f"      Option Lock: Enabled (phone verification disabled)")
        
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
        
        # Use the flash method which handles the full sequence
        flasher.flash(combined_firmware, reboot=not args.no_reboot, progress_callback=progress_callback)
        
        print("\n✨ Flashing Complete! ✨")
        return 0
        
    except OdinException as e:
        print(f"\n❌ Error: {e.message}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1
    except KeyboardInterrupt:
        print("\n\n⚠️  Flashing interrupted by user!")
        return 1
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
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


def cmd_oem_unlock(args):
    """Send OEM bootloader unlock command"""
    print("=" * 60)
    print("WARNING: OEM BOOTLOADER UNLOCK")
    print("=" * 60)
    print("This command will:")
    print("  - Permanently unlock the bootloader")
    print("  - Wipe all user data (factory reset)")
    print("  - May void warranty")
    print("  - May brick device if not supported")
    print("")
    
    if not args.force:
        response = input("Type 'YES' to confirm: ")
        if response != "YES":
            print("Cancelled.")
            return 0
    
    try:
        flasher = OdinFlasher(verbose=args.verbose)
        
        # Connect to device
        print("Connecting to device...")
        device_info = flasher.connect_device()
        print(f"Connected: {device_info.model_name or device_info.product}")
        
        # Send OEM unlock command
        print("Sending OEM unlock command...")
        success = flasher.oem_unlock()
        
        flasher.disconnect_device()
        
        if success:
            print("✓ OEM unlock command sent successfully")
            print("Device may reboot. Check device screen for confirmation.")
            return 0
        else:
            print("✗ OEM unlock command failed or not supported")
            return 1
    
    except OdinException as e:
        print(f"Error: {e.message}")
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}")
        return 1


def cmd_enumerate(args):
    """Enumerate accepted parameters for a command"""
    try:
        flasher = OdinFlasher(verbose=args.verbose)
        
        # Connect to device
        print(f"Connecting to device...")
        device_info = flasher.connect_device()
        print(f"Connected: {device_info.model_name or device_info.product}\n")
        
        # Create parameter range
        param_range = range(args.start, args.end)
        print(f"Enumerating parameters for command {args.cmd}/{args.sub}")
        print(f"  Range: {args.start} to {args.end-1} ({len(param_range)} values)")
        print(f"  Timeout: {args.timeout}s per probe\n")
        
        # Run enumeration
        results = flasher.enumerate_command_params(
            cmd=args.cmd,
            sub=args.sub,
            param_range=param_range,
            probe_timeout=args.timeout,
            verbose=not args.quiet
        )
        
        flasher.disconnect_device()
        
        # Print summary
        print("\n" + "=" * 60)
        print("ENUMERATION RESULTS")
        print("=" * 60)
        print(f"Command: {args.cmd}/{args.sub}")
        print(f"\nAccepted parameters ({len(results['accepted'])}):")
        if results['accepted']:
            # Group consecutive values
            accepted = sorted(results['accepted'])
            ranges = []
            start = accepted[0]
            prev = accepted[0]
            for val in accepted[1:]:
                if val == prev + 1:
                    prev = val
                else:
                    if start == prev:
                        ranges.append(str(start))
                    else:
                        ranges.append(f"{start}-{prev}")
                    start = val
                    prev = val
            if start == prev:
                ranges.append(str(start))
            else:
                ranges.append(f"{start}-{prev}")
            print(f"  {', '.join(ranges)}")
        else:
            print("  (none)")
        
        if results['rejected']:
            print(f"\nRejected parameters ({len(results['rejected'])}):")
            rejected = sorted(results['rejected'])
            print(f"  {', '.join(map(str, rejected[:20]))}{'...' if len(rejected) > 20 else ''}")
        
        if results['unexpected']:
            print(f"\nUnexpected responses ({len(results['unexpected'])}):")
            for param, resp_cmd, resp_data in results['unexpected'][:10]:
                print(f"  param={param}: cmd={resp_cmd}, data={resp_data}")
        
        if results['timeout'] and len(results['timeout']) < 50:
            print(f"\nTimeout parameters ({len(results['timeout'])}):")
            print(f"  {', '.join(map(str, sorted(results['timeout'])[:20]))}{'...' if len(results['timeout']) > 20 else ''}")
        elif results['timeout']:
            print(f"\nTimeout parameters: {len(results['timeout'])} (too many to list)")
        
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
    flash_parser.add_argument('firmware', nargs='?', help='Main firmware file (or use specific slots)')
    flash_parser.add_argument('-b', '--bl', help='Bootloader file')
    flash_parser.add_argument('-a', '--ap', help='AP/System file')
    flash_parser.add_argument('-c', '--cp', help='CP/Modem file')
    flash_parser.add_argument('-s', '--csc', help='CSC file')
    flash_parser.add_argument('-u', '--ums', help='UMS/USERDATA file')
    flash_parser.add_argument('-p', '--pit', help='PIT file (optional)')
    flash_parser.add_argument('-y', '--yes', action='store_true',
                             help='Skip confirmation prompt')
    flash_parser.add_argument('--no-verify', action='store_true',
                             help='Skip hash verification')
    flash_parser.add_argument('--no-reboot', action='store_true',
                             help='Do not reboot device after flashing')
    flash_parser.add_argument('--option-lock', action='store_true',
                             help='Enable option lock (disables phone verification for .BIN files)')
    flash_parser.add_argument('--bypass-verification', action='store_true',
                             help='⚠️  BYPASS signature verification (allows unsigned firmware - DANGEROUS!)')
    flash_parser.set_defaults(func=cmd_flash)
    
    # Dump PIT command
    dump_parser = subparsers.add_parser('dump-pit', help='Dump PIT from device')
    dump_parser.add_argument('-o', '--output', help='Output file (default: dump.pit)')
    dump_parser.set_defaults(func=cmd_dump_pit)
    
    # OEM unlock command
    oem_unlock_parser = subparsers.add_parser('oem-unlock',
                                              help='Send OEM bootloader unlock command')
    oem_unlock_parser.add_argument('--force', action='store_true',
                                   help='Skip confirmation prompt')
    oem_unlock_parser.set_defaults(func=cmd_oem_unlock)
    
    # Enumerate command parameters
    enum_parser = subparsers.add_parser('enumerate',
                                        help='Enumerate accepted parameters for a command')
    enum_parser.add_argument('cmd', type=int, help='Command ID (e.g., 100)')
    enum_parser.add_argument('sub', type=int, help='Sub-command ID (e.g., 3)')
    enum_parser.add_argument('--start', type=int, default=0,
                            help='Start parameter value (default: 0)')
    enum_parser.add_argument('--end', type=int, default=256,
                            help='End parameter value (exclusive, default: 256)')
    enum_parser.add_argument('--timeout', type=float, default=2.0,
                            help='Probe timeout in seconds (default: 2.0)')
    enum_parser.add_argument('--quiet', action='store_true',
                            help='Suppress verbose output')
    enum_parser.set_defaults(func=cmd_enumerate)
    
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
