"""
USB device communication for Samsung devices in Download/Odin mode
"""

import usb.core
import usb.util
import time
from typing import Optional, List, Tuple
from dataclasses import dataclass

from .exceptions import OdinUSBError, OdinTimeoutError
from .constants import (
    SAMSUNG_VENDOR_ID,
    SAMSUNG_DOWNLOAD_MODE_PIDS,
    USB_ENDPOINT_OUT,
    USB_ENDPOINT_IN,
    USB_PACKET_SIZE,
    TIMEOUT_READ,
    TIMEOUT_WRITE
)


@dataclass
class DeviceInfo:
    """Samsung device information"""
    vendor_id: int
    product_id: int
    manufacturer: str = ""
    product: str = ""
    serial_number: str = ""
    
    # Device-specific info (from Odin protocol)
    protocol_version: int = 0
    device_id: str = ""
    model_name: str = ""
    firmware_version: str = ""
    chip_id: str = ""
    supports_zlp: bool = False  # Zero-length packet support
    
    def __repr__(self) -> str:
        return f"DeviceInfo(product='{self.product}', model='{self.model_name}', serial='{self.serial_number}')"


class UsbDevice:
    """
    USB device communication handler
    
    Handles low-level USB communication with Samsung devices
    in Download/Odin mode.
    """
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.device: Optional[usb.core.Device] = None
        self.interface = 0
        self.endpoint_out: Optional[usb.core.Endpoint] = None
        self.endpoint_in: Optional[usb.core.Endpoint] = None
        self.device_info: Optional[DeviceInfo] = None
        self.packet_size = USB_PACKET_SIZE
    
    def log(self, message: str):
        """Print log message if verbose"""
        if self.verbose:
            print(f"[UsbDevice] {message}")
    
    def find_device(self) -> Optional[DeviceInfo]:
        """
        Find Samsung device in Download/Odin mode
        
        Returns:
            DeviceInfo if device found, None otherwise
        """
        self.log("Searching for Samsung device in Download mode...")
        
        for pid in SAMSUNG_DOWNLOAD_MODE_PIDS:
            device = usb.core.find(idVendor=SAMSUNG_VENDOR_ID, idProduct=pid)
            
            if device is not None:
                self.log(f"Found device: VID=0x{SAMSUNG_VENDOR_ID:04X}, PID=0x{pid:04X}")
                self.device = device
                
                # Get device info
                device_info = DeviceInfo(
                    vendor_id=SAMSUNG_VENDOR_ID,
                    product_id=pid
                )
                
                try:
                    device_info.manufacturer = usb.util.get_string(device, device.iManufacturer)
                    device_info.product = usb.util.get_string(device, device.iProduct)
                    device_info.serial_number = usb.util.get_string(device, device.iSerialNumber)
                except Exception as e:
                    self.log(f"Warning: Could not read device strings: {e}")
                
                self.device_info = device_info
                return device_info
        
        return None
    
    def connect(self) -> bool:
        """
        Connect to USB device and configure interface
        
        Returns:
            True if connection successful
        """
        if self.device is None:
            if self.find_device() is None:
                raise OdinUSBError("No Samsung device found in Download mode")
        
        try:
            self.log("Connecting to device...")
            
            # Try to detach kernel driver from ALL interfaces (Linux)
            cfg = self.device.get_active_configuration()
            for intf in cfg:
                if_num = intf.bInterfaceNumber
                try:
                    if self.device.is_kernel_driver_active(if_num):
                        self.log(f"Detaching kernel driver from interface {if_num}...")
                        self.device.detach_kernel_driver(if_num)
                        self.log(f"  ✓ Kernel driver detached from interface {if_num}")
                except (AttributeError, usb.core.USBError) as e:
                    self.log(f"  Warning: Could not detach from interface {if_num}: {e}")
            
            # Set configuration
            try:
                self.device.set_configuration()
            except usb.core.USBError as e:
                self.log(f"Warning: Could not set configuration: {e}")
            
            # Get interface
            cfg = self.device.get_active_configuration()
            self.log(f"Active configuration: {cfg.bConfigurationValue}")
            self.log(f"Number of interfaces: {cfg.bNumInterfaces}")
            
            # Find endpoints - search ALL interfaces
            self.log("Searching for endpoints across all interfaces...")
            
            for intf in cfg:
                self.log(f"Interface {intf.bInterfaceNumber}: "
                        f"Class={intf.bInterfaceClass}, "
                        f"Endpoints={intf.bNumEndpoints}")
                
                # Claim interface if it has endpoints
                if intf.bNumEndpoints > 0:
                    try:
                        usb.util.claim_interface(self.device, intf.bInterfaceNumber)
                        self.log(f"  Claimed interface {intf.bInterfaceNumber}")
                    except usb.core.USBError as e:
                        self.log(f"  Warning: Could not claim interface: {e}")
                
                # Check all endpoints in this interface
                for ep in intf:
                    direction = usb.util.endpoint_direction(ep.bEndpointAddress)
                    ep_type = usb.util.endpoint_type(ep.bmAttributes)
                    
                    type_name = {0: "CTRL", 1: "ISO", 2: "BULK", 3: "INT"}.get(ep_type, "UNK")
                    dir_name = "IN" if direction == usb.util.ENDPOINT_IN else "OUT"
                    
                    self.log(f"    Endpoint 0x{ep.bEndpointAddress:02X}: {type_name} {dir_name}")
                    
                    # Look for bulk endpoints (type 2)
                    if ep_type == 2:  # BULK
                        if direction == usb.util.ENDPOINT_OUT and self.endpoint_out is None:
                            self.endpoint_out = ep
                            self.interface = intf.bInterfaceNumber
                            self.log(f"      ★ Using as OUT endpoint")
                        elif direction == usb.util.ENDPOINT_IN and self.endpoint_in is None:
                            self.endpoint_in = ep
                            self.interface = intf.bInterfaceNumber
                            self.log(f"      ★ Using as IN endpoint")
            
            if self.endpoint_out is None or self.endpoint_in is None:
                error_msg = "Could not find USB endpoints\n"
                error_msg += f"Found OUT: {self.endpoint_out is not None}, "
                error_msg += f"Found IN: {self.endpoint_in is not None}"
                raise OdinUSBError(error_msg)
            
            self.log(f"✓ Endpoints configured:")
            self.log(f"  OUT: 0x{self.endpoint_out.bEndpointAddress:02X}")
            self.log(f"  IN:  0x{self.endpoint_in.bEndpointAddress:02X}")
            
            # Set interface alternate setting
            self.log(f"Setting interface alternate setting...")
            try:
                # Get the alternate setting for the interface
                for intf in cfg:
                    if intf.bInterfaceNumber == self.interface:
                        # Try to set alternate setting (usually 0)
                        self.device.set_interface_altsetting(self.interface, intf.bAlternateSetting)
                        self.log(f"  ✓ Set alternate setting {intf.bAlternateSetting} for interface {self.interface}")
                        break
            except Exception as e:
                self.log(f"  Warning: Could not set alternate setting: {e}")
            
            # CRITICAL: Clear/reset endpoints to ensure device is ready
            # Many Samsung devices need this to enter proper download state
            self.log("Clearing endpoints...")
            try:
                self.device.clear_halt(self.endpoint_out.bEndpointAddress)
                self.log(f"  ✓ Cleared OUT endpoint")
            except usb.core.USBError as e:
                self.log(f"  Warning: Could not clear OUT endpoint: {e}")
            
            try:
                self.device.clear_halt(self.endpoint_in.bEndpointAddress)
                self.log(f"  ✓ Cleared IN endpoint")
            except usb.core.USBError as e:
                self.log(f"  Warning: Could not clear IN endpoint: {e}")
            
            # Get packet size
            self.packet_size = self.endpoint_out.wMaxPacketSize
            self.log(f"Max packet size: {self.packet_size}")
            
            return True
            
        except usb.core.USBError as e:
            raise OdinUSBError(f"USB connection failed: {e}")
    
    def disconnect(self):
        """Disconnect from USB device"""
        if self.device is not None:
            try:
                usb.util.dispose_resources(self.device)
                self.log("Disconnected from device")
            except Exception as e:
                self.log(f"Warning during disconnect: {e}")
        
        self.device = None
        self.endpoint_out = None
        self.endpoint_in = None
    
    def write(self, data: bytes, timeout: int = TIMEOUT_WRITE) -> int:
        """
        Write data to device - EXACT implementation matching odin4.c
        
        odin4.c writes data in a single bulk transfer call, letting the
        USB library handle packet fragmentation automatically.
        
        Args:
            data: Data to write (exact bytes to send)
            timeout: Timeout in seconds
            
        Returns:
            Number of bytes written (must match len(data))
        """
        if self.endpoint_out is None:
            raise OdinUSBError("Device not connected")
        
        try:
            timeout_ms = int(timeout * 1000)
            
            # For large writes (>64KB), PyUSB might need chunking to avoid blocking
            # even though odin4 does single transfer
            if len(data) > 65536:
                total_written = 0
                offset = 0
                chunk_size = 65536  # 64KB chunks
                
                while offset < len(data):
                    chunk_end = min(offset + chunk_size, len(data))
                    chunk = data[offset:chunk_end]
                    
                    written = self.endpoint_out.write(chunk, timeout=timeout_ms)
                    total_written += written
                    offset = chunk_end
                    
                    if written != len(chunk):
                        self.log(f"Warning: Partial write {written}/{len(chunk)} bytes")
                        break
                
                if self.verbose:
                    self.log(f"Wrote {total_written} bytes (chunked)")
                
                return total_written
            else:
                # Small writes can go in one call
                bytes_written = self.endpoint_out.write(data, timeout=timeout_ms)
                
                if self.verbose:
                    self.log(f"Wrote {bytes_written} bytes")
                
                return bytes_written
            
        except usb.core.USBError as e:
            raise OdinUSBError(f"USB write failed: {e}")
    
    def read(self, size: int, timeout: int = TIMEOUT_READ) -> bytes:
        """
        Read data from device
        
        Args:
            size: Number of bytes to read
            timeout: Timeout in seconds
            
        Returns:
            Data read from device
        """
        if self.endpoint_in is None:
            raise OdinUSBError("Device not connected")
        
        try:
            timeout_ms = int(timeout * 1000)
            data = self.endpoint_in.read(size, timeout=timeout_ms)
            
            if self.verbose:
                self.log(f"Read {len(data)} bytes")
            
            return bytes(data)
            
        except usb.core.USBError as e:
            if e.errno == 110:  # Timeout
                raise OdinTimeoutError(f"USB read timeout after {timeout}s")
            raise OdinUSBError(f"USB read failed: {e}")
    
    def bulk_write(self, data: bytes, timeout: int = TIMEOUT_WRITE) -> int:
        """
        Write data in bulk transfer
        
        Args:
            data: Data to write
            timeout: Timeout in seconds
            
        Returns:
            Total bytes written
        """
        total_written = 0
        offset = 0
        
        while offset < len(data):
            chunk_size = min(self.packet_size, len(data) - offset)
            chunk = data[offset:offset + chunk_size]
            
            written = self.write(chunk, timeout)
            total_written += written
            offset += chunk_size
            
            if self.verbose and total_written % (self.packet_size * 100) == 0:
                self.log(f"Bulk write progress: {total_written}/{len(data)} bytes")
        
        return total_written
    
    def bulk_read(self, size: int, timeout: int = TIMEOUT_READ) -> bytes:
        """
        Read data in bulk transfer
        
        Args:
            size: Total bytes to read
            timeout: Timeout in seconds
            
        Returns:
            Data read from device
        """
        data = bytearray()
        
        while len(data) < size:
            remaining = size - len(data)
            chunk_size = min(self.packet_size, remaining)
            
            chunk = self.read(chunk_size, timeout)
            data.extend(chunk)
            
            if self.verbose and len(data) % (self.packet_size * 100) == 0:
                self.log(f"Bulk read progress: {len(data)}/{size} bytes")
        
        return bytes(data)
    
    def control_transfer(
        self,
        request_type: int,
        request: int,
        value: int = 0,
        index: int = 0,
        data: Optional[bytes] = None,
        timeout: int = TIMEOUT_WRITE
    ) -> bytes:
        """
        Perform USB control transfer
        
        Args:
            request_type: USB request type
            request: USB request
            value: wValue
            index: wIndex
            data: Data for OUT transfer
            timeout: Timeout in seconds
            
        Returns:
            Data from IN transfer
        """
        if self.device is None:
            raise OdinUSBError("Device not connected")
        
        try:
            timeout_ms = int(timeout * 1000)
            
            if data is not None:
                # OUT transfer
                result = self.device.ctrl_transfer(
                    request_type,
                    request,
                    value,
                    index,
                    data,
                    timeout=timeout_ms
                )
                return bytes()
            else:
                # IN transfer
                result = self.device.ctrl_transfer(
                    request_type,
                    request,
                    value,
                    index,
                    1024,  # Max data size
                    timeout=timeout_ms
                )
                return bytes(result)
                
        except usb.core.USBError as e:
            raise OdinUSBError(f"Control transfer failed: {e}")
    
    def reset(self):
        """Reset USB device"""
        if self.device is not None:
            try:
                self.device.reset()
                self.log("Device reset")
            except Exception as e:
                raise OdinUSBError(f"Device reset failed: {e}")
    
    def is_supported_zlp(self) -> bool:
        """
        Check if device supports Zero-Length Packets
        
        Returns:
            True if ZLP is supported
        """
        if self.device_info is not None:
            return self.device_info.supports_zlp
        return False
    
    @staticmethod
    def list_devices() -> List[DeviceInfo]:
        """
        List all Samsung devices in Download mode
        
        Returns:
            List of DeviceInfo objects
        """
        devices = []
        
        for pid in SAMSUNG_DOWNLOAD_MODE_PIDS:
            for device in usb.core.find(find_all=True, idVendor=SAMSUNG_VENDOR_ID, idProduct=pid):
                device_info = DeviceInfo(
                    vendor_id=SAMSUNG_VENDOR_ID,
                    product_id=pid
                )
                
                try:
                    device_info.manufacturer = usb.util.get_string(device, device.iManufacturer)
                    device_info.product = usb.util.get_string(device, device.iProduct)
                    device_info.serial_number = usb.util.get_string(device, device.iSerialNumber)
                except:
                    pass
                
                devices.append(device_info)
        
        return devices

