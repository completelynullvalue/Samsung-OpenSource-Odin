#!/usr/bin/env python3
"""
PyOdin GUI - Graphical User Interface for Samsung Firmware Flashing

Built with Tkinter for cross-platform compatibility.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import time
from pathlib import Path
from typing import Optional

from .flasher import OdinFlasher
from .firmware import FirmwareData
from .download_engine import DownloadProgress
from .usb_device import DeviceInfo
from .exceptions import OdinException


class OdinGUI:
    """
    PyOdin Graphical User Interface
    
    Provides user-friendly interface for firmware flashing operations.
    """
    
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("PyOdin - Samsung Firmware Flasher")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        
        # State variables
        self.flasher: Optional[OdinFlasher] = None
        self.firmware_data: Optional[FirmwareData] = None
        self.device_info: Optional[DeviceInfo] = None
        self.is_flashing = False
        self.is_connected = False
        
        # File paths
        self.firmware_path = tk.StringVar()
        self.pit_path = tk.StringVar()
        
        # Options
        self.option_verify = tk.BooleanVar(value=True)
        self.option_reboot = tk.BooleanVar(value=True)
        self.option_pit = tk.BooleanVar(value=False)
        self.option_verbose = tk.BooleanVar(value=False)
        
        # Progress
        self.progress_var = tk.DoubleVar(value=0.0)
        self.status_var = tk.StringVar(value="Ready")
        
        # Create UI
        self.create_ui()
        
        # Start device detection
        self.start_device_detection()
    
    def create_ui(self):
        """Create user interface"""
        # Create canvas and scrollbar for scrollable content
        canvas = tk.Canvas(self.root, highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.root, orient="vertical", command=canvas.yview)
        
        # Scrollable frame
        scrollable_frame = ttk.Frame(canvas, padding="10")
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas_window = canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Bind canvas width to scrollable frame width
        def configure_canvas_width(event):
            canvas.itemconfig(canvas_window, width=event.width)
        
        canvas.bind("<Configure>", configure_canvas_width)
        
        # Enable mouse wheel scrolling
        def on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        canvas.bind_all("<MouseWheel>", on_mousewheel)  # Windows/macOS
        canvas.bind_all("<Button-4>", lambda e: canvas.yview_scroll(-1, "units"))  # Linux scroll up
        canvas.bind_all("<Button-5>", lambda e: canvas.yview_scroll(1, "units"))   # Linux scroll down
        
        # Pack canvas and scrollbar
        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        
        # Main frame is now the scrollable_frame
        main_frame = scrollable_frame
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(5, weight=1)
        
        # Header
        self.create_header(main_frame)
        
        # Device section
        self.create_device_section(main_frame)
        
        # File selection section
        self.create_file_section(main_frame)
        
        # Options section
        self.create_options_section(main_frame)
        
        # Progress section
        self.create_progress_section(main_frame)
        
        # Log section
        self.create_log_section(main_frame)
        
        # Action buttons
        self.create_action_buttons(main_frame)
        
        # Status bar
        self.create_status_bar(main_frame)
    
    def create_header(self, parent):
        """Create header section"""
        header_frame = ttk.Frame(parent)
        header_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        title_label = ttk.Label(
            header_frame,
            text="PyOdin - Samsung Firmware Flasher",
            font=("Helvetica", 16, "bold")
        )
        title_label.grid(row=0, column=0, sticky=tk.W)
        
        version_label = ttk.Label(
            header_frame,
            text="v1.0.0",
            font=("Helvetica", 10)
        )
        version_label.grid(row=0, column=1, sticky=tk.E, padx=(10, 0))
        
        header_frame.columnconfigure(0, weight=1)
    
    def create_device_section(self, parent):
        """Create device detection section"""
        device_frame = ttk.LabelFrame(parent, text="Device Information", padding="10")
        device_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5)
        device_frame.columnconfigure(1, weight=1)
        
        # Device status
        ttk.Label(device_frame, text="Status:").grid(row=0, column=0, sticky=tk.W)
        self.device_status_label = ttk.Label(
            device_frame,
            text="No device detected",
            foreground="red"
        )
        self.device_status_label.grid(row=0, column=1, sticky=tk.W, padx=(10, 0))
        
        # Device model
        ttk.Label(device_frame, text="Model:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.device_model_label = ttk.Label(device_frame, text="-")
        self.device_model_label.grid(row=1, column=1, sticky=tk.W, padx=(10, 0), pady=5)
        
        # Device serial
        ttk.Label(device_frame, text="Serial:").grid(row=2, column=0, sticky=tk.W)
        self.device_serial_label = ttk.Label(device_frame, text="-")
        self.device_serial_label.grid(row=2, column=1, sticky=tk.W, padx=(10, 0))
        
        # Refresh button
        self.refresh_button = ttk.Button(
            device_frame,
            text="Refresh",
            command=self.refresh_device
        )
        self.refresh_button.grid(row=0, column=2, rowspan=3, padx=(10, 0))
    
    def create_file_section(self, parent):
        """Create file selection section"""
        file_frame = ttk.LabelFrame(parent, text="Firmware Files", padding="10")
        file_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=5)
        file_frame.columnconfigure(1, weight=1)
        
        # Firmware file
        ttk.Label(file_frame, text="Firmware:").grid(row=0, column=0, sticky=tk.W)
        firmware_entry = ttk.Entry(file_frame, textvariable=self.firmware_path, state="readonly")
        firmware_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5)
        ttk.Button(
            file_frame,
            text="Browse...",
            command=self.browse_firmware
        ).grid(row=0, column=2)
        
        # PIT file (optional)
        ttk.Label(file_frame, text="PIT File:").grid(row=1, column=0, sticky=tk.W, pady=(10, 0))
        pit_entry = ttk.Entry(file_frame, textvariable=self.pit_path, state="readonly")
        pit_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=5, pady=(10, 0))
        ttk.Button(
            file_frame,
            text="Browse...",
            command=self.browse_pit
        ).grid(row=1, column=2, pady=(10, 0))
    
    def create_options_section(self, parent):
        """Create options section"""
        options_frame = ttk.LabelFrame(parent, text="Options", padding="10")
        options_frame.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Checkbutton(
            options_frame,
            text="Verify MD5/SHA256 hash",
            variable=self.option_verify
        ).grid(row=0, column=0, sticky=tk.W, padx=5)
        
        ttk.Checkbutton(
            options_frame,
            text="Auto-reboot after flashing",
            variable=self.option_reboot
        ).grid(row=0, column=1, sticky=tk.W, padx=5)
        
        ttk.Checkbutton(
            options_frame,
            text="Use PIT file",
            variable=self.option_pit
        ).grid(row=1, column=0, sticky=tk.W, padx=5, pady=(5, 0))
        
        ttk.Checkbutton(
            options_frame,
            text="Verbose logging",
            variable=self.option_verbose
        ).grid(row=1, column=1, sticky=tk.W, padx=5, pady=(5, 0))
    
    def create_progress_section(self, parent):
        """Create progress section"""
        progress_frame = ttk.LabelFrame(parent, text="Progress", padding="10")
        progress_frame.grid(row=4, column=0, sticky=(tk.W, tk.E), pady=5)
        progress_frame.columnconfigure(0, weight=1)
        
        # Progress bar
        self.progress_bar = ttk.Progressbar(
            progress_frame,
            variable=self.progress_var,
            maximum=100,
            mode='determinate'
        )
        self.progress_bar.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 5))
        
        # Progress label
        self.progress_label = ttk.Label(progress_frame, text="0%")
        self.progress_label.grid(row=1, column=0, sticky=tk.W)
        
        # Speed label
        self.speed_label = ttk.Label(progress_frame, text="Speed: - MB/s")
        self.speed_label.grid(row=2, column=0, sticky=tk.W)
        
        # Current file label
        self.file_label = ttk.Label(progress_frame, text="File: -")
        self.file_label.grid(row=3, column=0, sticky=tk.W)
    
    def create_log_section(self, parent):
        """Create log section"""
        log_frame = ttk.LabelFrame(parent, text="Log", padding="10")
        log_frame.grid(row=5, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        
        # Log text area
        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            height=10,
            wrap=tk.WORD,
            state='disabled',
            font=("Courier", 9)
        )
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure tags for colored output
        self.log_text.tag_config("info", foreground="black")
        self.log_text.tag_config("success", foreground="green")
        self.log_text.tag_config("warning", foreground="orange")
        self.log_text.tag_config("error", foreground="red")
    
    def create_action_buttons(self, parent):
        """Create action buttons"""
        button_frame = ttk.Frame(parent)
        button_frame.grid(row=6, column=0, sticky=(tk.W, tk.E), pady=10)
        
        # Flash button
        self.flash_button = ttk.Button(
            button_frame,
            text="Start Flashing",
            command=self.start_flashing,
            style="Accent.TButton"
        )
        self.flash_button.pack(side=tk.LEFT, padx=5)
        
        # Stop button
        self.stop_button = ttk.Button(
            button_frame,
            text="Stop",
            command=self.stop_flashing,
            state='disabled'
        )
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        # Clear log button
        ttk.Button(
            button_frame,
            text="Clear Log",
            command=self.clear_log
        ).pack(side=tk.LEFT, padx=5)
        
        # About button
        ttk.Button(
            button_frame,
            text="About",
            command=self.show_about
        ).pack(side=tk.RIGHT, padx=5)
    
    def create_status_bar(self, parent):
        """Create status bar"""
        status_frame = ttk.Frame(parent, relief=tk.SUNKEN, borderwidth=1)
        status_frame.grid(row=7, column=0, sticky=(tk.W, tk.E))
        
        status_label = ttk.Label(
            status_frame,
            textvariable=self.status_var,
            anchor=tk.W
        )
        status_label.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
    
    def start_device_detection(self):
        """Start background device detection"""
        def detect_loop():
            while True:
                if not self.is_flashing:
                    self.detect_device()
                time.sleep(2)  # Check every 2 seconds
        
        thread = threading.Thread(target=detect_loop, daemon=True)
        thread.start()
    
    def detect_device(self):
        """Detect connected device"""
        try:
            if not self.flasher:
                self.flasher = OdinFlasher(verbose=False)  # Don't use verbose for detection
            
            devices = self.flasher.list_devices()
            
            if devices and not self.is_connected:
                device = devices[0]
                self.device_info = device
                
                # Update UI
                self.root.after(0, lambda: self.update_device_ui(device, True))
            elif not devices and self.is_connected:
                # Device disconnected
                self.root.after(0, lambda: self.update_device_ui(None, False))
        
        except Exception as e:
            # Silently fail detection, but log if verbose
            if self.option_verbose.get():
                self.root.after(0, self.log, f"Device detection: {e}", "warning")
    
    def update_device_ui(self, device: Optional[DeviceInfo], connected: bool):
        """Update device UI"""
        self.is_connected = connected
        
        if connected and device:
            self.device_status_label.config(
                text="Device detected (Download Mode)",
                foreground="green"
            )
            self.device_model_label.config(text=device.product or "Unknown")
            self.device_serial_label.config(text=device.serial_number or "Unknown")
            self.flash_button.config(state='normal')
        else:
            self.device_status_label.config(
                text="No device detected",
                foreground="red"
            )
            self.device_model_label.config(text="-")
            self.device_serial_label.config(text="-")
            self.flash_button.config(state='disabled')
    
    def refresh_device(self):
        """Manually refresh device detection"""
        self.log("Refreshing device detection...", "info")
        self.detect_device()
    
    def browse_firmware(self):
        """Browse for firmware file"""
        try:
            filename = filedialog.askopenfilename(
                title="Select Firmware File",
                filetypes=[
                    ("Firmware files", "*.tar.md5 *.tar *.tar.gz *.bin"),
                    ("All files", "*.*")
                ]
            )
            
            if filename:
                self.firmware_path.set(filename)
                self.log(f"Selected firmware: {Path(filename).name}", "info")
                
                # Try to parse firmware info
                self.parse_firmware_info(filename)
        
        except Exception as e:
            self.log(f"✗ Error selecting file: {e}", "error")
            messagebox.showerror("Error", f"Failed to open file browser:\n\n{e}")
    
    def browse_pit(self):
        """Browse for PIT file"""
        filename = filedialog.askopenfilename(
            title="Select PIT File",
            filetypes=[
                ("PIT files", "*.pit"),
                ("All files", "*.*")
            ]
        )
        
        if filename:
            self.pit_path.set(filename)
            self.log(f"Selected PIT: {Path(filename).name}", "info")
    
    def parse_firmware_info(self, firmware_path: str):
        """Parse and display firmware information"""
        def parse_thread():
            try:
                self.root.after(0, self.log, "Parsing firmware...", "info")
                
                if not self.flasher:
                    self.flasher = OdinFlasher(verbose=False)
                
                firmware_data = self.flasher.load_firmware(
                    firmware_path,
                    verify_hash=False  # Don't verify yet
                )
                
                self.firmware_data = firmware_data
                
                self.root.after(0, self.log, f"✓ Firmware parsed: {len(firmware_data.items)} items", "success")
                
                if firmware_data.md5_hash:
                    self.root.after(0, self.log, f"  MD5: {firmware_data.md5_hash}", "info")
                
                for item in firmware_data.items:
                    size_mb = item.size / (1024 * 1024)
                    self.root.after(0, self.log, f"  - {item.filename} ({size_mb:.1f} MB)", "info")
            
            except OdinException as e:
                self.root.after(0, self.log, f"✗ Odin error: {e.message}", "error")
                self.root.after(0, messagebox.showerror, "Parse Error", f"Failed to parse firmware:\n\n{e.message}")
                self.firmware_data = None
            
            except Exception as e:
                import traceback
                error_details = traceback.format_exc()
                self.root.after(0, self.log, f"✗ Failed to parse firmware: {e}", "error")
                self.root.after(0, self.log, f"Details: {error_details}", "error")
                self.root.after(0, messagebox.showerror, "Parse Error", 
                               f"Failed to parse firmware:\n\n{str(e)}\n\nCheck log for details.")
                self.firmware_data = None
        
        # Run parsing in background thread to avoid blocking UI
        thread = threading.Thread(target=parse_thread, daemon=True)
        thread.start()
    
    def start_flashing(self):
        """Start firmware flashing"""
        # Validation
        if not self.firmware_path.get():
            messagebox.showerror("Error", "Please select a firmware file")
            return
        
        if self.option_pit.get() and not self.pit_path.get():
            messagebox.showerror("Error", "Please select a PIT file or disable PIT option")
            return
        
        if not self.is_connected:
            messagebox.showerror("Error", "No device connected")
            return
        
        # Confirmation
        result = messagebox.askyesno(
            "Confirm Flashing",
            "⚠️ WARNING: This will flash firmware to your device!\n\n"
            "- All data will be erased\n"
            "- Device may be bricked if interrupted\n"
            "- Ensure device has >50% battery\n"
            "- Ensure stable USB connection\n\n"
            "Do you want to continue?",
            icon='warning'
        )
        
        if not result:
            return
        
        # Start flashing in background thread
        thread = threading.Thread(target=self.flash_firmware, daemon=True)
        thread.start()
    
    def flash_firmware(self):
        """Flash firmware (runs in background thread)"""
        try:
            self.is_flashing = True
            
            # Update UI
            self.root.after(0, self.set_flashing_ui, True)
            
            # Create flasher
            self.flasher = OdinFlasher(verbose=self.option_verbose.get())
            
            # Load firmware
            self.root.after(0, self.log, "[1/4] Loading firmware...", "info")
            firmware = self.flasher.load_firmware(
                self.firmware_path.get(),
                verify_hash=self.option_verify.get()
            )
            self.root.after(0, self.log, f"✓ Loaded {len(firmware.items)} items", "success")
            
            # Load PIT if needed
            pit_data = None
            if self.option_pit.get() and self.pit_path.get():
                self.root.after(0, self.log, "  Loading PIT file...", "info")
                with open(self.pit_path.get(), 'rb') as f:
                    pit_data = f.read()
            
            # Connect to device
            self.root.after(0, self.log, "[2/4] Connecting to device...", "info")
            device = self.flasher.connect_device()
            self.root.after(0, self.log, f"✓ Connected: {device.model_name or device.product}", "success")
            
            # Flash firmware
            self.root.after(0, self.log, "[3/4] Flashing firmware...", "info")
            success = self.flasher.flash(
                firmware,
                pit_data=pit_data,
                reboot=self.option_reboot.get(),
                progress_callback=self.update_progress
            )
            
            if success:
                self.root.after(0, self.log, "[4/4] ✓ Firmware flashed successfully!", "success")
                
                if self.option_reboot.get():
                    self.root.after(0, self.log, "  Device is rebooting...", "info")
                
                self.root.after(0, messagebox.showinfo, "Success",
                               "Firmware flashed successfully!\n\n"
                               "First boot may take 5-10 minutes.")
            else:
                self.root.after(0, self.log, "[4/4] ✗ Flashing failed!", "error")
                self.root.after(0, messagebox.showerror, "Error", "Flashing failed!")
            
            # Disconnect
            self.flasher.disconnect_device()
        
        except OdinException as e:
            self.root.after(0, self.log, f"✗ Error: {e.message}", "error")
            self.root.after(0, messagebox.showerror, "Error", str(e.message))
        
        except Exception as e:
            self.root.after(0, self.log, f"✗ Unexpected error: {e}", "error")
            self.root.after(0, messagebox.showerror, "Error", str(e))
        
        finally:
            self.is_flashing = False
            self.root.after(0, self.set_flashing_ui, False)
            self.root.after(0, self.reset_progress)
    
    def stop_flashing(self):
        """Stop flashing (not fully supported)"""
        messagebox.showwarning(
            "Warning",
            "⚠️ Cannot safely stop flashing in progress!\n\n"
            "Interrupting may brick your device.\n"
            "Please wait for flashing to complete."
        )
    
    def update_progress(self, progress: DownloadProgress):
        """Update progress (called from flasher)"""
        self.root.after(0, self._update_progress_ui, progress)
    
    def _update_progress_ui(self, progress: DownloadProgress):
        """Update progress UI (must be called from main thread)"""
        self.progress_var.set(progress.percentage)
        self.progress_label.config(text=f"{progress.percentage:.1f}%")
        
        speed_mb = progress.speed_bps / (1024 * 1024)
        self.speed_label.config(text=f"Speed: {speed_mb:.2f} MB/s")
        
        self.file_label.config(text=f"File: {progress.current_file}")
        
        self.status_var.set(f"Flashing: {progress.current_file} - {progress.percentage:.1f}%")
    
    def reset_progress(self):
        """Reset progress UI"""
        self.progress_var.set(0)
        self.progress_label.config(text="0%")
        self.speed_label.config(text="Speed: - MB/s")
        self.file_label.config(text="File: -")
        self.status_var.set("Ready")
    
    def set_flashing_ui(self, flashing: bool):
        """Update UI for flashing state"""
        if flashing:
            self.flash_button.config(state='disabled')
            self.stop_button.config(state='normal')
            self.refresh_button.config(state='disabled')
        else:
            self.flash_button.config(state='normal' if self.is_connected else 'disabled')
            self.stop_button.config(state='disabled')
            self.refresh_button.config(state='normal')
    
    def log(self, message: str, level: str = "info"):
        """Add message to log"""
        self.log_text.config(state='normal')
        
        timestamp = time.strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n", level)
        self.log_text.see(tk.END)
        
        self.log_text.config(state='disabled')
    
    def clear_log(self):
        """Clear log"""
        self.log_text.config(state='normal')
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state='disabled')
    
    def show_about(self):
        """Show about dialog"""
        messagebox.showinfo(
            "About PyOdin",
            "PyOdin v1.0.0\n\n"
            "Samsung Firmware Flasher\n\n"
            "A Python implementation of Odin,\n"
            "reverse-engineered from open-source code.\n\n"
            "⚠️ WARNING:\n"
            "Flashing firmware can brick your device.\n"
            "Use at your own risk!\n\n"
            "For educational purposes only."
        )


def main():
    """Main entry point for GUI"""
    try:
        root = tk.Tk()
        
        # Set theme (optional)
        try:
            style = ttk.Style()
            style.theme_use('clam')  # or 'alt', 'default', 'classic'
        except:
            pass  # Use default theme if clam not available
        
        # Create GUI
        gui = OdinGUI(root)
        
        # Start main loop
        root.mainloop()
    
    except Exception as e:
        import traceback
        error_msg = f"Fatal error starting GUI:\n\n{e}\n\n{traceback.format_exc()}"
        print(error_msg)
        
        try:
            messagebox.showerror("Fatal Error", error_msg)
        except:
            pass
        
        return 1
    
    return 0


if __name__ == '__main__':
    import sys
    sys.exit(main())

