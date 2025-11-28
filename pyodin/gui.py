#!/usr/bin/env python3
"""
PyOdin GUI - Graphical User Interface for Samsung Firmware Flashing

Modern dark theme with clean aesthetics.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import time
from pathlib import Path
from typing import Optional, Dict

from .flasher import OdinFlasher
from .firmware import FirmwareData
from .download_engine import DownloadProgress
from .usb_device import DeviceInfo
from .exceptions import OdinException


# Color scheme - Dark theme with cyan accent
COLORS = {
    'bg_dark': '#1a1a2e',
    'bg_medium': '#16213e',
    'bg_light': '#0f3460',
    'accent': '#00d9ff',
    'accent_dim': '#0891b2',
    'text': '#e2e8f0',
    'text_dim': '#94a3b8',
    'success': '#22c55e',
    'warning': '#f59e0b',
    'error': '#ef4444',
    'border': '#334155',
}


class OdinGUI:
    """PyOdin Graphical User Interface with modern dark theme."""
    
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("PyOdin")
        self.root.geometry("960x760")
        self.root.resizable(True, True)
        self.root.configure(bg=COLORS['bg_dark'])
        
        # State variables
        self.flasher: Optional[OdinFlasher] = None
        self.firmware_data: Optional[FirmwareData] = None
        self.firmware_sections: Dict[str, Optional[FirmwareData]] = {
            "BL": None, "AP": None, "CP": None, "CSC": None, "UMS": None
        }
        self.device_info: Optional[DeviceInfo] = None
        self.is_flashing = False
        self.is_connected = False
        
        # File paths
        self.bl_path = tk.StringVar()
        self.ap_path = tk.StringVar()
        self.cp_path = tk.StringVar()
        self.csc_path = tk.StringVar()
        self.ums_path = tk.StringVar()
        self.pit_path = tk.StringVar()
        
        # Options
        self.option_verify = tk.BooleanVar(value=True)
        self.option_reboot = tk.BooleanVar(value=True)
        self.option_pit = tk.BooleanVar(value=False)
        self.option_verbose = tk.BooleanVar(value=False)
        self.option_lock = tk.BooleanVar(value=False)
        self.option_bypass_verification = tk.BooleanVar(value=False)
        
        # Progress
        self.progress_var = tk.DoubleVar(value=0.0)
        self.status_var = tk.StringVar(value="Ready")
        
        self._setup_styles()
        self._create_ui()
        self._start_device_detection()
    
    def _setup_styles(self):
        """Configure ttk styles for dark theme."""
        style = ttk.Style()
        
        # Try to use clam as base for better customization
        try:
            style.theme_use('clam')
        except:
            pass
        
        # Frame styles
        style.configure('Dark.TFrame', background=COLORS['bg_dark'])
        style.configure('Card.TFrame', background=COLORS['bg_medium'])
        
        # Label styles
        style.configure('Dark.TLabel',
            background=COLORS['bg_dark'],
            foreground=COLORS['text'],
            font=('Segoe UI', 10)
        )
        style.configure('Card.TLabel',
            background=COLORS['bg_medium'],
            foreground=COLORS['text'],
            font=('Segoe UI', 10)
        )
        style.configure('Title.TLabel',
            background=COLORS['bg_dark'],
            foreground=COLORS['accent'],
            font=('Segoe UI', 22, 'bold')
        )
        style.configure('Subtitle.TLabel',
            background=COLORS['bg_dark'],
            foreground=COLORS['text_dim'],
            font=('Segoe UI', 10)
        )
        style.configure('Section.TLabel',
            background=COLORS['bg_medium'],
            foreground=COLORS['accent'],
            font=('Segoe UI', 11, 'bold')
        )
        style.configure('Status.TLabel',
            background=COLORS['bg_medium'],
            foreground=COLORS['text_dim'],
            font=('Segoe UI', 10)
        )
        style.configure('Connected.TLabel',
            background=COLORS['bg_medium'],
            foreground=COLORS['success'],
            font=('Segoe UI', 10, 'bold')
        )
        style.configure('Disconnected.TLabel',
            background=COLORS['bg_medium'],
            foreground=COLORS['error'],
            font=('Segoe UI', 10)
        )
        
        # LabelFrame style
        style.configure('Card.TLabelframe',
            background=COLORS['bg_medium'],
            bordercolor=COLORS['border'],
            relief='flat'
        )
        style.configure('Card.TLabelframe.Label',
            background=COLORS['bg_medium'],
            foreground=COLORS['accent'],
            font=('Segoe UI', 11, 'bold')
        )
        
        # Button styles
        style.configure('TButton',
            background=COLORS['bg_light'],
            foreground=COLORS['text'],
            bordercolor=COLORS['border'],
            focuscolor=COLORS['accent'],
            font=('Segoe UI', 10),
            padding=(12, 6)
        )
        style.map('TButton',
            background=[('active', COLORS['accent_dim']), ('pressed', COLORS['accent'])],
            foreground=[('active', COLORS['text']), ('pressed', COLORS['bg_dark'])]
        )
        
        style.configure('Accent.TButton',
            background=COLORS['accent'],
            foreground=COLORS['bg_dark'],
            font=('Segoe UI', 11, 'bold'),
            padding=(16, 8)
        )
        style.map('Accent.TButton',
            background=[('active', COLORS['accent_dim']), ('disabled', COLORS['border'])],
            foreground=[('disabled', COLORS['text_dim'])]
        )
        
        style.configure('Danger.TButton',
            background=COLORS['error'],
            foreground=COLORS['text'],
            font=('Segoe UI', 10, 'bold'),
            padding=(12, 6)
        )
        
        # Entry style
        style.configure('TEntry',
            fieldbackground=COLORS['bg_dark'],
            foreground=COLORS['text'],
            bordercolor=COLORS['border'],
            insertcolor=COLORS['text']
        )
        
        # Checkbutton style
        style.configure('TCheckbutton',
            background=COLORS['bg_medium'],
            foreground=COLORS['text'],
            font=('Segoe UI', 10)
        )
        style.map('TCheckbutton',
            background=[('active', COLORS['bg_medium'])],
            foreground=[('active', COLORS['accent'])]
        )
        
        # Progressbar style
        style.configure('Accent.Horizontal.TProgressbar',
            background=COLORS['accent'],
            troughcolor=COLORS['bg_dark'],
            bordercolor=COLORS['border'],
            lightcolor=COLORS['accent'],
            darkcolor=COLORS['accent_dim']
        )
        
        # Scrollbar style
        style.configure('TScrollbar',
            background=COLORS['bg_light'],
            troughcolor=COLORS['bg_dark'],
            bordercolor=COLORS['bg_dark'],
            arrowcolor=COLORS['text_dim']
        )
    
    def _create_ui(self):
        """Create the user interface."""
        # Main container
        container = ttk.Frame(self.root, style='Dark.TFrame')
        container.pack(fill='both', expand=True)
        
        # Canvas for scrolling
        canvas = tk.Canvas(container, bg=COLORS['bg_dark'], highlightthickness=0)
        scrollbar = ttk.Scrollbar(container, orient='vertical', command=canvas.yview)
        
        self.main_frame = ttk.Frame(canvas, style='Dark.TFrame')
        self.main_frame.bind('<Configure>', lambda e: canvas.configure(scrollregion=canvas.bbox('all')))
        
        canvas_window = canvas.create_window((0, 0), window=self.main_frame, anchor='nw')
        canvas.configure(yscrollcommand=scrollbar.set)
        
        def on_canvas_configure(event):
            canvas.itemconfig(canvas_window, width=event.width - 4)
        canvas.bind('<Configure>', on_canvas_configure)
        
        # Mouse wheel scrolling
        def on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), 'units')
        canvas.bind_all('<MouseWheel>', on_mousewheel)
        canvas.bind_all('<Button-4>', lambda e: canvas.yview_scroll(-1, 'units'))
        canvas.bind_all('<Button-5>', lambda e: canvas.yview_scroll(1, 'units'))
        
        scrollbar.pack(side='right', fill='y')
        canvas.pack(side='left', fill='both', expand=True)
        
        # Add padding frame
        content = ttk.Frame(self.main_frame, style='Dark.TFrame')
        content.pack(fill='both', expand=True, padx=24, pady=20)
        
        self._create_header(content)
        self._create_device_section(content)
        self._create_file_section(content)
        self._create_options_section(content)
        self._create_progress_section(content)
        self._create_log_section(content)
        self._create_action_buttons(content)
        self._create_status_bar(content)
    
    def _create_header(self, parent):
        """Create header with title."""
        header = ttk.Frame(parent, style='Dark.TFrame')
        header.pack(fill='x', pady=(0, 20))
        
        title = ttk.Label(header, text="PyOdin", style='Title.TLabel')
        title.pack(side='left')
        
        subtitle = ttk.Label(header, text="Samsung Firmware Flasher  •  v1.0.0", style='Subtitle.TLabel')
        subtitle.pack(side='left', padx=(12, 0), pady=(8, 0))
    
    def _create_device_section(self, parent):
        """Create device information card."""
        card = self._create_card(parent, "Device")
        
        # Status row
        row1 = ttk.Frame(card, style='Card.TFrame')
        row1.pack(fill='x', pady=(0, 8))
        
        ttk.Label(row1, text="Status:", style='Card.TLabel', width=12).pack(side='left')
        self.device_status_label = ttk.Label(row1, text="No device detected", style='Disconnected.TLabel')
        self.device_status_label.pack(side='left', padx=(0, 20))
        
        self.refresh_button = ttk.Button(row1, text="↻ Refresh", command=self._refresh_device, width=12)
        self.refresh_button.pack(side='right')
        
        # Model row
        row2 = ttk.Frame(card, style='Card.TFrame')
        row2.pack(fill='x', pady=4)
        
        ttk.Label(row2, text="Model:", style='Card.TLabel', width=12).pack(side='left')
        self.device_model_label = ttk.Label(row2, text="—", style='Status.TLabel')
        self.device_model_label.pack(side='left')
        
        # Serial row
        row3 = ttk.Frame(card, style='Card.TFrame')
        row3.pack(fill='x', pady=4)
        
        ttk.Label(row3, text="Serial:", style='Card.TLabel', width=12).pack(side='left')
        self.device_serial_label = ttk.Label(row3, text="—", style='Status.TLabel')
        self.device_serial_label.pack(side='left')
    
    def _create_file_section(self, parent):
        """Create firmware file selection card."""
        card = self._create_card(parent, "Firmware Files")
        
        sections = [
            ("BL", "Bootloader", self.bl_path),
            ("AP", "System", self.ap_path),
            ("CP", "Modem", self.cp_path),
            ("CSC", "Customization", self.csc_path),
            ("UMS", "Userdata", self.ums_path),
        ]
        
        for code, desc, var in sections:
            self._create_file_row(card, f"{code} ({desc}):", var, code)
        
        # PIT file (separated)
        sep = ttk.Frame(card, style='Card.TFrame', height=1)
        sep.pack(fill='x', pady=12)
        
        self._create_file_row(card, "PIT File (optional):", self.pit_path, "PIT", is_pit=True)
    
    def _create_file_row(self, parent, label: str, var: tk.StringVar, section: str, is_pit: bool = False):
        """Create a file selection row."""
        row = ttk.Frame(parent, style='Card.TFrame')
        row.pack(fill='x', pady=4)
        
        ttk.Label(row, text=label, style='Card.TLabel', width=18).pack(side='left')
        
        entry = tk.Entry(row, textvariable=var, state='readonly',
                        bg=COLORS['bg_dark'], fg=COLORS['text_dim'],
                        insertbackground=COLORS['text'], relief='flat',
                        highlightthickness=1, highlightbackground=COLORS['border'],
                        highlightcolor=COLORS['accent'], font=('Consolas', 9))
        entry.pack(side='left', fill='x', expand=True, padx=(0, 8))
        
        if is_pit:
            cmd = self._browse_pit
        else:
            cmd = lambda s=section, v=var: self._browse_firmware(s, v)
        
        ttk.Button(row, text="Browse", command=cmd, width=10).pack(side='right')
    
    def _create_options_section(self, parent):
        """Create options card."""
        card = self._create_card(parent, "Options")
        
        # First row
        row1 = ttk.Frame(card, style='Card.TFrame')
        row1.pack(fill='x', pady=2)
        
        ttk.Checkbutton(row1, text="Verify MD5/SHA256", variable=self.option_verify,
                       style='TCheckbutton').pack(side='left', padx=(0, 24))
        ttk.Checkbutton(row1, text="Auto-reboot after flash", variable=self.option_reboot,
                       style='TCheckbutton').pack(side='left', padx=(0, 24))
        ttk.Checkbutton(row1, text="Verbose logging", variable=self.option_verbose,
                       style='TCheckbutton').pack(side='left')
        
        # Second row
        row2 = ttk.Frame(card, style='Card.TFrame')
        row2.pack(fill='x', pady=(8, 2))
        
        ttk.Checkbutton(row2, text="Use PIT file", variable=self.option_pit,
                       style='TCheckbutton').pack(side='left', padx=(0, 24))
        ttk.Checkbutton(row2, text="Option Lock", variable=self.option_lock,
                       style='TCheckbutton').pack(side='left', padx=(0, 24))
        
        # Dangerous option
        row3 = ttk.Frame(card, style='Card.TFrame')
        row3.pack(fill='x', pady=(12, 0))
        
        self.bypass_check = ttk.Checkbutton(
            row3, text="⚠ BYPASS Signature Verification (DANGEROUS)",
            variable=self.option_bypass_verification,
            command=self._on_bypass_toggled,
            style='TCheckbutton'
        )
        self.bypass_check.pack(side='left')
    
    def _create_progress_section(self, parent):
        """Create progress card."""
        card = self._create_card(parent, "Progress")
        
        # Progress bar
        self.progress_bar = ttk.Progressbar(
            card, variable=self.progress_var, maximum=100,
            mode='determinate', style='Accent.Horizontal.TProgressbar'
        )
        self.progress_bar.pack(fill='x', pady=(0, 12))
        
        # Info row
        info = ttk.Frame(card, style='Card.TFrame')
        info.pack(fill='x')
        
        self.progress_label = ttk.Label(info, text="0%", style='Card.TLabel', width=8)
        self.progress_label.pack(side='left')
        
        self.speed_label = ttk.Label(info, text="— MB/s", style='Status.TLabel')
        self.speed_label.pack(side='left', padx=20)
        
        self.file_label = ttk.Label(info, text="Waiting...", style='Status.TLabel')
        self.file_label.pack(side='right')
    
    def _create_log_section(self, parent):
        """Create log card."""
        card = self._create_card(parent, "Log")
        
        # Log text with custom styling
        log_frame = ttk.Frame(card, style='Card.TFrame')
        log_frame.pack(fill='both', expand=True)
        
        self.log_text = tk.Text(
            log_frame, height=10, wrap='word', state='disabled',
            bg=COLORS['bg_dark'], fg=COLORS['text_dim'],
            insertbackground=COLORS['text'], relief='flat',
            highlightthickness=1, highlightbackground=COLORS['border'],
            highlightcolor=COLORS['accent'], font=('Consolas', 9),
            padx=8, pady=8
        )
        
        scrollbar = ttk.Scrollbar(log_frame, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        
        scrollbar.pack(side='right', fill='y')
        self.log_text.pack(side='left', fill='both', expand=True)
        
        # Configure tags
        self.log_text.tag_config('info', foreground=COLORS['text_dim'])
        self.log_text.tag_config('success', foreground=COLORS['success'])
        self.log_text.tag_config('warning', foreground=COLORS['warning'])
        self.log_text.tag_config('error', foreground=COLORS['error'])
    
    def _create_action_buttons(self, parent):
        """Create action buttons."""
        buttons = ttk.Frame(parent, style='Dark.TFrame')
        buttons.pack(fill='x', pady=(16, 8))
        
        # Main actions (left)
        left = ttk.Frame(buttons, style='Dark.TFrame')
        left.pack(side='left')
        
        self.flash_button = ttk.Button(
            left, text="▶ Start Flash", command=self._start_flashing,
            style='Accent.TButton', state='disabled'
        )
        self.flash_button.pack(side='left', padx=(0, 8))
        
        self.stop_button = ttk.Button(
            left, text="■ Stop", command=self._stop_flashing,
            style='Danger.TButton', state='disabled'
        )
        self.stop_button.pack(side='left', padx=(0, 8))
        
        ttk.Button(left, text="OEM Unlock", command=self._oem_unlock).pack(side='left', padx=(0, 8))
        
        # Secondary actions (right)
        right = ttk.Frame(buttons, style='Dark.TFrame')
        right.pack(side='right')
        
        ttk.Button(right, text="Clear Log", command=self._clear_log).pack(side='left', padx=(8, 0))
        ttk.Button(right, text="About", command=self._show_about).pack(side='left', padx=(8, 0))
    
    def _create_status_bar(self, parent):
        """Create status bar."""
        status = tk.Frame(parent, bg=COLORS['bg_medium'], height=28)
        status.pack(fill='x', pady=(8, 0))
        status.pack_propagate(False)
        
        status_label = tk.Label(
            status, textvariable=self.status_var, anchor='w',
            bg=COLORS['bg_medium'], fg=COLORS['text_dim'],
            font=('Segoe UI', 9), padx=12
        )
        status_label.pack(side='left', fill='both', expand=True)
    
    def _create_card(self, parent, title: str) -> ttk.Frame:
        """Create a styled card with title."""
        # Outer container with padding
        outer = ttk.Frame(parent, style='Dark.TFrame')
        outer.pack(fill='x', pady=8)
        
        # Title
        ttk.Label(outer, text=title, style='Section.TLabel').pack(anchor='w', pady=(0, 6))
        
        # Card body
        card = tk.Frame(outer, bg=COLORS['bg_medium'], padx=16, pady=12)
        card.pack(fill='x')
        
        # Round corners simulation via border
        card.configure(highlightthickness=1, highlightbackground=COLORS['border'])
        
        return card
    
    # ─── Device Detection ────────────────────────────────────────────────────
    
    def _start_device_detection(self):
        """Start background device detection loop."""
        def loop():
            while True:
                if not self.is_flashing:
                    self._detect_device()
                time.sleep(2)
        
        threading.Thread(target=loop, daemon=True).start()
    
    def _detect_device(self):
        """Detect connected Samsung device in download mode."""
        try:
            if not self.flasher:
                self.flasher = OdinFlasher(verbose=False)
            
            devices = self.flasher.list_devices()
            
            if devices and not self.is_connected:
                self.root.after(0, self._update_device_ui, devices[0], True)
            elif not devices and self.is_connected:
                self.root.after(0, self._update_device_ui, None, False)
        except Exception as e:
            if self.option_verbose.get():
                self.root.after(0, self._log, f"Detection error: {e}", 'warning')
    
    def _update_device_ui(self, device: Optional[DeviceInfo], connected: bool):
        """Update device section UI."""
        self.is_connected = connected
        self.device_info = device
        
        if connected and device:
            self.device_status_label.configure(text="Connected (Download Mode)", style='Connected.TLabel')
            self.device_model_label.configure(text=device.product or "Unknown")
            self.device_serial_label.configure(text=device.serial_number or "Unknown")
            self.flash_button.configure(state='normal')
        else:
            self.device_status_label.configure(text="No device detected", style='Disconnected.TLabel')
            self.device_model_label.configure(text="—")
            self.device_serial_label.configure(text="—")
            self.flash_button.configure(state='disabled')
    
    def _refresh_device(self):
        """Manually refresh device detection."""
        self._log("Refreshing device detection...", 'info')
        self._detect_device()
    
    # ─── File Browsing ───────────────────────────────────────────────────────
    
    def _browse_firmware(self, section: str, var: tk.StringVar):
        """Browse for firmware file."""
        filename = filedialog.askopenfilename(
            title=f"Select {section} Firmware",
            filetypes=[
                ("Firmware", "*.tar.md5 *.tar *.tar.gz *.bin"),
                ("All files", "*.*")
            ]
        )
        
        if filename:
            var.set(filename)
            self._log(f"Selected {section}: {Path(filename).name}", 'info')
            self._parse_firmware(section, filename)
    
    def _browse_pit(self):
        """Browse for PIT file."""
        filename = filedialog.askopenfilename(
            title="Select PIT File",
            filetypes=[("PIT files", "*.pit"), ("All files", "*.*")]
        )
        
        if filename:
            self.pit_path.set(filename)
            self._log(f"Selected PIT: {Path(filename).name}", 'info')
    
    def _parse_firmware(self, section: str, path: str):
        """Parse firmware file in background."""
        def parse():
            try:
                self.root.after(0, self._log, f"Parsing {section}...", 'info')
                
                if not self.flasher:
                    self.flasher = OdinFlasher(verbose=False, bypass_verification=self.option_bypass_verification.get())
                
                fw = self.flasher.load_firmware(path, verify_hash=False)
                self.firmware_sections[section] = fw
                
                self.root.after(0, self._log, f"✓ {section}: {len(fw.items)} items loaded", 'success')
                
                for item in fw.items:
                    size_mb = item.size / (1024 * 1024)
                    self.root.after(0, self._log, f"  • {item.filename} ({size_mb:.1f} MB)", 'info')
            
            except OdinException as e:
                self.root.after(0, self._log, f"✗ {section} error: {e.message}", 'error')
                self.firmware_sections[section] = None
            except Exception as e:
                self.root.after(0, self._log, f"✗ {section} failed: {e}", 'error')
                self.firmware_sections[section] = None
        
        threading.Thread(target=parse, daemon=True).start()
    
    # ─── Options ─────────────────────────────────────────────────────────────
    
    def _on_bypass_toggled(self):
        """Handle bypass verification toggle."""
        if self.option_bypass_verification.get():
            result = messagebox.askyesno(
                "⚠ Security Warning",
                "You are about to DISABLE signature verification!\n\n"
                "This allows flashing unsigned/modified firmware.\n\n"
                "RISKS:\n"
                "• Can permanently brick your device\n"
                "• Voids all warranties\n"
                "• Compromises device security\n\n"
                "For RESEARCH/DEVELOPMENT only!\n\n"
                "Are you sure?",
                icon='warning'
            )
            
            if not result:
                self.option_bypass_verification.set(False)
                self._log("Bypass verification cancelled", 'info')
            else:
                self._log("⚠ BYPASS ENABLED - unsigned firmware allowed!", 'warning')
        else:
            self._log("Bypass verification disabled", 'info')
    
    # ─── Flashing ────────────────────────────────────────────────────────────
    
    def _start_flashing(self):
        """Start firmware flashing process."""
        sections = {k: v for k, v in self.firmware_sections.items() if v is not None}
        
        if not sections:
            messagebox.showerror("Error", "Select at least one firmware section")
            return
        
        if self.option_pit.get() and not self.pit_path.get():
            messagebox.showerror("Error", "Select a PIT file or disable PIT option")
            return
        
        if not self.is_connected:
            messagebox.showerror("Error", "No device connected")
            return
        
        bypass_warn = "\n\n🔥 BYPASS ENABLED: UNSIGNED FIRMWARE! 🔥" if self.option_bypass_verification.get() else ""
        
        if not messagebox.askyesno(
            "Confirm Flash",
            f"⚠ WARNING: This will flash firmware!\n\n"
            f"Sections: {', '.join(sections.keys())}{bypass_warn}\n\n"
            "• All data may be erased\n"
            "• Device may brick if interrupted\n"
            "• Ensure >50% battery\n"
            "• Keep USB connected\n\n"
            "Continue?",
            icon='warning'
        ):
            return
        
        threading.Thread(target=self._flash_firmware, daemon=True).start()
    
    def _flash_firmware(self):
        """Execute firmware flashing (background thread)."""
        try:
            self.is_flashing = True
            self.root.after(0, self._set_flashing_ui, True)
            
            self.flasher = OdinFlasher(
                verbose=self.option_verbose.get(),
                bypass_verification=self.option_bypass_verification.get()
            )
            
            sections = {k: v for k, v in self.firmware_sections.items() if v is not None}
            
            self.root.after(0, self._log, f"[1/4] Loading {len(sections)} sections...", 'info')
            
            if self.option_verify.get():
                for name in list(sections.keys()):
                    path_var = getattr(self, f"{name.lower()}_path")
                    if path_var.get():
                        self.root.after(0, self._log, f"  Verifying {name}...", 'info')
                        sections[name] = self.flasher.load_firmware(path_var.get(), verify_hash=True)
                        self.root.after(0, self._log, f"  ✓ {name} verified", 'success')
            
            if self.option_lock.get():
                for fw in sections.values():
                    if fw:
                        fw.option_lock = True
                self.root.after(0, self._log, "  Option Lock enabled", 'info')
            
            pit_data = None
            if self.option_pit.get() and self.pit_path.get():
                with open(self.pit_path.get(), 'rb') as f:
                    pit_data = f.read()
            
            self.root.after(0, self._log, "[2/4] Connecting to device...", 'info')
            device = self.flasher.connect_device()
            self.root.after(0, self._log, f"✓ Connected: {device.model_name or device.product}", 'success')
            
            self.root.after(0, self._log, "[3/4] Flashing...", 'info')
            success = self.flasher.flash_multi_section(
                sections, pit_data=pit_data,
                reboot=self.option_reboot.get(),
                reboot_to_download=False,
                progress_callback=self._update_progress
            )
            
            if success:
                self.root.after(0, self._log, "[4/4] ✓ Flash complete!", 'success')
                if self.option_reboot.get():
                    self.root.after(0, self._log, "  Device rebooting...", 'info')
                self.root.after(0, messagebox.showinfo, "Success", "Firmware flashed successfully!")
            else:
                self.root.after(0, self._log, "[4/4] ✗ Flash failed!", 'error')
                self.root.after(0, messagebox.showerror, "Error", "Flashing failed!")
            
            self.flasher.disconnect_device()
        
        except OdinException as e:
            self.root.after(0, self._log, f"✗ Error: {e.message}", 'error')
            self.root.after(0, messagebox.showerror, "Error", str(e.message))
        except Exception as e:
            self.root.after(0, self._log, f"✗ Error: {e}", 'error')
            self.root.after(0, messagebox.showerror, "Error", str(e))
        finally:
            self.is_flashing = False
            self.root.after(0, self._set_flashing_ui, False)
            self.root.after(0, self._reset_progress)
    
    def _stop_flashing(self):
        """Stop flashing (warning only)."""
        messagebox.showwarning(
            "Warning",
            "⚠ Cannot safely stop flashing!\n\n"
            "Interrupting may brick your device.\n"
            "Please wait for completion."
        )
    
    def _update_progress(self, progress: DownloadProgress):
        """Update progress from flasher callback."""
        self.root.after(0, self._update_progress_ui, progress)
    
    def _update_progress_ui(self, progress: DownloadProgress):
        """Update progress UI elements."""
        self.progress_var.set(progress.percentage)
        self.progress_label.configure(text=f"{progress.percentage:.1f}%")
        self.speed_label.configure(text=f"{progress.speed_bps / (1024*1024):.1f} MB/s")
        self.file_label.configure(text=progress.current_file)
        self.status_var.set(f"Flashing: {progress.current_file} ({progress.percentage:.1f}%)")
    
    def _reset_progress(self):
        """Reset progress UI."""
        self.progress_var.set(0)
        self.progress_label.configure(text="0%")
        self.speed_label.configure(text="— MB/s")
        self.file_label.configure(text="Waiting...")
        self.status_var.set("Ready")
    
    def _set_flashing_ui(self, flashing: bool):
        """Update UI for flashing state."""
        if flashing:
            self.flash_button.configure(state='disabled')
            self.stop_button.configure(state='normal')
            self.refresh_button.configure(state='disabled')
        else:
            self.flash_button.configure(state='normal' if self.is_connected else 'disabled')
            self.stop_button.configure(state='disabled')
            self.refresh_button.configure(state='normal')
    
    # ─── OEM Unlock ──────────────────────────────────────────────────────────
    
    def _oem_unlock(self):
        """OEM bootloader unlock."""
        if not messagebox.askokcancel(
            "OEM Unlock",
            "⚠ WARNING ⚠\n\n"
            "This will PERMANENTLY unlock the bootloader!\n\n"
            "• Wipes ALL user data\n"
            "• Voids warranty\n"
            "• May brick unsupported devices\n\n"
            "Continue?",
            icon='warning', default='cancel'
        ):
            return
        
        if not messagebox.askyesno(
            "Final Confirmation",
            "Are you ABSOLUTELY SURE?\n\nALL DATA WILL BE ERASED!",
            icon='warning', default='no'
        ):
            return
        
        threading.Thread(target=self._perform_oem_unlock, daemon=True).start()
    
    def _perform_oem_unlock(self):
        """Execute OEM unlock (background thread)."""
        try:
            self.is_flashing = True
            self.root.after(0, self._set_flashing_ui, True)
            
            flasher = OdinFlasher(verbose=self.option_verbose.get())
            
            self.root.after(0, self._log, "Connecting...", 'info')
            device = flasher.connect_device()
            self.root.after(0, self._log, f"✓ Connected: {device.model_name or device.product}", 'success')
            
            self.root.after(0, self._log, "Sending OEM unlock...", 'info')
            success = flasher.oem_unlock()
            flasher.disconnect_device()
            
            if success:
                self.root.after(0, self._log, "✓ OEM unlock sent!", 'success')
                self.root.after(0, messagebox.showinfo, "Success", "OEM unlock command sent!\nCheck device screen.")
            else:
                self.root.after(0, self._log, "✗ OEM unlock failed", 'error')
                self.root.after(0, messagebox.showerror, "Error", "OEM unlock failed or not supported.")
        
        except Exception as e:
            self.root.after(0, self._log, f"✗ Error: {e}", 'error')
            self.root.after(0, messagebox.showerror, "Error", f"OEM unlock failed:\n{e}")
        finally:
            self.is_flashing = False
            self.root.after(0, self._set_flashing_ui, False)
    
    # ─── Logging ─────────────────────────────────────────────────────────────
    
    def _log(self, message: str, level: str = 'info'):
        """Add message to log."""
        self.log_text.configure(state='normal')
        timestamp = time.strftime("%H:%M:%S")
        self.log_text.insert('end', f"[{timestamp}] {message}\n", level)
        self.log_text.see('end')
        self.log_text.configure(state='disabled')
    
    def _clear_log(self):
        """Clear log."""
        self.log_text.configure(state='normal')
        self.log_text.delete('1.0', 'end')
        self.log_text.configure(state='disabled')
    
    def _show_about(self):
        """Show about dialog."""
        messagebox.showinfo(
            "About PyOdin",
            "PyOdin v1.0.0\n\n"
            "Samsung Firmware Flasher\n\n"
            "A Python implementation of Odin,\n"
            "reverse-engineered from open-source code.\n\n"
            "⚠ WARNING:\n"
            "Flashing can brick your device.\n"
            "Use at your own risk!\n\n"
            "For educational purposes only."
        )


def main():
    """Main entry point."""
    try:
        root = tk.Tk()
        root.configure(bg=COLORS['bg_dark'])
        
        # Set minimum size
        root.minsize(800, 600)
        
        OdinGUI(root)
        root.mainloop()
        return 0
    
    except Exception as e:
        import traceback
        error = f"Fatal error:\n\n{e}\n\n{traceback.format_exc()}"
        print(error)
        try:
            messagebox.showerror("Fatal Error", error)
        except:
            pass
        return 1


if __name__ == '__main__':
    import sys
    sys.exit(main())
