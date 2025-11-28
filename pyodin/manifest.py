"""
Manifest file handling

Handles Samsung firmware manifest files with RSA signature verification.
"""

import struct
from typing import Optional, Dict, Any
from dataclasses import dataclass, field

from .exceptions import OdinFirmwareError, OdinVerificationError
from .crypto_utils import (
    verify_rsa_signature,
    aes_decrypt_cbc,
    is_bypass_enabled,
    get_verification_status
)


@dataclass
class ManifestInfo:
    """Manifest file information"""
    version: str = ""
    model: str = ""
    region: str = ""
    carrier: str = ""
    build_date: str = ""
    firmware_version: str = ""
    bootloader_version: str = ""
    modem_version: str = ""
    csc_version: str = ""
    
    # Metadata
    files: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    signature: bytes = b""
    public_key: bytes = b""
    
    def __repr__(self) -> str:
        return f"ManifestInfo(model='{self.model}', version='{self.firmware_version}')"


class ManifestParser:
    """
    Manifest file parser
    
    Parses Samsung firmware manifest files and verifies signatures.
    """
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
    
    def log(self, message: str):
        """Print log message if verbose"""
        if self.verbose:
            print(f"[ManifestParser] {message}")
    
    def parse(self, manifest_data: bytes) -> ManifestInfo:
        """
        Parse manifest data
        
        Args:
            manifest_data: Raw manifest file data
            
        Returns:
            ManifestInfo object
        """
        self.log(f"Parsing manifest ({len(manifest_data)} bytes)...")
        
        manifest = ManifestInfo()
        
        try:
            # Try to parse as text manifest
            text = manifest_data.decode('utf-8', errors='ignore')
            self._parse_text_manifest(text, manifest)
            
        except Exception as e:
            self.log(f"Warning: Failed to parse as text manifest: {e}")
        
        return manifest
    
    def _parse_text_manifest(self, text: str, manifest: ManifestInfo):
        """Parse text-based manifest"""
        lines = text.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Parse key=value pairs
            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip().lower()
                value = value.strip()
                
                if key == 'model':
                    manifest.model = value
                elif key == 'version':
                    manifest.firmware_version = value
                elif key == 'region':
                    manifest.region = value
                elif key == 'carrier':
                    manifest.carrier = value
                elif key == 'date' or key == 'build_date':
                    manifest.build_date = value
                elif key == 'bootloader':
                    manifest.bootloader_version = value
                elif key == 'modem':
                    manifest.modem_version = value
                elif key == 'csc':
                    manifest.csc_version = value
        
        self.log(f"Parsed manifest: {manifest}")
    
    def is_manifest_file(self, filename: str) -> bool:
        """Check if filename is a manifest file"""
        manifest_names = [
            'manifest.xml',
            'manifest.txt',
            'META-INF/MANIFEST.MF',
            '.manifest'
        ]
        
        filename_lower = filename.lower()
        return any(name in filename_lower for name in manifest_names)
    
    def is_meta_file(self, filename: str) -> bool:
        """Check if filename is a metadata file"""
        meta_names = [
            '.meta',
            'meta.xml',
            'meta.txt',
            'META-INF/'
        ]
        
        filename_lower = filename.lower()
        return any(name in filename_lower for name in meta_names)
    
    def compare_model(self, manifest: ManifestInfo, expected_model: str) -> bool:
        """
        Compare manifest model with expected model
        
        Args:
            manifest: Manifest info
            expected_model: Expected model name
            
        Returns:
            True if models match
        """
        if not manifest.model or not expected_model:
            return True  # Skip comparison if either is empty
        
        # Normalize models (remove spaces, case insensitive)
        model1 = manifest.model.replace(' ', '').replace('-', '').lower()
        model2 = expected_model.replace(' ', '').replace('-', '').lower()
        
        return model1 == model2
    
    def verify_signature(
        self,
        manifest_data: bytes,
        signature: bytes,
        public_key: Optional[bytes] = None
    ) -> bool:
        """
        Verify manifest RSA signature
        
        Args:
            manifest_data: Manifest data
            signature: RSA signature
            public_key: Public key (optional)
            
        Returns:
            True if signature is valid
        """
        # BYPASS: Check "NOTAPPLIED" status (odin4.c line 16353)
        if get_verification_status() == "NOTAPPLIED":
            self.log("[BYPASS] Manifest signature verification skipped (NOTAPPLIED)")
            return True
        
        # BYPASS: Check if verification is globally disabled (odin4.c line 18140: || !v32)
        if is_bypass_enabled():
            self.log("[BYPASS] Manifest signature verification skipped (bypass enabled)")
            return True
        
        self.log("Verifying manifest signature...")
        
        try:
            if public_key is None:
                # Try to extract public key from signature data
                public_key = self._extract_public_key(signature)
            
            if public_key is None:
                self.log("Warning: No public key available")
                return False
            
            result = verify_rsa_signature(manifest_data, signature, public_key, "SHA256")
            
            self.log(f"Signature verification: {'PASS' if result else 'FAIL'}")
            
            return result
            
        except Exception as e:
            self.log(f"Signature verification error: {e}")
            return False
    
    def _extract_public_key(self, signature_data: bytes) -> Optional[bytes]:
        """Extract public key from signature data"""
        # Look for PEM markers
        pem_start = signature_data.find(b"-----BEGIN PUBLIC KEY-----")
        pem_end = signature_data.find(b"-----END PUBLIC KEY-----")
        
        if pem_start != -1 and pem_end != -1:
            return signature_data[pem_start:pem_end + len(b"-----END PUBLIC KEY-----")]
        
        return None
    
    def decrypt_manifest(
        self,
        encrypted_data: bytes,
        key: bytes,
        iv: bytes
    ) -> bytes:
        """
        Decrypt AES-encrypted manifest
        
        Args:
            encrypted_data: Encrypted manifest data
            key: AES key
            iv: Initialization vector
            
        Returns:
            Decrypted manifest data
        """
        self.log("Decrypting manifest...")
        
        try:
            decrypted = aes_decrypt_cbc(encrypted_data, key, iv)
            self.log(f"Decrypted {len(decrypted)} bytes")
            return decrypted
            
        except Exception as e:
            raise OdinVerificationError(f"Manifest decryption failed: {e}")
    
    def get_dump_path(self, filename: str) -> str:
        """
        Get dump path for file (for debugging)
        
        Args:
            filename: Original filename
            
        Returns:
            Dump path
        """
        import os
        
        dump_dir = "odin_dumps"
        os.makedirs(dump_dir, exist_ok=True)
        
        return os.path.join(dump_dir, filename)









































