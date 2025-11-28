"""
Cryptographic utilities for PyOdin

Handles MD5, SHA256, RSA verification, and AES decryption.
"""

import hashlib
from typing import Optional, Tuple
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from .exceptions import OdinVerificationError

# ============================================================================
# BOOTLOADER BYPASS (from odin4.c decompiled analysis)
# ============================================================================
# This implements the verification bypass found in Samsung's Odin4 bootloader.
# 
# Two bypass mechanisms discovered:
# 1. "NOTAPPLIED" string check - skips SHA256 verification entirely
# 2. v32 == 0 condition - bypasses all signature checks in TAR context
#
# SECURITY WARNING: This allows flashing unsigned firmware!
# ============================================================================

# Global bypass flag (mimics odin4.c offset +304 string field)
_VERIFICATION_BYPASS_ENABLED = False
_VERIFICATION_STATUS_STRING = ""  # "NOTAPPLIED" = bypass active


def enable_verification_bypass():
    """
    Enable bootloader verification bypass (DANGEROUS!)
    
    This replicates the vulnerability found in odin4.c where setting
    the verification status string to "NOTAPPLIED" bypasses all
    cryptographic verification.
    
    WARNING: This allows flashing unsigned/modified firmware!
    """
    global _VERIFICATION_BYPASS_ENABLED, _VERIFICATION_STATUS_STRING
    _VERIFICATION_BYPASS_ENABLED = True
    _VERIFICATION_STATUS_STRING = "NOTAPPLIED"
    print("[BYPASS] ⚠️  Verification bypass ENABLED - unsigned firmware allowed!")
    print("[BYPASS] ⚠️  This replicates the odin4.c security vulnerability")


def disable_verification_bypass():
    """Disable bootloader verification bypass"""
    global _VERIFICATION_BYPASS_ENABLED, _VERIFICATION_STATUS_STRING
    _VERIFICATION_BYPASS_ENABLED = False
    _VERIFICATION_STATUS_STRING = ""
    print("[BYPASS] ✓ Verification bypass disabled")


def is_bypass_enabled() -> bool:
    """Check if verification bypass is enabled"""
    return _VERIFICATION_BYPASS_ENABLED


def get_verification_status() -> str:
    """Get verification status string (mimics odin4.c +304 field)"""
    return _VERIFICATION_STATUS_STRING


def calculate_md5(data: bytes) -> str:
    """
    Calculate MD5 hash of data
    
    Args:
        data: Data to hash
        
    Returns:
        Hexadecimal MD5 hash string
    """
    md5 = hashlib.md5()
    md5.update(data)
    return md5.hexdigest()


def calculate_md5_file(filepath: str, chunk_size: int = 8192) -> str:
    """
    Calculate MD5 hash of file using streaming (memory efficient)
    
    Args:
        filepath: Path to file
        chunk_size: Chunk size for reading (default 8KB)
        
    Returns:
        Hexadecimal MD5 hash string
    """
    md5 = hashlib.md5()
    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            md5.update(chunk)
    return md5.hexdigest()


def calculate_sha256(data: bytes) -> str:
    """
    Calculate SHA256 hash of data
    
    Args:
        data: Data to hash
        
    Returns:
        Hexadecimal SHA256 hash string
    """
    sha256 = hashlib.sha256()
    sha256.update(data)
    return sha256.hexdigest()


def verify_md5(data: bytes, expected_hash: str) -> bool:
    """
    Verify MD5 hash of data
    
    Args:
        data: Data to verify
        expected_hash: Expected MD5 hash (hex string)
        
    Returns:
        True if hash matches, False otherwise
    """
    # BYPASS: Check if verification is disabled (odin4.c line 18140: || !v32)
    if _VERIFICATION_BYPASS_ENABLED:
        print("[BYPASS] MD5 verification skipped (bypass enabled)")
        return True
    
    actual_hash = calculate_md5(data)
    return actual_hash.lower() == expected_hash.lower()


def verify_sha256(data: bytes, expected_hash: str) -> bool:
    """
    Verify SHA256 hash of data
    
    Args:
        data: Data to verify
        expected_hash: Expected SHA256 hash (hex string)
        
    Returns:
        True if hash matches, False otherwise
    """
    # BYPASS: Check "NOTAPPLIED" status (odin4.c line 16353)
    if _VERIFICATION_STATUS_STRING == "NOTAPPLIED":
        print("[BYPASS] SHA256 verification skipped (NOTAPPLIED)")
        return True
    
    actual_hash = calculate_sha256(data)
    return actual_hash.lower() == expected_hash.lower()


def verify_rsa_signature(
    data: bytes,
    signature: bytes,
    public_key_pem: bytes,
    hash_algorithm: str = "SHA256"
) -> bool:
    """
    Verify RSA signature using PKCS1v15 padding
    
    Args:
        data: Data that was signed
        signature: RSA signature to verify
        public_key_pem: Public key in PEM format
        hash_algorithm: Hash algorithm used (SHA256, SHA1, etc.)
        
    Returns:
        True if signature is valid, False otherwise
    """
    # BYPASS: Replicate odin4.c Manifest::rsaVerify bypass behavior
    if _VERIFICATION_BYPASS_ENABLED:
        print("[BYPASS] RSA signature verification skipped (bypass enabled)")
        return True
    
    try:
        # Load public key
        public_key = serialization.load_pem_public_key(
            public_key_pem,
            backend=default_backend()
        )
        
        # Select hash algorithm
        if hash_algorithm.upper() == "SHA256":
            hash_algo = hashes.SHA256()
        elif hash_algorithm.upper() == "SHA1":
            hash_algo = hashes.SHA1()
        elif hash_algorithm.upper() == "MD5":
            hash_algo = hashes.MD5()
        else:
            raise OdinVerificationError(f"Unsupported hash algorithm: {hash_algorithm}")
        
        # Verify signature
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hash_algo
        )
        return True
        
    except Exception as e:
        print(f"RSA verification failed: {e}")
        return False


def aes_decrypt_cbc(data: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Decrypt data using AES-CBC mode
    
    Args:
        data: Encrypted data
        key: AES key (128, 192, or 256 bits)
        iv: Initialization vector (16 bytes)
        
    Returns:
        Decrypted data
    """
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(data)
        # Remove PKCS7 padding
        return unpad(decrypted, AES.block_size)
    except Exception as e:
        raise OdinVerificationError(f"AES decryption failed: {e}")


def extract_public_key_from_signature(signature_data: bytes) -> Optional[bytes]:
    """
    Extract public key from signature data (if embedded)
    
    Args:
        signature_data: Signature data that may contain embedded public key
        
    Returns:
        Public key in PEM format, or None if not found
    """
    # Look for PEM markers
    pem_start = signature_data.find(b"-----BEGIN PUBLIC KEY-----")
    pem_end = signature_data.find(b"-----END PUBLIC KEY-----")
    
    if pem_start != -1 and pem_end != -1:
        return signature_data[pem_start:pem_end + len(b"-----END PUBLIC KEY-----")]
    
    return None


def verify_manifest_signature(
    manifest_data: bytes,
    signature: bytes,
    public_key_pem: Optional[bytes] = None
) -> bool:
    """
    Verify manifest signature (Samsung specific)
    
    Args:
        manifest_data: Manifest data to verify
        signature: RSA signature
        public_key_pem: Public key in PEM format (optional, will try to extract)
        
    Returns:
        True if signature is valid, False otherwise
    """
    if public_key_pem is None:
        # Try to extract public key from signature
        public_key_pem = extract_public_key_from_signature(signature)
        
        if public_key_pem is None:
            print("Warning: No public key available for verification")
            return False
    
    return verify_rsa_signature(manifest_data, signature, public_key_pem, "SHA256")


class CryptoVerifier:
    """
    Unified crypto verification class
    """
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
    
    def verify_firmware_hash(
        self,
        data: bytes,
        hash_value: str,
        algorithm: str = "MD5"
    ) -> bool:
        """
        Verify firmware hash
        
        Args:
            data: Firmware data
            hash_value: Expected hash value (hex string)
            algorithm: Hash algorithm (MD5 or SHA256)
            
        Returns:
            True if hash is valid
        """
        # BYPASS: Check if verification is disabled
        if _VERIFICATION_BYPASS_ENABLED:
            if self.verbose:
                print(f"[BYPASS] {algorithm} hash verification skipped")
            return True
        
        if self.verbose:
            print(f"Verifying {algorithm} hash...")
        
        algorithm = algorithm.upper()
        
        if algorithm == "MD5":
            result = verify_md5(data, hash_value)
        elif algorithm == "SHA256":
            result = verify_sha256(data, hash_value)
        else:
            raise OdinVerificationError(f"Unsupported algorithm: {algorithm}")
        
        if self.verbose:
            print(f"Hash verification: {'PASS' if result else 'FAIL'}")
        
        return result
    
    def verify_firmware_signature(
        self,
        data: bytes,
        signature: bytes,
        public_key: Optional[bytes] = None
    ) -> bool:
        """
        Verify firmware signature
        
        Args:
            data: Firmware data
            signature: RSA signature
            public_key: Public key in PEM format (optional)
            
        Returns:
            True if signature is valid
        """
        # BYPASS: Check if verification is disabled
        if _VERIFICATION_BYPASS_ENABLED:
            if self.verbose:
                print("[BYPASS] RSA signature verification skipped")
            return True
        
        if self.verbose:
            print("Verifying RSA signature...")
        
        result = verify_manifest_signature(data, signature, public_key)
        
        if self.verbose:
            print(f"Signature verification: {'PASS' if result else 'FAIL'}")
        
        return result
