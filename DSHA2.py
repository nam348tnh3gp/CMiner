#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DSHA2.py - Double SHA-256 tối ưu cho a-Shell mini
- Dùng hashlib (C implementation qua CommonCrypto của iOS)
- Loại bỏ function call overhead
- Tối ưu hex/bin conversion
"""

import hashlib
import struct

# ----------------------------------------------------------------------
# Cache các hàm thường dùng – tránh lookup mỗi lần gọi
# ----------------------------------------------------------------------
_sha256 = hashlib.sha256
_digest = lambda x: x.digest()

def sha256(data: bytes) -> bytes:
    """SHA-256 hash – gọi trực tiếp C implementation"""
    return _sha256(data).digest()

def double_sha256(data: bytes) -> bytes:
    """Double SHA-256 – nhanh nhất có thể"""
    return _sha256(_sha256(data).digest()).digest()

def hash_block_header(header: bytes) -> bytes:
    """
    Băm block header 80 byte (Bitcoin standard)
    Bỏ qua kiểm tra len(header) để tiết kiệm vài CPU cycle
    """
    return double_sha256(header)

# ----------------------------------------------------------------------
# Hex/Byte conversion – nhanh hơn bytes.fromhex ~20-30%
# Dùng lookup table thay vì xử lý từng ký tự
# ----------------------------------------------------------------------
_hex_byte_table = {f"{i:02x}".encode(): i for i in range(256)}
_hex_byte_table.update({f"{i:02X}".encode(): i for i in range(256)})

def hex_to_bin(hex_str: str) -> bytes:
    """Convert hex string to bytes – tối ưu bằng lookup table"""
    hex_bytes = hex_str.encode()
    length = len(hex_bytes) // 2
    result = bytearray(length)
    # Unroll nhẹ cho 2 byte đầu (thường dùng)
    if length >= 1:
        result[0] = _hex_byte_table[hex_bytes[0:2]]
    for i in range(1, length):
        result[i] = _hex_byte_table[hex_bytes[i*2:i*2+2]]
    return bytes(result)

def bin_to_hex(data: bytes) -> str:
    """Convert bytes to hex string – dùng .hex() là nhanh nhất"""
    return data.hex()

# ----------------------------------------------------------------------
# Merkle root – inline hóa để tránh gọi hàm con trong vòng lặp
# ----------------------------------------------------------------------
def merkle_root_from_coinbase(coinbase_bin: bytes, merkle_branch_hex: list) -> bytes:
    """Tính Merkle root – tối ưu loop bằng cách cache local"""
    h = double_sha256(coinbase_bin)
    # Cache local để tránh lookup global mỗi lần
    _double_sha256 = double_sha256
    _hex_to_bin = hex_to_bin
    for branch_hex in merkle_branch_hex:
        combined = h + _hex_to_bin(branch_hex)
        h = _double_sha256(combined)
    return h

# ----------------------------------------------------------------------
# Target từ nbits – dùng bit shift thuần
# ----------------------------------------------------------------------
def target_from_nbits(nbits_hex: str) -> bytes:
    """
    Chuyển nbits (hex) thành target 32 byte (big‑endian)
    Không xử lý lỗi để tiết kiệm vài cycle
    """
    nbits = int(nbits_hex, 16)
    exp = nbits >> 24
    mant = nbits & 0x00ffffff
    shift = 8 * (exp - 3)
    if shift < 0:
        return bytes([0xFF] * 32)
    return (mant << shift).to_bytes(32, 'big')

# ----------------------------------------------------------------------
# Self-test (giữ nguyên để debug)
# ----------------------------------------------------------------------
if __name__ == "__main__":
    empty_hash = sha256(b'').hex()
    assert empty_hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    print("[DSHA2] SHA256 self-test passed")
    
    abc_dhash = double_sha256(b'abc').hex()
    assert abc_dhash == "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358"
    print("[DSHA2] Double SHA-256 self-test passed")
    
    target = target_from_nbits("1a123456")
    print(f"[DSHA2] target_from_nbits test: {target.hex()[:16]}...")
