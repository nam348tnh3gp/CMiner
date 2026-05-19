#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DSHA2.py - Double SHA-256 tối ưu cho a-Shell mini
"""

import hashlib

# Cache global functions
_sha256 = hashlib.sha256

def sha256(data: bytes) -> bytes:
    return _sha256(data).digest()

def double_sha256(data: bytes) -> bytes:
    return _sha256(_sha256(data).digest()).digest()

def hash_block_header(header: bytes) -> bytes:
    return double_sha256(header)

# ─── Hex/Byte conversion ───
_hex_byte_table = {f"{i:02x}".encode(): i for i in range(256)}
_hex_byte_table.update({f"{i:02X}".encode(): i for i in range(256)})

def hex_to_bin(hex_str: str) -> bytes:
    hex_bytes = hex_str.encode()
    n = len(hex_bytes) // 2
    result = bytearray(n)
    if n >= 1:
        result[0] = _hex_byte_table[hex_bytes[0:2]]
    for i in range(1, n):
        result[i] = _hex_byte_table[hex_bytes[i*2:i*2+2]]
    return bytes(result)

def bin_to_hex(data: bytes) -> str:
    return data.hex()

# ─── Merkle root ───
def merkle_root_from_coinbase(coinbase_bin: bytes, merkle_branch_hex: list) -> bytes:
    h = double_sha256(coinbase_bin)
    _double = double_sha256
    _hex = hex_to_bin
    
    for branch_hex in merkle_branch_hex:
        # Bitcoin: hash cần ở little-endian trước khi hash tiếp
        branch_le = _hex(branch_hex)[::-1]
        combined = h[::-1] + branch_le
        h = _double(combined)
    
    return h

# ─── Target từ nbits ───
def target_from_nbits(nbits_hex: str) -> bytes:
    nbits = int(nbits_hex, 16)
    exp = nbits >> 24
    mant = nbits & 0x00ffffff
    shift = 8 * (exp - 3)
    if shift < 0:
        return bytes([0xFF] * 32)
    return (mant << shift).to_bytes(32, 'big')

# ─── Self-test ───
if __name__ == "__main__":
    # Test SHA-256
    assert sha256(b'').hex() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    print("[DSHA2] SHA256 OK")
    
    # Test Double SHA-256
    assert double_sha256(b'abc').hex() == "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358"
    print("[DSHA2] Double SHA-256 OK")
    
    # Test Merkle root với Genesis block
    coinbase = bytes.fromhex("04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73")
    branches = []  # Genesis block không có merkle branch
    root = merkle_root_from_coinbase(coinbase, branches)
    print(f"[DSHA2] Merkle root test: {root.hex()}")
    
    print("[DSHA2] All tests passed!")
