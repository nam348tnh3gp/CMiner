#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DSHA2.py - Double SHA-256 utilities for Stratum Miner
Dùng hashlib để tối ưu tốc độ (C implementation)
"""

import hashlib
import struct

def sha256(data: bytes) -> bytes:
    """SHA-256 hash, trả về bytes (big‑endian)"""
    return hashlib.sha256(data).digest()

def double_sha256(data: bytes) -> bytes:
    """Double SHA-256 (SHA256d)"""
    return sha256(sha256(data))

def hash_block_header(header: bytes) -> bytes:
    """
    Băm block header 80 byte theo chuẩn Bitcoin:
        hash = double_sha256(header)
    Trả về 32 byte (big‑endian)
    """
    if len(header) != 80:
        raise ValueError("Header must be exactly 80 bytes")
    return double_sha256(header)

def bin_to_hex(data: bytes) -> str:
    """Chuyển bytes -> hex string (lowercase)"""
    return data.hex()

def hex_to_bin(hex_str: str) -> bytes:
    """Chuyển hex string -> bytes (bỏ qua khoảng trắng nếu có)"""
    hex_str = hex_str.strip()
    if len(hex_str) % 2 != 0:
        raise ValueError("Hex string length must be even")
    return bytes.fromhex(hex_str)

def merkle_root_from_coinbase(coinbase_bin: bytes, merkle_branch_hex: list) -> bytes:
    """
    Tính Merkle root từ coinbase và các branch (theo thứ tự từ pool)
    Dùng double SHA-256 cho mỗi bước.
    """
    h = double_sha256(coinbase_bin)
    for branch_hex in merkle_branch_hex:
        branch_bin = hex_to_bin(branch_hex)
        combined = h + branch_bin
        h = double_sha256(combined)
    return h

def target_from_nbits(nbits_hex: str) -> bytes:
    """
    Chuyển nbits (hex string, big‑endian, ví dụ "1a123456") thành target 32 byte (big‑endian)
    Công thức:
        exp = nbits >> 24
        mant = nbits & 0x00ffffff
        target = mant * 2^(8*(exp - 3))
    """
    nbits = int(nbits_hex, 16)
    exp = nbits >> 24
    mant = nbits & 0x00ffffff
    shift = 8 * (exp - 3)
    if shift < 0:
        # Giá trị mặc định cho trường hợp lỗi
        return bytes([0xFF] * 32)
    target_val = mant << shift
    # Chuyển thành bytes big‑endian 32 byte
    target_bytes = target_val.to_bytes(32, 'big')
    return target_bytes

# -------------------------------------------------------
# Tự kiểm tra nhanh nếu chạy file này trực tiếp
# -------------------------------------------------------
if __name__ == "__main__":
    # Test vector: empty string -> SHA256
    empty_hash = sha256(b'').hex()
    assert empty_hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    print("[DSHA2] SHA256 self-test passed")

    # Test double SHA-256 của "abc"
    abc_dhash = double_sha256(b'abc').hex()
    # Giá trị mong đợi: double SHA-256 của "abc" = SHA256(SHA256("abc"))
    # SHA256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    # SHA256(that) = 4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358
    assert abc_dhash == "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358"
    print("[DSHA2] Double SHA-256 self-test passed")

    # Test target_from_nbits
    # Ví dụ nbits "1a123456" (block 1) -> target có 0x123456 * 2^(8*(0x1a-3))
    target = target_from_nbits("1a123456")
    print(f"[DSHA2] target_from_nbits test: {target.hex()}")
