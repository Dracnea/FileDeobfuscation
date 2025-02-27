#!/usr/bin/env python3
import os
import base64
import string
import itertools
import argparse

def main():
    # ========== 0. User Settings ==========
    parser = argparse.ArgumentParser(description="XOR deobfuscation script")
    parser.add_argument("file_path", type=str, help="Input file to analyze")
    parser.add_argument("output_path", type=str, help="Where to output XOR'd data")
    parser.add_argument("chosen_key", type=int, nargs='?', default=32, help="XOR key to use (default: 32)")
    args = parser.parse_args()

    file_path = args.file_path
    output_path = args.output_path
    chosen_key = args.chosen_key

    # ========== 1. Read the Binary File ==========
    print(f"Reading file: {file_path}")
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Could not open file: {file_path}")

    with open(file_path, "rb") as f:
        data = f.read()

    data_len = len(data)
    print(f"File size: {data_len} bytes\n")

    # Optional: Inspect the first few bytes in hex
    first_bytes = data[:32]
    print("First 32 bytes (hex):")
    print(" ".join(f"{b:02X}" for b in first_bytes))
    print()

    # ========== Quick Check: Known Signatures Without XOR ==========
    signatures = [
        ("ZIP", [0x50, 0x4B, 0x03, 0x04]),
        ("PDF", [0x25, 0x50, 0x44, 0x46]),
        ("EXE", [0x4D, 0x5A]),
        ("PNG", [0x89, 0x50, 0x4E, 0x47]),
        ("ELF", [0x7F, 0x45, 0x4C, 0x46]),
    ]

    for file_type, sig_bytes in signatures:
        sig_len = len(sig_bytes)
        if data_len >= sig_len and data[:sig_len] == bytes(sig_bytes):
            print(f"Detected a valid {file_type} signature at offset 0 with key=0.")
            print("This file does not appear to be XOR-obfuscated. Exiting.\n")
            return

    # ========== 2. Check if File Is Valid Base64 ==========
    valid_b64_set = set(string.ascii_uppercase + string.ascii_lowercase + string.digits + "+/=")
    char_data = data.decode("latin-1", errors="ignore")
    is_base64_char = [c in valid_b64_set for c in char_data]
    if all(is_base64_char) and data_len > 0:
        print("Entire file is valid Base64 characters. Decoding...")
        decoded_data = base64.b64decode(data)
        print(f"Decoded data size: {len(decoded_data)} bytes\n")
        # You can further analyze decoded_data if needed

    # ========== 3. Basic Frequency / Entropy Scan ==========
    entropy = calculate_entropy(data)
    print(f"File entropy: {entropy:.2f} bits per byte")
    # A high entropy (> ~7.5) might indicate compression/encryption
    if entropy > 7.5:
        print("High entropy detected. File might be compressed or encrypted.\n")
    else:
        print("Entropy appears relatively low.\n")

    # ========== 4. Known Packer / Compression Signatures ==========
    packer_signatures = [
        ("UPX", b"UPX!"),         # Common UPX marker
        ("gzip", b"\x1F\x8B"),      # gzip
        ("bzip2", b"BZh"),         # bzip2
        ("LZMA", b"\x5D\x00\x00\x80")  # A possible LZMA header fragment
    ]
    print("--- Scanning for packer/compression signatures ---")
    for packer_name, marker in packer_signatures:
        if data.find(marker) != -1:
            print(f"Detected packer/compression marker: {packer_name} (marker: {marker})")
    print()

    # ========== 5. Single-Byte XOR Brute Force Checks ==========
    N = min(data_len, 2000)  # Check up to 2000 bytes
    print(f"--- Single-byte XOR: Checking for mostly printable text (first {N} bytes) ---")
    for key in range(256):
        test_data = bytes(byte ^ key for byte in data[:N])
        num_printable = sum(32 <= b <= 126 for b in test_data)
        if (num_printable / N) > 0.8:
            pct_printable = (num_printable / N) * 100
            print(f"Key {key:3d}: ~{pct_printable:.0f}% printable")
    print()

    print("--- Single-byte XOR: Checking known signatures under XOR ---")
    for file_type, sig_bytes in signatures:
        sig_len = len(sig_bytes)
        if data_len < sig_len:
            continue
        for key in range(256):
            test_data = bytes(byte ^ key for byte in data[:sig_len])
            if list(test_data) == sig_bytes:
                print(f"Key {key:3d} yields a valid {file_type} signature at offset 0")
    print()

    print("--- Single-byte XOR: Searching for known strings ---")
    known_strings = ["ERROR", "CONFIG_VERSION=", "HELLO_WORLD", "SOME_KNOWN_STRING"]
    for key in range(256):
        test_data_chars = "".join(chr(byte ^ key) for byte in data)
        for ks in known_strings:
            if ks.lower() in test_data_chars.lower():
                print(f'Key {key:3d} reveals string "{ks}"')
    print()

    # ========== 6. Multi-byte XOR Checks (2-byte repeating key) ==========
    # WARNING: This brute-force check runs 256*256 iterations.
    print("--- Multi-byte XOR (2-byte key) signature checks ---")
    sample_len = 16  # Use the first 16 bytes to test known signatures
    for key_tuple in itertools.product(range(256), repeat=2):
        key_bytes = bytes(key_tuple)
        # Apply the repeating key XOR on the sample
        test_data = apply_repeating_xor(data[:sample_len], key_bytes)
        # Check against each known signature (if signature length <= sample_len)
        for file_type, sig_bytes in signatures:
            if len(sig_bytes) <= sample_len and list(test_data[:len(sig_bytes)]) == sig_bytes:
                print(f"Multi-byte key {key_bytes.hex()} yields a valid {file_type} signature at offset 0")
    print()

    # ========== 7. Bit-Rotation (Left Shift) Checks ==========
    # Try rotations from 1 to 7 bits on the first few bytes
    print("--- Bit-rotation (left shift) checks ---")
    for rot in range(1, 8):
        rotated = bytes(rotate_left(b, rot) for b in data[:8])
        for file_type, sig_bytes in signatures:
            if len(sig_bytes) <= len(rotated) and list(rotated[:len(sig_bytes)]) == sig_bytes:
                print(f"Rotation of {rot} bits yields a valid {file_type} signature at offset 0")
    print()

    # ========== 8. Output the File Using Your Chosen Key ==========
    # (This is still run even if obfuscation is not detected; adjust as needed.)
    print(f"Using chosen_key = {chosen_key} to create: {output_path}")
    out_data = bytes(byte ^ chosen_key for byte in data)
    with open(output_path, "wb") as f_out:
        f_out.write(out_data)
    print(f"Wrote {len(out_data)} bytes to {output_path}")

def apply_repeating_xor(data_bytes: bytes, key: bytes) -> bytes:
    """
    Apply repeating-key XOR to data_bytes.
    """
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data_bytes))

def rotate_left(byte: int, r: int) -> int:
    """
    Rotate an 8-bit byte left by r bits.
    """
    return ((byte << r) | (byte >> (8 - r))) & 0xFF

def calculate_entropy(byte_array: bytes) -> float:
    """
    Calculate Shannon entropy (in bits/byte) for the given byte array.
    """
    from math import log2
    if not byte_array:
        return 0.0
    counts = [0] * 256
    for b in byte_array:
        counts[b] += 1
    total = len(byte_array)
    probs = [count / total for count in counts if count > 0]
    entropy = -sum(p * log2(p) for p in probs)
    return entropy

if __name__ == "__main__":
    main()
