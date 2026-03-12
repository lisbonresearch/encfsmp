#!/usr/bin/env python3
"""
EncFSMP Python Implementation
Compatible with EncFSMP C++ implementation

Usage:
    python3 encfsmp.py <config.xml> <src_dir> <dst_dir> <decrypt|encrypt>

Refer to CRYPTO.md for a detailed description of the algorithms.
"""

import sys
import os
import argparse
import getpass
import xml.etree.ElementTree as ET
import base64
import struct
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

KEY_CHECKSUM_BYTES = 4  # bytes of checksum prepended to the encoded key blob
HEADER_SIZE = 8         # bytes of per-file IV header (when uniqueIV=True)
MAX_IVLENGTH = 16       # maximum IV length (AES)

# Custom EncFS Base-64 alphabet (values 0-63 → characters)
# Built from B64ToAscii in base64.cpp:
#   0-11  → table ",-0123456789"
#   12-37 → 'A'-'Z'
#   38-63 → 'a'-'z'
_B64_CHARS = ',-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
assert len(_B64_CHARS) == 64

# Reverse lookup: ASCII character → 6-bit value
_ASCII_TO_B64 = {c: i for i, c in enumerate(_B64_CHARS)}


# ---------------------------------------------------------------------------
# Custom Base-64 helpers (LSB-first bit packing, EncFS alphabet)
# ---------------------------------------------------------------------------

def _b64_enc(data: bytes) -> str:
    """Encode raw bytes to EncFS custom Base-64 string (LSB-first, no padding).

    Equivalent to changeBase2Inline(data, 8→6, partial=True) + B64ToAscii.
    """
    work = 0
    work_bits = 0
    result = []
    for byte in data:
        work |= byte << work_bits
        work_bits += 8
        while work_bits >= 6:
            result.append(_B64_CHARS[work & 0x3F])
            work >>= 6
            work_bits -= 6
    if work_bits > 0:
        result.append(_B64_CHARS[work & 0x3F])
    return ''.join(result)


def _b64_dec(s: str, output_len: int) -> bytes:
    """Decode EncFS custom Base-64 string to raw bytes (LSB-first, no padding).

    Equivalent to AsciiToB64(s) + changeBase2Inline(6→8, partial=False).
    *output_len* is the expected number of output bytes (truncate to this).
    """
    work = 0
    work_bits = 0
    result = bytearray()
    for ch in s:
        v = _ASCII_TO_B64.get(ch)
        if v is None:
            raise ValueError(f"Invalid EncFS Base-64 character: {ch!r}")
        work |= v << work_bits
        work_bits += 6
        while work_bits >= 8:
            result.append(work & 0xFF)
            work >>= 8
            work_bits -= 8
    return bytes(result[:output_len])


def _b256_to_b64_bytes(n: int) -> int:
    """Number of 6-bit (Base-64) output characters for *n* input bytes."""
    return (n * 8 + 5) // 6  # round up


def _b64_to_b256_bytes(n: int) -> int:
    """Number of output bytes for *n* Base-64 (6-bit) input characters."""
    return (n * 6) // 8  # round down


# ---------------------------------------------------------------------------
# Configuration parsing
# ---------------------------------------------------------------------------

def parse_config(xml_path: str) -> dict:
    """Parse an EncFS .encfs6.xml configuration file.

    Returns a dict with all relevant fields.
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()

    # Support both <boost_serialization>/<cfg>/... and <config>/...
    cfg = root.find('.//cfg')
    if cfg is None:
        cfg = root.find('.//config')
    if cfg is None:
        cfg = root  # fallback – try root element itself

    def _text(tag, default=None):
        el = cfg.find(tag)
        if el is None:
            return default
        return el.text.strip() if el.text else default

    def _int(tag, default=0):
        v = _text(tag)
        return int(v) if v is not None else default

    def _bool(tag, default=False):
        v = _text(tag)
        if v is None:
            return default
        return v.strip() not in ('0', 'false', 'False')

    # Cipher algorithm
    cipher_name_el = cfg.find('cipherAlg/name')
    cipher_name = cipher_name_el.text.strip() if cipher_name_el is not None else 'ssl/aes'

    name_alg_el = cfg.find('nameAlg/name')
    name_alg = name_alg_el.text.strip() if name_alg_el is not None else 'nameio/block'

    key_size_bits = _int('keySize', 192)
    block_size = _int('blockSize', 1024)

    unique_iv = _bool('uniqueIV', True)
    chained_name_iv = _bool('chainedNameIV', True)
    external_iv_chaining = _bool('externalIVChaining', False)
    block_mac_bytes = _int('blockMACBytes', 0)
    block_mac_rand_bytes = _int('blockMACRandBytes', 0)
    allow_holes = _bool('allowHoles', True)

    encoded_key_size = _int('encodedKeySize')
    encoded_key_data_b64 = _text('encodedKeyData', '')
    salt_len = _int('saltLen', 0)
    salt_data_b64 = _text('saltData', '')
    kdf_iterations = _int('kdfIterations', 0)

    # Decode standard-base64 fields
    encoded_key_data = base64.b64decode(encoded_key_data_b64.replace('\n', '').strip())
    salt = base64.b64decode(salt_data_b64.replace('\n', '').strip()) if salt_data_b64 else b''

    # Determine cipher block/IV size
    if cipher_name == 'ssl/blowfish':
        iv_length = 8
    else:
        iv_length = 16  # AES and CAMELLIA

    # Cipher block size: 16 bytes for AES/CAMELLIA, 8 bytes for Blowfish
    # This is used for filename encryption padding (different from file data block_size)
    if cipher_name == 'ssl/blowfish':
        cipher_block_size = 8
    else:
        cipher_block_size = 16  # AES and CAMELLIA

    return {
        'cipher_name': cipher_name,
        'name_alg': name_alg,
        'key_size_bits': key_size_bits,
        'key_size': key_size_bits // 8,
        'iv_length': iv_length,
        'block_size': block_size,           # file data block size (e.g. 1024)
        'cipher_block_size': cipher_block_size,  # cipher block size (e.g. 16 for AES)
        'unique_iv': unique_iv,
        'chained_name_iv': chained_name_iv,
        'external_iv_chaining': external_iv_chaining,
        'block_mac_bytes': block_mac_bytes,
        'block_mac_rand_bytes': block_mac_rand_bytes,
        'allow_holes': allow_holes,
        'encoded_key_size': encoded_key_size,
        'encoded_key_data': encoded_key_data,
        'salt': salt,
        'kdf_iterations': kdf_iterations,
    }


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

def derive_password_key(password: str, config: dict) -> tuple:
    """Derive the password-based key and IV from the config.

    Returns (password_key: bytes, password_iv: bytes).
    """
    key_size = config['key_size']
    iv_length = config['iv_length']
    salt = config['salt']
    iterations = config['kdf_iterations']

    total = key_size + iv_length
    if salt and iterations > 0:
        # Modern: PBKDF2-HMAC-SHA1
        key_material = hashlib.pbkdf2_hmac(
            'sha1',
            password.encode('utf-8'),
            salt,
            iterations,
            total,
        )
    else:
        # Legacy: BytesToKey (iterated SHA1, no salt)
        key_material = _bytes_to_key(password.encode('utf-8'), total)

    return key_material[:key_size], key_material[key_size:]


def _bytes_to_key(password: bytes, total: int) -> bytes:
    """Legacy EVP_BytesToKey-style key derivation (no salt, 16 SHA1 rounds).

    This matches the C++ BytesToKey() function used for old config files.
    """
    result = b''
    prev = b''
    while len(result) < total:
        d = prev + password
        for _ in range(16):
            d = hashlib.sha1(d).digest()
        result += d
        prev = d
    return result[:total]


# ---------------------------------------------------------------------------
# IV generation (setIVec – version >= 3)
# ---------------------------------------------------------------------------

def set_ivec(master_key: bytes, master_iv: bytes, seed: int, iv_length: int) -> bytes:
    """Generate the actual cipher IV from a 64-bit seed.

    Equivalent to SSL_Cipher::setIVec() for interface version >= 3.

    Algorithm:
      1. Start with master_iv bytes
      2. Serialize seed as 8 bytes little-endian
      3. Compute HMAC-SHA1(key=master_key, data=master_iv || seed_bytes)
      4. Return first iv_length bytes of HMAC digest
    """
    seed_bytes = struct.pack('<Q', seed & 0xFFFFFFFFFFFFFFFF)
    mac = hmac.new(master_key, master_iv + seed_bytes, hashlib.sha1).digest()
    return mac[:iv_length]


# ---------------------------------------------------------------------------
# Low-level cipher operations
# ---------------------------------------------------------------------------

def _cfb_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """AES-CFB128 encryption (no padding)."""
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()


def _cfb_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """AES-CFB128 decryption (no padding)."""
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    dec = cipher.decryptor()
    return dec.update(data) + dec.finalize()


def _cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """AES-CBC encryption (no padding; data must be multiple of block size)."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()


def _cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """AES-CBC decryption (no padding; data must be multiple of block size)."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    return dec.update(data) + dec.finalize()


def _cipher_encrypt(key: bytes, iv: bytes, data: bytes, mode: str) -> bytes:
    """Dispatch block/stream encryption based on mode."""
    if mode == 'cbc':
        return _cbc_encrypt(key, iv, data)
    return _cfb_encrypt(key, iv, data)


def _cipher_decrypt(key: bytes, iv: bytes, data: bytes, mode: str) -> bytes:
    """Dispatch block/stream decryption based on mode."""
    if mode == 'cbc':
        return _cbc_decrypt(key, iv, data)
    return _cfb_decrypt(key, iv, data)


# ---------------------------------------------------------------------------
# Shuffle / flip helpers (from SSL_Cipher.cpp)
# ---------------------------------------------------------------------------

def _shuffle_bytes(buf: bytearray) -> None:
    """In-place: buf[i+1] ^= buf[i] for all i in 0..len-2."""
    for i in range(len(buf) - 1):
        buf[i + 1] ^= buf[i]


def _unshuffle_bytes(buf: bytearray) -> None:
    """Reverse of _shuffle_bytes: buf[i] ^= buf[i-1] for i from end to 1."""
    for i in range(len(buf) - 1, 0, -1):
        buf[i] ^= buf[i - 1]


def _flip_bytes(buf: bytearray) -> None:
    """Reverse bytes in 64-byte chunks (matches flipBytes in SSL_Cipher.cpp)."""
    CHUNK = 64
    n = len(buf)
    offset = 0
    while offset < n:
        end = min(offset + CHUNK, n)
        buf[offset:end] = buf[offset:end][::-1]
        offset += CHUNK


# ---------------------------------------------------------------------------
# Stream cipher (double-pass, from SSL_Cipher::streamEncode/streamDecode)
# ---------------------------------------------------------------------------

def stream_encode(data: bytes, iv64: int,
                  master_key: bytes, master_iv: bytes, iv_length: int) -> bytes:
    """Double-pass stream cipher encoding.

    Steps (matching SSL_Cipher::streamEncode):
      1. shuffleBytes
      2. CFB-encrypt with setIVec(iv64)
      3. flipBytes
      4. shuffleBytes
      5. CFB-encrypt with setIVec(iv64 + 1)
    """
    buf = bytearray(data)
    _shuffle_bytes(buf)
    ivec = set_ivec(master_key, master_iv, iv64, iv_length)
    buf = bytearray(_cfb_encrypt(master_key, ivec, bytes(buf)))
    _flip_bytes(buf)
    _shuffle_bytes(buf)
    ivec = set_ivec(master_key, master_iv, iv64 + 1, iv_length)
    buf = bytearray(_cfb_encrypt(master_key, ivec, bytes(buf)))
    return bytes(buf)


def stream_decode(data: bytes, iv64: int,
                  master_key: bytes, master_iv: bytes, iv_length: int) -> bytes:
    """Double-pass stream cipher decoding.

    Steps (matching SSL_Cipher::streamDecode, reverse of streamEncode):
      1. CFB-decrypt with setIVec(iv64 + 1)
      2. unshuffleBytes
      3. flipBytes
      4. CFB-decrypt with setIVec(iv64)
      5. unshuffleBytes
    """
    buf = bytearray(data)
    ivec = set_ivec(master_key, master_iv, iv64 + 1, iv_length)
    buf = bytearray(_cfb_decrypt(master_key, ivec, bytes(buf)))
    _unshuffle_bytes(buf)
    _flip_bytes(buf)
    ivec = set_ivec(master_key, master_iv, iv64, iv_length)
    buf = bytearray(_cfb_decrypt(master_key, ivec, bytes(buf)))
    _unshuffle_bytes(buf)
    return bytes(buf)


# ---------------------------------------------------------------------------
# Block cipher (CBC mode, from SSL_Cipher::blockEncode/blockDecode)
# ---------------------------------------------------------------------------

def block_encode(data: bytes, iv64: int,
                 master_key: bytes, master_iv: bytes, iv_length: int) -> bytes:
    """CBC block cipher encoding.

    *data* must be an exact multiple of the cipher block size (16 bytes for AES).
    """
    ivec = set_ivec(master_key, master_iv, iv64, iv_length)
    return _cbc_encrypt(master_key, ivec, data)


def block_decode(data: bytes, iv64: int,
                 master_key: bytes, master_iv: bytes, iv_length: int) -> bytes:
    """CBC block cipher decoding.

    *data* must be an exact multiple of the cipher block size.
    """
    ivec = set_ivec(master_key, master_iv, iv64, iv_length)
    return _cbc_decrypt(master_key, ivec, data)


# ---------------------------------------------------------------------------
# MAC functions (from SSL_Cipher::MAC_64 / Cipher::MAC_32 / Cipher::MAC_16)
# ---------------------------------------------------------------------------

def _checksum_64_raw(master_key: bytes, data: bytes,
                     chained_iv: int = None) -> int:
    """Compute raw 64-bit HMAC-SHA1 checksum.

    Matches _checksum_64() in SSL_Cipher.cpp:
      - HMAC-SHA1 over data (+ 8-byte LE chained_iv if provided)
      - XOR-fold first 19 bytes (mdLen-1) of the 20-byte digest into 8 bytes
      - Return as big-endian uint64
    """
    h = hmac.new(master_key, data, hashlib.sha1)
    if chained_iv is not None:
        h.update(struct.pack('<Q', chained_iv & 0xFFFFFFFFFFFFFFFF))
    digest = h.digest()  # 20 bytes

    result = bytearray(8)
    # Use only the first 19 bytes (mdLen - 1 where mdLen == 20)
    for i in range(19):
        result[i % 8] ^= digest[i]

    # Assemble as big-endian uint64
    value = 0
    for byte in result:
        value = (value << 8) | byte
    return value


def mac_64(master_key: bytes, data: bytes, chained_iv: int = None):
    """Compute MAC_64 (64-bit HMAC-based checksum).

    Returns (mac64_value, new_chained_iv).  If chained_iv is None, only
    computes over data; otherwise includes chained_iv in HMAC and updates it.
    """
    value = _checksum_64_raw(master_key, data, chained_iv)
    new_iv = value if chained_iv is not None else chained_iv
    return value, new_iv


def mac_32(master_key: bytes, data: bytes, chained_iv: int = None):
    """Compute MAC_32: XOR-fold of MAC_64 into 32 bits."""
    value, new_iv = mac_64(master_key, data, chained_iv)
    mac32 = ((value >> 32) & 0xFFFFFFFF) ^ (value & 0xFFFFFFFF)
    return mac32, new_iv


def mac_16(master_key: bytes, data: bytes, chained_iv: int = None):
    """Compute MAC_16: XOR-fold of MAC_64 into 16 bits.

    Returns (mac16, new_chained_iv).
    MAC_16 calls MAC_64 which updates *chainedIV to the MAC_64 result.
    """
    value, new_iv = mac_64(master_key, data, chained_iv)
    mac32 = ((value >> 32) & 0xFFFFFFFF) ^ (value & 0xFFFFFFFF)
    mac_16_val = ((mac32 >> 16) & 0xFFFF) ^ (mac32 & 0xFFFF)
    # new_iv is the MAC_64 value (not MAC_16), matching C++ behaviour
    return mac_16_val, value  # value is the new chained IV


# ---------------------------------------------------------------------------
# Master key decryption / encryption
# ---------------------------------------------------------------------------

def decrypt_master_key(config: dict, password_key: bytes, password_iv: bytes):
    """Decrypt the master key from the config.

    Returns (master_key: bytes, master_iv: bytes).
    Raises ValueError if the password is wrong (checksum mismatch).
    """
    key_size = config['key_size']
    iv_length = config['iv_length']
    blob = config['encoded_key_data']  # raw bytes (base64-decoded already)

    # First KEY_CHECKSUM_BYTES bytes are the big-endian checksum
    checksum = struct.unpack('>I', blob[:KEY_CHECKSUM_BYTES])[0]

    # Remaining bytes are the stream-encrypted key+IV material
    encrypted = bytes(blob[KEY_CHECKSUM_BYTES: KEY_CHECKSUM_BYTES + key_size + iv_length])

    # Stream-decode using password_key / password_iv, with checksum as iv64
    decrypted = stream_decode(encrypted, checksum, password_key, password_iv, iv_length)

    # Verify checksum: MAC_32 over decrypted key material
    computed_checksum, _ = mac_32(password_key, decrypted)
    if computed_checksum != checksum:
        raise ValueError("Wrong password (checksum mismatch)")

    master_key = decrypted[:key_size]
    master_iv = decrypted[key_size: key_size + iv_length]
    return master_key, master_iv


def encrypt_master_key(master_key: bytes, master_iv: bytes,
                       password_key: bytes, password_iv: bytes,
                       key_size: int, iv_length: int) -> bytes:
    """Encrypt the master key for storage in the config file.

    Returns the raw blob: checksum(4 bytes big-endian) + encrypted(key+iv).
    """
    plain = master_key + master_iv
    checksum, _ = mac_32(password_key, plain)
    encrypted = stream_encode(plain, checksum, password_key, password_iv, iv_length)
    header = struct.pack('>I', checksum & 0xFFFFFFFF)
    return header + encrypted


# ---------------------------------------------------------------------------
# Filename encoding / decoding (BlockNameIO)
# ---------------------------------------------------------------------------

def encode_filename(plaintext: str, master_key: bytes, master_iv: bytes,
                    iv_length: int, block_size: int,
                    chained_iv: int = None) -> tuple:
    """Encrypt a single filename component.

    Returns (encrypted_name: str, new_chained_iv: int).

    Matches BlockNameIO::encodeName() (interface version >= 3).
    """
    name_bytes = plaintext.encode('utf-8')
    length = len(name_bytes)

    # Pad to block boundary (always add at least 1 byte of padding)
    padding = block_size - (length % block_size)
    if padding == 0:
        padding = block_size

    # Layout: [2-byte MAC space | plaintext | padding bytes (value = padding)]
    data = bytearray(2 + length + padding)
    data[2:2 + length] = name_bytes
    for i in range(padding):
        data[2 + length + i] = padding

    # Save current chained IV before MAC_16 updates it
    tmp_iv = chained_iv if chained_iv is not None else 0

    # Compute MAC_16 over (plaintext + padding) — updates chained_iv
    mac16, new_chained_iv = mac_16(master_key, bytes(data[2:]), chained_iv)

    # Store MAC as 2 bytes big-endian
    data[0] = (mac16 >> 8) & 0xFF
    data[1] = mac16 & 0xFF

    # Block-encode with seed = mac16 XOR tmp_iv
    seed = (mac16 ^ tmp_iv) & 0xFFFFFFFFFFFFFFFF
    encrypted = block_encode(bytes(data[2:]), seed, master_key, master_iv, iv_length)
    data[2:] = encrypted

    # Encode as EncFS custom Base-64
    encoded = _b64_enc(bytes(data))
    return encoded, new_chained_iv


def decode_filename(encoded: str, master_key: bytes, master_iv: bytes,
                    iv_length: int, block_size: int,
                    chained_iv: int = None) -> tuple:
    """Decrypt a single filename component.

    Returns (plaintext: str, new_chained_iv: int).

    Matches BlockNameIO::decodeName() (interface version >= 3).
    """
    # Decode from EncFS custom Base-64 to bytes
    expected_bytes = _b64_to_b256_bytes(len(encoded))
    raw = _b64_dec(encoded, expected_bytes)

    decoded_stream_len = len(raw) - 2  # subtract 2 MAC bytes
    if decoded_stream_len < block_size:
        raise ValueError(f"Filename too short to decode: {encoded!r}")

    # Extract MAC from first 2 bytes
    mac = (raw[0] << 8) | raw[1]

    # Save current chained IV before blockDecode
    tmp_iv = chained_iv if chained_iv is not None else 0

    # Block-decode with seed = mac XOR tmp_iv
    seed = (mac ^ tmp_iv) & 0xFFFFFFFFFFFFFFFF
    decrypted = block_decode(raw[2:], seed, master_key, master_iv, iv_length)

    # Find true string length from padding
    padding = decrypted[-1]
    if padding == 0 or padding > block_size:
        raise ValueError(f"Invalid padding value {padding} in filename {encoded!r}")
    final_size = decoded_stream_len - padding
    if final_size < 0:
        raise ValueError(f"Invalid filename padding in {encoded!r}")

    # Verify MAC_16 and update chained IV
    mac2, new_chained_iv = mac_16(master_key, bytes(decrypted), chained_iv)
    if mac2 != mac:
        raise ValueError(
            f"MAC mismatch in filename {encoded!r}: expected {mac}, got {mac2}")

    plaintext = decrypted[:final_size].decode('utf-8')
    return plaintext, new_chained_iv


# ---------------------------------------------------------------------------
# File content encryption / decryption (CipherFileIO)
# ---------------------------------------------------------------------------

def _decrypt_file_header(raw_header: bytes, external_iv: int,
                         master_key: bytes, master_iv: bytes,
                         iv_length: int) -> int:
    """Decode the 8-byte per-file IV header.

    The header is stream-encoded with the external IV as the seed.
    Returns the 64-bit file IV.
    """
    dec = stream_decode(raw_header, external_iv, master_key, master_iv, iv_length)
    file_iv = struct.unpack('>Q', dec)[0]
    return file_iv


def _encrypt_file_header(file_iv: int, external_iv: int,
                         master_key: bytes, master_iv: bytes,
                         iv_length: int) -> bytes:
    """Encode the 8-byte per-file IV header."""
    buf = struct.pack('>Q', file_iv)
    return stream_encode(buf, external_iv, master_key, master_iv, iv_length)


def decrypt_file(src_path: str, dst_path: str, config: dict,
                 master_key: bytes, master_iv: bytes,
                 external_iv: int = 0) -> None:
    """Decrypt a single file from *src_path* (ciphertext) to *dst_path* (plaintext)."""
    key_size = config['key_size']
    iv_length = config['iv_length']
    block_size = config['block_size']
    unique_iv = config['unique_iv']
    block_mac_bytes = config['block_mac_bytes']
    block_mac_rand_bytes = config['block_mac_rand_bytes']

    with open(src_path, 'rb') as f:
        data = f.read()

    if len(data) == 0:
        # Empty file
        os.makedirs(os.path.dirname(dst_path), exist_ok=True)
        with open(dst_path, 'wb') as f:
            pass
        return

    if unique_iv:
        if len(data) < HEADER_SIZE:
            raise ValueError(f"File too short for IV header: {src_path}")
        raw_header = data[:HEADER_SIZE]
        file_iv = _decrypt_file_header(
            raw_header, external_iv, master_key, master_iv, iv_length)
        payload = data[HEADER_SIZE:]
    else:
        file_iv = 0
        payload = data

    # The on-disk block size includes any MAC bytes
    on_disk_block = block_size + block_mac_bytes + block_mac_rand_bytes
    logical_block = block_size  # what CipherFileIO sees

    plaintext_blocks = []
    block_num = 0
    offset = 0

    while offset < len(payload):
        # Read one on-disk block
        on_disk_chunk = payload[offset: offset + on_disk_block]
        offset += on_disk_block

        if block_mac_bytes > 0:
            # MAC layer: [MAC(block_mac_bytes) | rand(block_mac_rand_bytes) | encrypted_data]
            mac_bytes_stored = on_disk_chunk[:block_mac_bytes]
            rand_bytes = on_disk_chunk[block_mac_bytes: block_mac_bytes + block_mac_rand_bytes]
            enc_data = on_disk_chunk[block_mac_bytes + block_mac_rand_bytes:]

            # Verify MAC (little-endian stored MAC value)
            mac_val_stored = int.from_bytes(mac_bytes_stored, 'little')
            mac_input = rand_bytes + enc_data
            mac_val_computed, _ = mac_64(master_key, mac_input)
            # Truncate to block_mac_bytes * 8 bits
            mac_val_computed &= (1 << (block_mac_bytes * 8)) - 1
            if mac_val_computed != mac_val_stored:
                raise ValueError(
                    f"Block MAC mismatch in {src_path} block {block_num}")
        else:
            enc_data = on_disk_chunk

        if len(enc_data) == 0:
            break

        iv_seed = (block_num ^ file_iv) & 0xFFFFFFFFFFFFFFFF

        if len(enc_data) == logical_block:
            # Full block: CBC
            plain = block_decode(enc_data, iv_seed, master_key, master_iv, iv_length)
        else:
            # Partial (last) block: CFB stream
            plain = stream_decode(enc_data, iv_seed, master_key, master_iv, iv_length)

        plaintext_blocks.append(plain)
        block_num += 1

    os.makedirs(os.path.dirname(dst_path) if os.path.dirname(dst_path) else '.', exist_ok=True)
    with open(dst_path, 'wb') as f:
        f.write(b''.join(plaintext_blocks))


def encrypt_file(src_path: str, dst_path: str, config: dict,
                 master_key: bytes, master_iv: bytes,
                 external_iv: int = 0) -> None:
    """Encrypt a single file from *src_path* (plaintext) to *dst_path* (ciphertext)."""
    iv_length = config['iv_length']
    block_size = config['block_size']
    unique_iv = config['unique_iv']
    block_mac_bytes = config['block_mac_bytes']
    block_mac_rand_bytes = config['block_mac_rand_bytes']

    with open(src_path, 'rb') as f:
        plaintext = f.read()

    os.makedirs(os.path.dirname(dst_path) if os.path.dirname(dst_path) else '.', exist_ok=True)

    if len(plaintext) == 0:
        with open(dst_path, 'wb') as f:
            pass
        return

    # Generate a random per-file IV
    if unique_iv:
        file_iv = int.from_bytes(os.urandom(8), 'big')
        while file_iv == 0:
            file_iv = int.from_bytes(os.urandom(8), 'big')
    else:
        file_iv = 0

    out_parts = []

    # Write header
    if unique_iv:
        header = _encrypt_file_header(
            file_iv, external_iv, master_key, master_iv, iv_length)
        out_parts.append(header)

    # Encrypt blocks
    offset = 0
    block_num = 0
    while offset < len(plaintext):
        chunk = plaintext[offset: offset + block_size]
        offset += block_size
        iv_seed = (block_num ^ file_iv) & 0xFFFFFFFFFFFFFFFF

        if len(chunk) == block_size:
            enc = block_encode(chunk, iv_seed, master_key, master_iv, iv_length)
        else:
            enc = stream_encode(chunk, iv_seed, master_key, master_iv, iv_length)

        if block_mac_bytes > 0:
            rand_bytes = os.urandom(block_mac_rand_bytes) if block_mac_rand_bytes > 0 else b''
            mac_input = rand_bytes + enc
            mac_val, _ = mac_64(master_key, mac_input)
            mac_val &= (1 << (block_mac_bytes * 8)) - 1
            mac_stored = mac_val.to_bytes(block_mac_bytes, 'little')
            out_parts.append(mac_stored + rand_bytes + enc)
        else:
            out_parts.append(enc)

        block_num += 1

    with open(dst_path, 'wb') as f:
        f.write(b''.join(out_parts))


# ---------------------------------------------------------------------------
# Directory walking and name decoding/encoding
# ---------------------------------------------------------------------------

def _get_dir_iv(enc_dir_components: list, master_key: bytes, master_iv: bytes,
                iv_length: int, cipher_block_size: int,
                use_chained_iv: bool) -> int:
    """Compute the chained IV for a directory given its encrypted path components.

    The IV chain starts at 0 and is updated by decoding each path component.
    """
    if not use_chained_iv:
        return 0
    iv = 0
    for enc_name in enc_dir_components:
        try:
            _, iv = decode_filename(
                enc_name, master_key, master_iv, iv_length, cipher_block_size, iv)
        except Exception:
            # If we can't decode, reset (best-effort)
            iv = 0
    return iv


def process_directory(
    src_dir: str,
    dst_dir: str,
    config: dict,
    master_key: bytes,
    master_iv: bytes,
    operation: str,
) -> None:
    """Process all files in *src_dir*, applying encrypt or decrypt, writing to *dst_dir*.

    Maintains the same folder structure.  Handles IV chaining for filenames and
    external IV chaining for file content.
    """
    use_chained_iv = config['chained_name_iv']
    use_external_iv = config['external_iv_chaining']
    iv_length = config['iv_length']
    block_size = config['block_size']
    cipher_block_size = config['cipher_block_size']

    # --- DECRYPT MODE: walk encrypted source, produce plaintext destination ---
    if operation == 'decrypt':
        _process_dir_decrypt(
            src_dir, src_dir, dst_dir, config,
            master_key, master_iv, iv_length, block_size, cipher_block_size,
            use_chained_iv, use_external_iv,
            dir_iv=0,
        )

    # --- ENCRYPT MODE: walk plaintext source, produce encrypted destination ---
    elif operation == 'encrypt':
        _process_dir_encrypt(
            src_dir, src_dir, dst_dir, config,
            master_key, master_iv, iv_length, block_size, cipher_block_size,
            use_chained_iv, use_external_iv,
            dir_iv=0,
        )
    else:
        raise ValueError(f"Unknown operation: {operation!r}")


def _process_dir_decrypt(
    root_src: str,
    current_enc_dir: str,
    current_plain_dir: str,
    config: dict,
    master_key: bytes,
    master_iv: bytes,
    iv_length: int,
    block_size: int,
    cipher_block_size: int,
    use_chained_iv: bool,
    use_external_iv: bool,
    dir_iv: int,
) -> None:
    """Recursively decrypt an encrypted directory tree."""
    os.makedirs(current_plain_dir, exist_ok=True)

    try:
        entries = sorted(os.listdir(current_enc_dir))
    except PermissionError as e:
        print(f"Warning: cannot list {current_enc_dir}: {e}", file=sys.stderr)
        return

    for enc_name in entries:
        # Skip the EncFS config file itself
        if enc_name == '.encfs6.xml':
            continue
        # Pass-through special names "." and ".."
        if enc_name in ('.', '..'):
            continue

        enc_path = os.path.join(current_enc_dir, enc_name)

        # Decode filename (uses cipher_block_size for padding)
        try:
            plain_name, file_iv = decode_filename(
                enc_name, master_key, master_iv, iv_length, cipher_block_size,
                dir_iv if use_chained_iv else None,
            )
        except Exception as e:
            print(f"Warning: cannot decode filename {enc_name!r}: {e}",
                  file=sys.stderr)
            continue

        plain_path = os.path.join(current_plain_dir, plain_name)

        if os.path.isdir(enc_path):
            # Recurse: the dir_iv for children is updated by the dir-name decode
            child_dir_iv = file_iv if use_chained_iv else 0
            _process_dir_decrypt(
                root_src, enc_path, plain_path, config,
                master_key, master_iv, iv_length, block_size, cipher_block_size,
                use_chained_iv, use_external_iv,
                child_dir_iv,
            )
        else:
            # File: external_iv is the iv after decoding the filename
            ext_iv = file_iv if use_external_iv else 0
            try:
                decrypt_file(enc_path, plain_path, config,
                             master_key, master_iv, ext_iv)
            except Exception as e:
                print(f"Warning: failed to decrypt {enc_path!r}: {e}",
                      file=sys.stderr)


def _process_dir_encrypt(
    root_src: str,
    current_plain_dir: str,
    current_enc_dir: str,
    config: dict,
    master_key: bytes,
    master_iv: bytes,
    iv_length: int,
    block_size: int,
    cipher_block_size: int,
    use_chained_iv: bool,
    use_external_iv: bool,
    dir_iv: int,
) -> None:
    """Recursively encrypt a plaintext directory tree."""
    os.makedirs(current_enc_dir, exist_ok=True)

    try:
        entries = sorted(os.listdir(current_plain_dir))
    except PermissionError as e:
        print(f"Warning: cannot list {current_plain_dir}: {e}", file=sys.stderr)
        return

    for plain_name in entries:
        if plain_name in ('.', '..'):
            continue

        plain_path = os.path.join(current_plain_dir, plain_name)

        # Encode filename (uses cipher_block_size for padding)
        try:
            enc_name, file_iv = encode_filename(
                plain_name, master_key, master_iv, iv_length, cipher_block_size,
                dir_iv if use_chained_iv else None,
            )
        except Exception as e:
            print(f"Warning: cannot encode filename {plain_name!r}: {e}",
                  file=sys.stderr)
            continue

        enc_path = os.path.join(current_enc_dir, enc_name)

        if os.path.isdir(plain_path):
            child_dir_iv = file_iv if use_chained_iv else 0
            _process_dir_encrypt(
                root_src, plain_path, enc_path, config,
                master_key, master_iv, iv_length, block_size, cipher_block_size,
                use_chained_iv, use_external_iv,
                child_dir_iv,
            )
        else:
            ext_iv = file_iv if use_external_iv else 0
            try:
                encrypt_file(plain_path, enc_path, config,
                             master_key, master_iv, ext_iv)
            except Exception as e:
                print(f"Warning: failed to encrypt {plain_path!r}: {e}",
                      file=sys.stderr)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description='EncFSMP Python implementation — encrypt or decrypt an EncFS volume.')
    parser.add_argument('config', help='Path to the .encfs6.xml configuration file')
    parser.add_argument('src', help='Source directory (encrypted for decrypt, plaintext for encrypt)')
    parser.add_argument('dst', help='Destination directory')
    parser.add_argument('operation', choices=['decrypt', 'encrypt'],
                        help='Operation to perform')
    args = parser.parse_args()

    # Validate paths
    if not os.path.isfile(args.config):
        print(f"Error: config file not found: {args.config}", file=sys.stderr)
        return 1
    if not os.path.isdir(args.src):
        print(f"Error: source directory not found: {args.src}", file=sys.stderr)
        return 1

    # Parse configuration
    try:
        config = parse_config(args.config)
    except Exception as e:
        print(f"Error parsing config: {e}", file=sys.stderr)
        return 1

    cipher = config['cipher_name']
    if cipher not in ('ssl/aes',):
        print(f"Warning: cipher {cipher!r} support is experimental; only AES is fully tested.",
              file=sys.stderr)

    print(f"Cipher: {cipher}, key size: {config['key_size_bits']} bits, "
          f"block size: {config['block_size']} bytes")
    print(f"uniqueIV: {config['unique_iv']}, chainedNameIV: {config['chained_name_iv']}, "
          f"externalIVChaining: {config['external_iv_chaining']}")

    # Prompt for password
    password = getpass.getpass('Password: ')

    # Derive password key
    try:
        password_key, password_iv = derive_password_key(password, config)
    except Exception as e:
        print(f"Error during key derivation: {e}", file=sys.stderr)
        return 1

    # Decrypt master key
    try:
        master_key, master_iv = decrypt_master_key(config, password_key, password_iv)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    print(f"Master key decrypted successfully ({len(master_key)} bytes).")

    # Process directory
    try:
        process_directory(
            args.src, args.dst, config, master_key, master_iv, args.operation)
    except Exception as e:
        print(f"Error during processing: {e}", file=sys.stderr)
        return 1

    print("Done.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
