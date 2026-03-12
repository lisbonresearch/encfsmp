# EncFSMP Cryptographic Operations Reference

This document thoroughly describes all cryptographic operations and file formats used by the EncFSMP implementation. It is intended to provide enough detail for someone to write a compatible implementation (e.g. in Python).

**Source tree:** `src/encfs/`

---

## Table of Contents

1. [Configuration File (`.encfs6.xml`)](#1-configuration-file-encfs6xml)
2. [Password-Based Key Derivation](#2-password-based-key-derivation)
3. [Master Key Storage and Retrieval](#3-master-key-storage-and-retrieval)
4. [Supported Cipher Algorithms](#4-supported-cipher-algorithms)
5. [IV Generation (`setIVec`)](#5-iv-generation-setivec)
6. [File Content Encryption](#6-file-content-encryption)
7. [MAC\_64 / MAC\_16](#7-mac_64--mac_16)
8. [Filename Encryption](#8-filename-encryption)
9. [Stream Cipher (double-pass)](#9-stream-cipher-double-pass)
10. [IV Chaining for Filenames](#10-iv-chaining-for-filenames)
11. [Base64 / Base32 Encoding](#11-base64--base32-encoding)
12. [Encoded Key Size](#12-encoded-key-size)
13. [Default and Paranoia Configurations](#13-default-and-paranoia-configurations)
14. [Backward Compatibility](#14-backward-compatibility)
15. [Python Implementation Guide](#15-python-implementation-guide)

---

## 1. Configuration File (`.encfs6.xml`)

**Source:** `src/encfs/FileUtils.cpp`, `src/encfs/ConfigReader.cpp`

The filesystem configuration is stored in `.encfs6.xml` in the root directory of the encrypted volume (V6/XML format). The XML is serialized using Boost.Serialization and lives under the `boost_serialization/cfg` or `boost_serialization/config` element.

### XML Fields

| Field | Type | Description |
|---|---|---|
| `version` | integer | Config version number (e.g. `20100713` or `20`) |
| `creator` | string | String identifying the creating application |
| `cipherAlg` | string | Cipher algorithm interface name (e.g. `ssl/aes`) |
| `nameAlg` | string | Name encoding interface name (e.g. `nameio/block`) |
| `keySize` | integer | Key size in **bits** |
| `blockSize` | integer | File data block size in bytes (default `1024`) |
| `plainData` | bool | Whether filenames are stored in plaintext |
| `uniqueIV` | bool | Whether each file has a unique per-file IV header |
| `chainedNameIV` | bool | Whether IV chaining is used for filenames |
| `externalIVChaining` | bool | Whether external IV chaining is enabled |
| `blockMACBytes` | integer | Number of MAC bytes per block (`0`–`8`); `0` = no MAC |
| `blockMACRandBytes` | integer | Number of random bytes per block header |
| `allowHoles` | bool | Whether sparse files (all-zero blocks) are supported |
| `encodedKeySize` | integer | Size in bytes of the base64-decoded encoded key blob |
| `encodedKeyData` | string | Base64-encoded encrypted master key (+ IV + checksum) |
| `saltLen` | integer | Length of KDF salt in bytes (present if `subVersion >= 20080816`) |
| `saltData` | string | Base64-encoded KDF salt |
| `kdfIterations` | integer | PBKDF2 iteration count |
| `desiredKDFDuration` | integer | Target KDF duration in milliseconds (used for auto-tuning) |

### Example (AES-192, default settings)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE boost_serialization>
<boost_serialization signature="serialization::archive" version="9">
  <cfg class_id="0" tracking_level="0" version="20">
    <version>20100713</version>
    <creator>EncFSMP 1.0</creator>
    <cipherAlg>
      <name>ssl/aes</name>
      <major>3</major>
      <minor>0</minor>
    </cipherAlg>
    <nameAlg>
      <name>nameio/block</name>
      <major>3</major>
      <minor>0</minor>
    </nameAlg>
    <keySize>192</keySize>
    <blockSize>1024</blockSize>
    <plainData>0</plainData>
    <uniqueIV>1</uniqueIV>
    <chainedNameIV>1</chainedNameIV>
    <externalIVChaining>0</externalIVChaining>
    <blockMACBytes>0</blockMACBytes>
    <blockMACRandBytes>0</blockMACRandBytes>
    <allowHoles>1</allowHoles>
    <encodedKeySize>44</encodedKeySize>
    <encodedKeyData>...</encodedKeyData>
    <saltLen>20</saltLen>
    <saltData>...</saltData>
    <kdfIterations>180000</kdfIterations>
    <desiredKDFDuration>500</desiredKDFDuration>
  </cfg>
</boost_serialization>
```

---

## 2. Password-Based Key Derivation

**Source:** `src/encfs/SSL_Cipher.cpp` — `newKey()`, `TimedPBKDF2()`

### Modern (subVersion ≥ 20080816)

- **Algorithm:** PBKDF2-HMAC-SHA1 (via OpenSSL `PKCS5_PBKDF2_HMAC_SHA1`)
- **Password:** User-supplied passphrase (UTF-8 bytes)
- **Salt:** Random bytes from the config file (`saltData`, `saltLen` bytes)
- **Output length:** `keySize_bytes + ivLength_bytes` (key and IV concatenated)
- **Iterations:** `kdfIterations` from config (auto-tuned to match `desiredKDFDuration` ms on first use)
- **Output layout:** First `keySize_bytes` bytes = master password key, next `ivLength_bytes` bytes = password IV

```
PBKDF2-HMAC-SHA1(password, salt, kdfIterations, keySize_bytes + ivLength_bytes)
  → [ password_key (keySize_bytes) | password_iv (ivLength_bytes) ]
```

The IV length equals the cipher's block size: 8 bytes for Blowfish, 16 bytes for AES and CAMELLIA.

### Iteration count auto-tuning

If `kdfIterations` is not yet stored (first mount), EncFSMP runs `TimedPBKDF2` which measures how many iterations complete within `desiredKDFDuration` milliseconds and saves that count to the config.

### Legacy (subVersion < 20080816) — `BytesToKey`

Older configs used an EVP_BytesToKey-style key derivation:
- No salt
- 16 fixed iterations of SHA1 over `password || previous_hash`
- Output same length as above

---

## 3. Master Key Storage and Retrieval

**Source:** `src/encfs/SSL_Cipher.cpp` — `writeKey()` / `readKey()`

The master key is a randomly generated key (and IV) that is used for all actual file and filename encryption. It is stored encrypted in the config file so that the password can be changed without re-encrypting all data.

### Encoded key layout

```
[ master_key (keySize_bytes) | master_iv (ivLength_bytes) | checksum (4 bytes) ]
                                            total = encodedKeySize bytes
```

- `master_key`: randomly generated cipher key (`keySize / 8` bytes)
- `master_iv`: randomly generated IV (`ivLength` bytes = cipher block size)
- `checksum`: first 4 bytes of `HMAC-SHA1(key=password_key, data=master_key || master_iv)`

### Encryption of the key blob (`writeKey`)

1. Build the plaintext buffer: `master_key || master_iv || checksum`
2. Stream-encrypt the entire buffer using the **password-derived key** and **password-derived IV** (stream cipher = CFB mode of the configured cipher)
3. Base64-encode the result → stored as `encodedKeyData` in the XML

### Decryption of the key blob (`readKey`)

1. Base64-decode `encodedKeyData`
2. Stream-decrypt using the password-derived key and IV
3. Extract `master_key` (first `keySize_bytes` bytes) and `master_iv` (next `ivLength_bytes` bytes)
4. Recompute `HMAC-SHA1(key=password_key, data=master_key || master_iv)` and verify that the first 4 bytes match `checksum`; if not, the password is wrong

`KEY_CHECKSUM_BYTES = 4`

---

## 4. Supported Cipher Algorithms

**Source:** `src/encfs/SSL_Cipher.cpp`

| Name | Interface string | Block cipher | Stream cipher | Key sizes (bits) | Default key size | IV/block size |
|---|---|---|---|---|---|---|
| AES | `ssl/aes` | AES-CBC | AES-CFB | 128, 192, 256 | 192 | 16 bytes |
| Blowfish | `ssl/blowfish` | Blowfish-CBC | Blowfish-CFB | 128–256 (32-bit steps) | 160 | 8 bytes |
| CAMELLIA | `ssl/camellia` | CAMELLIA-CBC | CAMELLIA-CFB | 128, 192, 256 | 192 | 16 bytes |

All ciphers operate with **OpenSSL padding disabled** (block operations use exact multiples of the block size).

---

## 5. IV Generation (`setIVec`)

**Source:** `src/encfs/SSL_Cipher.cpp` — `setIVec()`

Before each block or stream cipher operation, a full IV vector is derived from a 64-bit seed:

1. **Seed:** `blockNumber XOR fileIV` (both are 64-bit values)
2. Serialize the seed as **8 bytes, big-endian**
3. Compute `HMAC-SHA1(key=master_key, data=seed_bytes)` using the master key's HMAC context
4. Copy the first `ivLength` bytes of the HMAC output into the IV used for the cipher operation

```python
import hmac, hashlib, struct

def set_ivec(master_key, seed_64bit):
    seed_bytes = struct.pack('>Q', seed_64bit)
    mac = hmac.new(master_key, seed_bytes, hashlib.sha1).digest()
    return mac[:iv_length]   # iv_length = cipher block size
```

This prevents watermarking attacks by making every block's IV unpredictable.

### Legacy `setIVec_old` (v1 backward compatibility)

For old-format volumes, the seed is a 32-bit value and the IV is derived by XOR-folding the seed into the stored key IV bytes rather than using HMAC.

---

## 6. File Content Encryption

**Source:** `src/encfs/CipherFileIO.cpp`, `src/encfs/BlockFileIO.cpp`

### 6a. Per-File IV Header (`uniqueIV = true`)

When `uniqueIV` is enabled, each encrypted file begins with an **8-byte header** containing the per-file IV:

```
Byte offset 0: [ fileIV (8 bytes) ]   ← stream-encrypted
Byte offset 8: [ encrypted data blocks ... ]
```

- `fileIV` is a random 64-bit value generated when the file is first created.
- The 8-byte header is stream-encoded using the external IV (the encrypted filename's IV, cast to a 64-bit seed) as the IV seed for `setIVec`.
- If `uniqueIV = false`, there is no header; the file starts at byte offset 0 and `fileIV = 0`.

### 6b. Block Encryption

The logical file data is divided into fixed-size blocks of `blockSize` bytes. Each block is encrypted independently:

- **Block number:** 0-based index of the block within the file (after the header)
- **IV seed:** `blockNumber XOR fileIV`
- **Full blocks:** Encrypted with the block cipher in **CBC mode** (no OpenSSL padding)
- **Partial (last) block:** Encrypted with the stream cipher in **CFB mode**

```
for block_number, block_data in enumerate(blocks):
    iv = set_ivec(master_key, block_number ^ fileIV)
    if len(block_data) == blockSize:
        ciphertext = AES_CBC_encrypt(master_key, iv, block_data)
    else:
        ciphertext = AES_CFB_encrypt(master_key, iv, block_data)
```

### 6c. MAC Layer (`blockMACBytes > 0`)

**Source:** `src/encfs/MACFileIO.cpp`

When MAC protection is enabled, each on-disk block is structured as:

```
[ MAC (blockMACBytes bytes) | random (blockMACRandBytes bytes) | encrypted data ]
```

- The **MAC** is `MAC_64` computed over `[random_bytes || encrypted_data]`, stored as `blockMACBytes` bytes in **little-endian** byte order.
- `blockMACRandBytes` random bytes are generated fresh for each write to make the MAC non-deterministic.
- The **logical block size** seen by the crypto layer is `blockSize - blockMACBytes - blockMACRandBytes`.

On read, the MAC is verified; a mismatch indicates data corruption or tampering.

---

## 7. MAC\_64 / MAC\_16

**Source:** `src/encfs/SSL_Cipher.cpp`

Both MAC functions use **HMAC-SHA1** keyed with the master key.

### MAC\_64

1. Compute `HMAC-SHA1(key=master_key, data=src)` → 20-byte digest
2. XOR-fold the 20 bytes into 8 bytes:
   ```
   result[i] ^= digest[i]       for i in 0..7
   result[i-8] ^= digest[i]     for i in 8..19
   ```
   (i.e., fold bytes 8–19 back onto bytes 0–7 / 0–3)
3. Optionally XOR with a supplied `augment` value (64-bit)
4. Return the 8-byte (64-bit) result as a `uint64_t`

```python
def mac_64(master_key, data, augment=0):
    digest = hmac.new(master_key, data, hashlib.sha1).digest()  # 20 bytes
    result = bytearray(8)
    for i, b in enumerate(digest):
        result[i % 8] ^= b
    value = struct.unpack('<Q', bytes(result))[0]
    return value ^ augment
```

### MAC\_16

1. Call `MAC_64` over `src`
2. XOR-fold the 64-bit result into 16 bits:
   ```
   result16 = (mac64 >> 48) ^ (mac64 >> 32) ^ (mac64 >> 16) ^ mac64
   result16 &= 0xFFFF
   ```
3. If an `iv` pointer is provided (IV chaining), update `*iv ^= result16`

```python
def mac_16(master_key, data, iv=0):
    m = mac_64(master_key, data)
    result = ((m >> 48) ^ (m >> 32) ^ (m >> 16) ^ m) & 0xFFFF
    iv ^= result
    return result, iv
```

---

## 8. Filename Encryption

### 8a. Block Mode (`nameio/block` or `nameio/block32`)

**Source:** `src/encfs/BlockNameIO.cpp`

Block mode is the default filename encoding. Encrypted names use Base64 (or Base32 for `nameio/block32`).

#### Encoding

1. Pad the plaintext filename bytes to a multiple of the cipher block size using PKCS-style padding: the last byte equals the number of padding bytes added.
2. Compute `MAC_16(master_key, padded_plaintext, chainedIV)` → 16-bit checksum, and optionally update `chainedIV`.
3. Build IV for block encryption: `iv_seed = mac ^ chainedIV` (before the MAC\_16 update)
4. Block-encrypt `[padded_plaintext]` with `set_ivec(master_key, iv_seed)` using the block cipher (CBC).
5. Prepend the 2-byte MAC (big-endian) to the ciphertext.
6. Base64-encode (or Base32-encode for `nameio/block32`) the full buffer `[checksum(2) | ciphertext]`.

#### Decoding

1. Base64 (or Base32) decode the encrypted filename.
2. Extract the 2-byte MAC prefix and the ciphertext.
3. Reconstruct `iv_seed = mac ^ chainedIV`.
4. Block-decrypt the ciphertext using `set_ivec(master_key, iv_seed)`.
5. Remove PKCS padding from the result.
6. Recompute `MAC_16(master_key, padded_plaintext, chainedIV)` and verify it matches the stored MAC.

### 8b. Stream Mode (`nameio/stream`)

**Source:** `src/encfs/StreamNameIO.cpp`

#### Encoding

1. Compute `MAC_16(master_key, plaintext, chainedIV)` → 16-bit checksum, optionally update `chainedIV`.
2. Build IV seed: `iv_seed = mac ^ chainedIV` (before update).
3. Stream-encode the plaintext bytes with `set_ivec(master_key, iv_seed)` (CFB mode, double-pass).
4. Prepend the 2-byte MAC (big-endian) to the stream ciphertext.
5. Base64-encode the full buffer `[checksum(2) | stream_ciphertext]`.

#### Decoding

1. Base64-decode the encrypted filename.
2. Extract the 2-byte MAC and the stream ciphertext.
3. Reconstruct `iv_seed = mac ^ chainedIV`.
4. Stream-decode the ciphertext with `set_ivec(master_key, iv_seed)`.
5. Recompute `MAC_16(master_key, plaintext, chainedIV)` and verify.

---

## 9. Stream Cipher (double-pass)

**Source:** `src/encfs/SSL_Cipher.cpp` — `streamEncode()` / `streamDecode()`

Single-pass CFB allows a 1-byte change in plaintext to affect only 1 byte of ciphertext (plus the block after it). To propagate changes across the entire buffer, EncFSMP uses a **double-pass** approach:

### Encoding (5 steps)

1. **Shuffle** — byte diffusion: `buf[i] ^= buf[(i * 3 + 1) % len]` for i in `[0, len-1]`
2. **Encrypt pass 1** — CFB encrypt the full buffer with `iv1 = set_ivec(master_key, seed)`
3. **Reverse** — reverse the byte order of the buffer
4. **Shuffle** — apply the same diffusion step again
5. **Encrypt pass 2** — CFB encrypt again with `iv2 = set_ivec(master_key, seed ^ 1)`

### Decoding (reverse order)

1. **Decrypt pass 2** — CFB decrypt with `iv2`
2. **Unshuffle** — reverse the diffusion step
3. **Reverse** — reverse byte order
4. **Decrypt pass 1** — CFB decrypt with `iv1`
5. **Unshuffle** — reverse the diffusion step

The shuffle/unshuffle operation ensures that single-byte flips in the ciphertext affect the entire plaintext buffer after decryption.

---

## 10. IV Chaining for Filenames

**Source:** `src/encfs/DirNode.cpp`, `src/encfs/NameIO.cpp`

When `chainedNameIV = true`, the IV used to encrypt each filename component depends on the **encrypted name of its parent directory**.

- Starting IV for the root directory: `0`
- For each path component: the IV is passed to the filename encoding function, which calls `MAC_16` and updates the IV as a side-effect
- The updated IV is passed to the next component's encoding call

This means:
- The full encrypted path uniquely determines the IV for each filename component
- Renaming any directory in the path requires re-encrypting all child entries
- The IV is a `uint64_t` accumulated across the path depth

```python
def encode_path(components, master_key):
    iv = 0
    encoded = []
    for name in components:
        enc_name, iv = block_encode(name, master_key, iv)
        encoded.append(enc_name)
    return '/'.join(encoded)
```

---

## 11. Base64 / Base32 Encoding

**Source:** `src/encfs/base64.cpp`

### Custom Base64

EncFSMP uses a **non-standard Base64 alphabet** (not RFC 4648):

```
,0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz
```

- 64 characters: `,` followed by `0–9`, `A–Z`, `a–z`
- No `+`, `/`, or `=` characters
- No padding
- Safe for use in filesystem filenames on case-sensitive filesystems

Encoding is standard base64 bit-grouping (6 bits per character) using this alphabet.

### Base32 (`nameio/block32`)

EncFSMP also supports a 5-bit base32 encoding for case-insensitive filesystems (e.g. macOS HFS+). Base32 uses an alphabet of 32 characters and produces longer filenames but is safe on filesystems that fold uppercase and lowercase.

---

## 12. Encoded Key Size

`encodedKeySize = keySize_bytes + ivLength_bytes + KEY_CHECKSUM_BYTES`

where `KEY_CHECKSUM_BYTES = 4`.

| Cipher | Key size | IV size | encodedKeySize |
|---|---|---|---|
| AES-128 | 16 | 16 | 36 |
| AES-192 | 24 | 16 | 44 |
| AES-256 | 32 | 16 | 52 |
| Blowfish-128 | 16 | 8 | 28 |
| Blowfish-160 | 20 | 8 | 32 |
| Blowfish-256 | 32 | 8 | 44 |
| CAMELLIA-128 | 16 | 16 | 36 |
| CAMELLIA-192 | 24 | 16 | 44 |
| CAMELLIA-256 | 32 | 16 | 52 |

---

## 13. Default and Paranoia Configurations

### Standard (default) configuration

| Setting | Value |
|---|---|
| Cipher | AES (`ssl/aes`) |
| Key size | 192 bits |
| Block size | 1024 bytes |
| Name encoding | Block (`nameio/block`) |
| `uniqueIV` | `true` |
| `chainedNameIV` | `true` |
| `externalIVChaining` | `false` |
| `blockMACBytes` | `0` |
| `blockMACRandBytes` | `0` |
| `allowHoles` | `true` |
| KDF duration target | 500 ms |

### Paranoia configuration

| Setting | Value |
|---|---|
| Cipher | AES (`ssl/aes`) |
| Key size | 256 bits |
| Block size | 1024 bytes |
| Name encoding | Block (`nameio/block`) |
| `uniqueIV` | `true` |
| `chainedNameIV` | `true` |
| `externalIVChaining` | `true` |
| `blockMACBytes` | `8` |
| `blockMACRandBytes` | `8` |
| `allowHoles` | `false` |
| KDF duration target | 3000 ms |

In paranoia mode:
- Each on-disk block has a 16-byte overhead (8 MAC + 8 random), so the logical block is `1024 - 16 = 1008` bytes.
- External IV chaining links the filename IV into the file data IV, so moving/renaming files changes all their data IVs.

---

## 14. Backward Compatibility

### V5 config format

Older EncFS versions used a binary config format (V5). EncFSMP can read this format but always writes V6 XML. The fields are the same but the serialization is different.

### `subVersion < 20080816` — legacy KDF

When the config version predates `20080816`, the `saltData` field is absent and `BytesToKey` (iterated SHA1, no salt) is used for key derivation instead of PBKDF2.

### Legacy `setIVec_old` (v1)

Very old volumes (version 1 interface) use a simpler IV derivation that XOR-folds a 32-bit seed into the stored IV bytes, rather than the HMAC-based approach.

---

## 15. Python Implementation Guide

This section outlines how to implement EncFSMP-compatible encryption and decryption in Python using standard libraries.

### Recommended libraries

```
pip install cryptography lxml
```

- [`cryptography`](https://cryptography.io/) — AES-CBC, AES-CFB, PBKDF2, HMAC
- [`hashlib`](https://docs.python.org/3/library/hashlib.html) — SHA1, HMAC (standard library)
- [`hmac`](https://docs.python.org/3/library/hmac.html) — HMAC (standard library)
- [`lxml`](https://lxml.de/) or `xml.etree.ElementTree` — parsing `.encfs6.xml`
- [`base64`](https://docs.python.org/3/library/base64.html) — standard library (custom alphabet needed)

### Step 1: Parse the config file

```python
import xml.etree.ElementTree as ET
import base64

def parse_config(path):
    tree = ET.parse(path)
    root = tree.getroot()
    cfg = root.find('cfg') or root.find('config')
    config = {}
    for field in ['version', 'keySize', 'blockSize', 'blockMACBytes',
                  'blockMACRandBytes', 'kdfIterations', 'encodedKeySize',
                  'saltLen']:
        el = cfg.find(field)
        if el is not None:
            config[field] = int(el.text)
    for field in ['uniqueIV', 'chainedNameIV', 'externalIVChaining',
                  'plainData', 'allowHoles']:
        el = cfg.find(field)
        if el is not None:
            config[field] = el.text.strip() == '1'
    for field in ['cipherAlg', 'nameAlg', 'creator']:
        el = cfg.find(field)
        if el is not None:
            name_el = el.find('name') if el.find('name') is not None else el
            config[field] = name_el.text.strip()
    config['encodedKeyData'] = base64.b64decode(cfg.find('encodedKeyData').text.strip())
    config['saltData'] = base64.b64decode(cfg.find('saltData').text.strip())
    return config
```

### Step 2: Derive the password key

```python
import hashlib

def derive_key(password, config):
    key_bytes = config['keySize'] // 8
    iv_bytes = 16  # AES block size; 8 for Blowfish
    out_len = key_bytes + iv_bytes
    dk = hashlib.pbkdf2_hmac(
        'sha1',
        password.encode('utf-8'),
        config['saltData'],
        config['kdfIterations'],
        dklen=out_len
    )
    return dk[:key_bytes], dk[key_bytes:]  # (password_key, password_iv)
```

### Step 3: Decrypt the master key

```python
import hmac
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

KEY_CHECKSUM_BYTES = 4

def set_ivec(master_key, seed, iv_len=16):
    seed_bytes = struct.pack('>Q', seed & 0xFFFFFFFFFFFFFFFF)
    mac = hmac.new(master_key, seed_bytes, hashlib.sha1).digest()
    return mac[:iv_len]

def stream_decrypt(key, iv_seed, data, iv_len=16):
    iv = set_ivec(key, iv_seed, iv_len)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    dec = cipher.decryptor()
    return dec.update(data) + dec.finalize()

def read_master_key(config, password_key, password_iv, iv_len=16):
    key_bytes = config['keySize'] // 8
    # Use password_iv bytes as a seed integer
    iv_seed = int.from_bytes(password_iv[:8], 'big')
    blob = stream_decrypt(password_key, iv_seed, config['encodedKeyData'], iv_len)
    master_key = blob[:key_bytes]
    master_iv  = blob[key_bytes:key_bytes + iv_len]
    checksum   = blob[key_bytes + iv_len:key_bytes + iv_len + KEY_CHECKSUM_BYTES]
    expected = hmac.new(password_key, master_key + master_iv, hashlib.sha1).digest()
    if expected[:KEY_CHECKSUM_BYTES] != checksum:
        raise ValueError("Wrong password or corrupted key data")
    return master_key, master_iv
```

> **Note:** The actual IV seed used for key blob decryption is the password-derived IV itself (used as a 64-bit integer, big-endian). See `SSL_Cipher.cpp` `readKey()` for the exact derivation.

### Step 4: Decrypt a file block

```python
def decrypt_block(master_key, block_number, file_iv, ciphertext, iv_len=16):
    seed = block_number ^ file_iv
    iv = set_ivec(master_key, seed, iv_len)
    cipher = Cipher(algorithms.AES(master_key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    return dec.update(ciphertext) + dec.finalize()

def read_file(encrypted_path, master_key, config, external_iv=0, iv_len=16):
    with open(encrypted_path, 'rb') as f:
        if config['uniqueIV']:
            header = f.read(8)
            file_iv_enc = header
            file_iv = struct.unpack('>Q', stream_decrypt(master_key, external_iv, file_iv_enc, iv_len))[0]
        else:
            file_iv = 0
        data = f.read()
    block_size = config['blockSize']
    plaintext = b''
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        plaintext += decrypt_block(master_key, i // block_size, file_iv, block, iv_len)
    return plaintext
```

### Step 5: Decode an encrypted filename (block mode)

```python
ENCFS_B64 = ',0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

def encfs_b64decode(s):
    bits = 0
    count = 0
    result = []
    for c in s:
        bits = (bits << 6) | ENCFS_B64.index(c)
        count += 6
        if count >= 8:
            count -= 8
            result.append((bits >> count) & 0xFF)
    return bytes(result)

def mac_64(master_key, data):
    digest = hmac.new(master_key, data, hashlib.sha1).digest()
    result = bytearray(8)
    for i, b in enumerate(digest):
        result[i % 8] ^= b
    return struct.unpack('<Q', bytes(result))[0]

def mac_16(master_key, data, iv=0):
    m = mac_64(master_key, data)
    result = int(((m >> 48) ^ (m >> 32) ^ (m >> 16) ^ m) & 0xFFFF)
    return result, iv ^ result

def decode_filename_block(enc_name, master_key, chained_iv=0, iv_len=16, block_size=16):
    raw = encfs_b64decode(enc_name)
    mac = struct.unpack('>H', raw[:2])[0]
    ciphertext = raw[2:]
    iv_seed = mac ^ chained_iv
    iv = set_ivec(master_key, iv_seed, iv_len)
    cipher = Cipher(algorithms.AES(master_key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    pad_len = padded[-1]
    plaintext = padded[:-pad_len]
    expected_mac, _ = mac_16(master_key, padded, chained_iv)
    if expected_mac != mac:
        raise ValueError("Filename MAC verification failed")
    return plaintext.decode('utf-8')
```

### Notes for a Full Implementation

- The `stream_decrypt` / `stream_encode` functions use the **double-pass** shuffle+CFB approach described in [Section 9](#9-stream-cipher-double-pass) for filename stream mode and key blob decryption.
- The `set_ivec` seed for the **per-file IV header** uses the external IV (filename's chained IV cast to `uint64_t`), not `blockNumber ^ fileIV`.
- When `externalIVChaining = true`, the external IV is also XOR-folded into the per-file IV before block encryption, creating a link between filename and content IVs.
- The MAC for the block MAC layer uses `MAC_64` over `[random_bytes || encrypted_block_data]` and stores only the first `blockMACBytes` bytes in **little-endian** order.
- Refer to the source files in `src/encfs/` for full details on edge cases and version-specific behavior.

---

*Document generated from a review of the EncFSMP source code in `src/encfs/`. Reference implementations: `SSL_Cipher.cpp`, `CipherFileIO.cpp`, `BlockFileIO.cpp`, `MACFileIO.cpp`, `BlockNameIO.cpp`, `StreamNameIO.cpp`, `DirNode.cpp`, `FileUtils.cpp`, `base64.cpp`.*
