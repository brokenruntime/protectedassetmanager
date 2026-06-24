```
    ___  ___  ____  ____________________________    ___   __________________
   / _ \/ _ \/ __ \/_  __/ __/ ___/_  __/ __/ _ \  / _ | / __/ __/ __/_  __/
  / ___/ , _/ /_/ / / / / _// /__  / / / _// // / / __ |_\ \_\ \/ _/  / /
 /_/  /_/|_|\____/ /_/ /___/\___/ /_/ /___/____/ /_/ |_/___/___/___/ /_/
  _____MANAGER_________________________________________________________________
```

A secure Python library that encrypts folders into multiple protected fragments, which can only be decrypted and fully restored with the correct password and authentication token.
---

## Requirements

- Python 3.10+
- `cryptography`
- `argon2-cffi`

---

## Setup

**Windows**
```batch
setup.bat
```

**Linux / macOS**
```bash
chmod +x setup.sh && ./setup.sh
```

---

## Usage

**Encrypt**
```bash
python protectedassetmanager.py encrypt <folder> <password>
```

**Decrypt**
```bash
python protectedassetmanager.py decrypt <fragment_folder> <password> <token_file>
```

---

## Security

| Layer | Algorithm | Details |
|-------|-----------|---------|
| KDF | Argon2id | 256 MB memory, time=4, parallelism=4 |
| Cipher | AES-256-GCM | Authenticated encryption per chunk |
| MAC | HMAC-SHA512 | Fragment integrity verification |
| Integrity | SHA-256 | ZIP hash verification |

---

## Technical Structure

### Encrypt Pipeline

1. Read folder contents
2. Create ZIP archive in memory (ZIP64, store mode)
3. Derive key from password using Argon2id (salt from CSPRNG)
4. Split ZIP into 8 MB chunks → encrypt each chunk with AES-256-GCM
5. Assemble 10 `.protectedassetpart` files + 1 `.token` file

### Decrypt Pipeline

1. Verify HMAC-SHA512 headers of all fragment files
2. Reassemble fragment stream in order
3. Split into 8 MB chunks
4. Decrypt each chunk with AES-256-GCM (verify auth tag)
5. Reconstruct ZIP archive (ZIP64)
6. Verify ZIP SHA-256 hash against token metadata
7. Extract to output folder

### Token File

JSON metadata file. Required for decryption alongside the password.

### Fragment Format

Each `.protectedassetpart` file layout:

```
[  4 bytes magic number   ]  ← 0x50414D32 ("PAM2")
[  4 bytes version        ]  ← fragment version
[  4 bytes fragment_id    ]  ← 1–10
[  4 bytes chunk_size     ]  ← 8388608
[  8 bytes timestamp      ]  ← creation timestamp
[ 12 bytes nonce          ]  ← AES-GCM nonce (unique per fragment)
[ 16 bytes auth_tag       ]  ← AES-GCM authentication tag
[  N bytes ciphertext     ]  ← encrypted chunk data
[ 64 bytes hmac           ]  ← HMAC-SHA512 of all above
```
