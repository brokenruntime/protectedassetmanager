#!/usr/bin/env python3
import os
import sys
import json
import hmac
import uuid
import struct
import hashlib
import zipfile
import secrets
import tempfile
import shutil
import atexit
import time
from pathlib import Path
from datetime import datetime
from typing import Optional

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from argon2.low_level import hash_secret_raw, Type
except ImportError:
    print("Use first setup.bat on Windows or setup.sh on Linux ")
    sys.exit(1)

VERSION          = b"PAM2"
FRAGMENT_COUNT   = 10
CHUNK_SIZE       = 8 * 1024 * 1024
EXTENSION        = ".protectedassetpart"
MIN_FREE_SPACE   = 1.5

ARGON2_TIME      = 4
ARGON2_MEM       = 262144
ARGON2_PARALLEL  = 4
ARGON2_LEN       = 64

BLUE   = "\033[94m"
RED    = "\033[91m"
GREEN  = "\033[92m"
RESET  = "\033[0m"

def info(msg: str):
    print(f"{BLUE}[INFO]{RESET} {msg}")

def error(msg: str):
    print(f"{RED}[ERROR]{RESET} {msg}")

def success(msg: str):
    print(f"{GREEN}[SUCCESS]{RESET} {msg}")

_cleanup_registry: list[Path] = []

def _emergency_cleanup():
    for path in _cleanup_registry:
        try:
            if path.is_file():
                _secure_wipe(path)
            elif path.is_dir():
                shutil.rmtree(path, ignore_errors=True)
        except Exception:
            pass

atexit.register(_emergency_cleanup)


class DiskSpaceManager:

    @staticmethod
    def get_dir_size(path: Path) -> int:
        total = 0
        for f in path.rglob("*"):
            if f.is_file():
                try:
                    total += f.stat().st_size
                except OSError:
                    pass
        return total

    @staticmethod
    def get_free_space(path: Path) -> int:
        stat = shutil.disk_usage(path)
        return stat.free

    @staticmethod
    def check_encrypt_space(source_dir: Path, output_dir: Path, tmp_dir: Path):
        source_size = DiskSpaceManager.get_dir_size(source_dir)
        needed      = int(source_size * MIN_FREE_SPACE * 2)

        for check_path, label in [(tmp_dir, "Temp"), (output_dir, "Output")]:
            check_path.mkdir(parents=True, exist_ok=True)
            free = DiskSpaceManager.get_free_space(check_path)

            info(f"{label} drive:")
            info(f"  Free:     {free / 1024**3:.2f} GB")
            info(f"  Required: {needed / 1024**3:.2f} GB")

            if free < needed:
                raise RuntimeError(
                    f"NOT ENOUGH DISK SPACE on {label} drive!\n"
                    f"  Available: {free / 1024**3:.2f} GB\n"
                    f"  Required:  {needed / 1024**3:.2f} GB\n"
                    f"  Source:    {source_size / 1024**3:.2f} GB\n"
                    f"Please free up disk space!"
                )

        success(f"Disk space sufficient ({source_size / 1024**3:.2f} GB source data)")
        return source_size

    @staticmethod
    def monitor_space_during_write(output_dir: Path, min_free_gb: float = 2.0):
        free = DiskSpaceManager.get_free_space(output_dir)
        if free < min_free_gb * 1024**3:
            raise RuntimeError(
                f"CRITICAL: Only {free / 1024**3:.2f} GB remaining!\n"
                f"Write operation aborted to prevent corruption!"
            )


def _secure_wipe(path: Path, passes: int = 3):
    if not path.exists():
        return
    try:
        size = path.stat().st_size
        with open(path, "r+b") as f:
            for pattern in [b'\x00', b'\xFF', None]:
                f.seek(0)
                written = 0
                while written < size:
                    chunk_len = min(CHUNK_SIZE, size - written)
                    data = secrets.token_bytes(chunk_len) if pattern is None \
                           else pattern * chunk_len
                    f.write(data)
                    written += chunk_len
                f.flush()
                os.fsync(f.fileno())
    except Exception:
        pass
    finally:
        path.unlink(missing_ok=True)


class ProgressTracker:

    def __init__(self, total_bytes: int, label: str = ""):
        self.total      = total_bytes
        self.processed  = 0
        self.label      = label
        self.start      = time.time()
        self.last_print = 0

    def update(self, bytes_done: int):
        self.processed += bytes_done
        now = time.time()

        if now - self.last_print < 0.5 and self.processed < self.total:
            return
        self.last_print = now

        pct     = (self.processed / self.total * 100) if self.total > 0 else 100
        elapsed = now - self.start
        speed   = (self.processed / elapsed / 1024**2) if elapsed > 0 else 0
        eta     = ((self.total - self.processed) / (self.processed / elapsed)) \
                  if self.processed > 0 and elapsed > 0 else 0

        bar_len = 30
        filled  = int(bar_len * pct / 100)
        bar     = "#" * filled + "-" * (bar_len - filled)

        print(
            f"\r  {self.label} [{bar}] {pct:5.1f}% "
            f"{self.processed/1024**2:.1f}/{self.total/1024**2:.1f} MB "
            f"@ {speed:.1f} MB/s  ETA: {eta:.0f}s   ",
            end="", flush=True
        )

        if self.processed >= self.total:
            elapsed_total = time.time() - self.start
            avg_speed     = self.total / elapsed_total / 1024**2 if elapsed_total > 0 else 0
            print(f"\n{GREEN}[SUCCESS]{RESET} Done in {elapsed_total:.1f}s @ avg {avg_speed:.1f} MB/s")


class ZIP64StreamEngine:

    def create(self, source_dir: Path, zip_path: Path):
        info("Scanning directory...")
        files       = sorted([f for f in source_dir.rglob("*") if f.is_file()])
        total_bytes = sum(f.stat().st_size for f in files)

        info(f"Files:      {len(files):,}")
        info(f"Total size: {total_bytes / 1024**2:.1f} MB")

        compress_level = 1 if total_bytes > 10 * 1024**3 else 6
        info(f"Compression level: {compress_level}")

        progress = ProgressTracker(total_bytes, "ZIP") if total_bytes > 0 else None

        try:
            with zipfile.ZipFile(
                zip_path, "w",
                compression=zipfile.ZIP_DEFLATED,
                compresslevel=compress_level,
                allowZip64=True
            ) as zf:
                for file_path in files:
                    arcname = str(file_path.relative_to(source_dir.parent))
                    zi              = zipfile.ZipInfo(arcname)
                    zi.compress_type = zipfile.ZIP_DEFLATED

                    with zf.open(zi, "w", force_zip64=True) as zf_out:
                        with open(file_path, "rb") as src:
                            while True:
                                chunk = src.read(CHUNK_SIZE)
                                if not chunk:
                                    break
                                zf_out.write(chunk)
                                if progress:
                                    progress.update(len(chunk))

        except Exception as e:
            _secure_wipe(zip_path)
            raise RuntimeError(f"ZIP64 creation failed: {e}")

        zip_size = zip_path.stat().st_size
        info(f"ZIP size: {zip_size / 1024**2:.1f} MB")

    def extract(self, zip_path: Path, output_dir: Path):
        output_dir.mkdir(parents=True, exist_ok=True)

        with zipfile.ZipFile(zip_path, "r", allowZip64=True) as zf:
            members     = zf.infolist()
            total_bytes = sum(m.file_size for m in members)
            progress    = ProgressTracker(total_bytes, "Extract") if total_bytes > 0 else None

            for member in members:
                target = output_dir / member.filename
                target.parent.mkdir(parents=True, exist_ok=True)

                if member.is_dir():
                    target.mkdir(exist_ok=True)
                    continue

                with zf.open(member) as src, open(target, "wb") as dst:
                    while True:
                        chunk = src.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        dst.write(chunk)
                        if progress:
                            progress.update(len(chunk))


class StreamEncryptEngine:

    FOOTER_MARKER = b'\xDE\xAD\xBE\xEF'

    def derive_fragment_key(self, master_key: bytes, frag_idx: int) -> bytes:
        return hashlib.blake2b(
            master_key,
            key=master_key[:32],
            person=f"fragment_{frag_idx:04d}".encode().ljust(16, b'\x00')[:16]
        ).digest()[:32]

    def encrypt_and_split(
        self,
        zip_path: Path,
        output_dir: Path,
        output_name: str,
        aes_key: bytes,
        hmac_key: bytes,
    ) -> list[dict]:

        zip_size  = zip_path.stat().st_size
        frag_size = (zip_size + FRAGMENT_COUNT - 1) // FRAGMENT_COUNT

        info("Starting stream encryption")
        info(f"ZIP size:        {zip_size / 1024**2:.1f} MB")
        info(f"Fragment size:   {frag_size / 1024**2:.1f} MB (approx.)")
        info(f"Fragment count:  {FRAGMENT_COUNT}")

        fragment_infos = []
        progress       = ProgressTracker(zip_size, "Encrypt")

        with open(zip_path, "rb") as zip_src:

            for frag_idx in range(FRAGMENT_COUNT):
                frag_path     = output_dir / f"{output_name}{EXTENSION}{frag_idx + 1}"
                frag_key      = self.derive_fragment_key(aes_key, frag_idx)
                hmac_ctx      = hmac.new(hmac_key, digestmod=hashlib.sha512)
                aesgcm        = AESGCM(frag_key)
                bytes_written = 0

                DiskSpaceManager.monitor_space_during_write(output_dir)

                tmp_path = frag_path.with_suffix(".tmp")
                _cleanup_registry.append(tmp_path)

                try:
                    with open(tmp_path, "wb") as frag_out:

                        header = (
                            VERSION
                            + struct.pack(">H", 2)
                            + struct.pack(">H", frag_idx)
                            + struct.pack(">H", FRAGMENT_COUNT)
                            + b'\x00' * 6
                        )
                        frag_out.write(header)
                        hmac_ctx.update(header)

                        remaining = frag_size
                        while remaining > 0:
                            to_read = min(CHUNK_SIZE, remaining)
                            chunk   = zip_src.read(to_read)
                            if not chunk:
                                break

                            nonce     = secrets.token_bytes(12)
                            enc_chunk = aesgcm.encrypt(nonce, chunk, None)

                            frame = (
                                nonce
                                + struct.pack(">I", len(enc_chunk))
                                + enc_chunk
                            )

                            frag_out.write(frame)
                            hmac_ctx.update(frame)

                            remaining     -= len(chunk)
                            bytes_written += len(chunk)
                            progress.update(len(chunk))

                        mac    = hmac_ctx.digest()
                        footer = self.FOOTER_MARKER + mac
                        frag_out.write(footer)
                        frag_out.flush()
                        os.fsync(frag_out.fileno())

                    tmp_path.rename(frag_path)
                    _cleanup_registry.remove(tmp_path)

                except Exception as e:
                    _secure_wipe(tmp_path)
                    for inf in fragment_infos:
                        _secure_wipe(Path(inf["path"]))
                    raise RuntimeError(f"Fragment {frag_idx+1} failed: {e}")

                frag_hash        = self._hash_file(frag_path)
                frag_size_actual = frag_path.stat().st_size

                fragment_infos.append({
                    "index"    : frag_idx,
                    "path"     : str(frag_path),
                    "name"     : frag_path.name,
                    "sha256"   : frag_hash.hex(),
                    "size"     : frag_size_actual,
                    "plaintext": bytes_written,
                })

                success(f"Fragment {frag_idx+1:02d}: {frag_size_actual/1024**2:.1f} MB written")

        return fragment_infos

    def decrypt_and_assemble(
        self,
        fragment_paths: list[Path],
        output_zip: Path,
        aes_key: bytes,
        hmac_key: bytes,
        expected_hash: bytes,
    ):
        total_size = sum(p.stat().st_size for p in fragment_paths)
        progress   = ProgressTracker(total_size, "Decrypt")
        tmp_zip    = output_zip.with_suffix(".tmp")
        _cleanup_registry.append(tmp_zip)

        try:
            with open(tmp_zip, "wb") as zip_out:

                for frag_idx, frag_path in enumerate(fragment_paths):
                    frag_key = self.derive_fragment_key(aes_key, frag_idx)
                    hmac_ctx = hmac.new(hmac_key, digestmod=hashlib.sha512)
                    aesgcm   = AESGCM(frag_key)
                    frag_sz  = frag_path.stat().st_size

                    info(f"Fragment {frag_idx+1}/{FRAGMENT_COUNT}: {frag_path.name}")

                    with open(frag_path, "rb") as frag_in:

                        header = frag_in.read(16)
                        if header[:4] != VERSION:
                            raise ValueError(
                                f"Fragment {frag_idx+1}: Invalid magic bytes!"
                            )

                        stored_frag_idx = struct.unpack(">H", header[6:8])[0]
                        if stored_frag_idx != frag_idx:
                            raise ValueError(
                                f"Wrong fragment order! "
                                f"Expected {frag_idx}, received {stored_frag_idx}"
                            )

                        hmac_ctx.update(header)

                        FOOTER_SIZE = 4 + 64
                        content_end = frag_sz - FOOTER_SIZE
                        bytes_read  = 16

                        while bytes_read < content_end:
                            frame_hdr = frag_in.read(16)
                            if len(frame_hdr) < 16:
                                break

                            nonce   = frame_hdr[:12]
                            enc_len = struct.unpack(">I", frame_hdr[12:16])[0]

                            if enc_len > CHUNK_SIZE * 2:
                                raise ValueError(f"Invalid chunk size: {enc_len}")

                            enc_chunk = frag_in.read(enc_len)
                            if len(enc_chunk) != enc_len:
                                raise ValueError(f"Incomplete chunk in fragment {frag_idx+1}!")

                            frame = frame_hdr + enc_chunk
                            hmac_ctx.update(frame)

                            try:
                                plain = aesgcm.decrypt(nonce, enc_chunk, None)
                            except Exception:
                                raise ValueError(
                                    f"AES-GCM authentication FAILED!\n"
                                    f"Fragment {frag_idx+1} is tampered or wrong key!"
                                )

                            zip_out.write(plain)
                            bytes_read += len(frame)
                            progress.update(len(frame))

                        footer        = frag_in.read(FOOTER_SIZE)
                        stored_marker = footer[:4]
                        stored_hmac   = footer[4:68]

                        if stored_marker != self.FOOTER_MARKER:
                            raise ValueError(f"Footer marker missing in fragment {frag_idx+1}!")

                        computed_hmac = hmac_ctx.digest()
                        if not hmac.compare_digest(stored_hmac, computed_hmac):
                            raise ValueError(
                                f"HMAC INVALID for fragment {frag_idx+1}!\n"
                                f"File tampered or wrong key!"
                            )

                        success(f"Fragment {frag_idx+1:02d}: HMAC valid | AES-GCM valid | Integrity confirmed")

                zip_out.flush()
                os.fsync(zip_out.fileno())

            tmp_zip.rename(output_zip)
            _cleanup_registry.remove(tmp_zip)

            info("Verifying ZIP integrity...")
            actual_hash = self._hash_file(output_zip)

            if not hmac.compare_digest(expected_hash, actual_hash):
                _secure_wipe(output_zip)
                raise ValueError(
                    "CRITICAL: ZIP hash INVALID!\n"
                    "Reconstructed data does not match original!\n"
                    "Output has NOT been created."
                )

            success("ZIP integrity confirmed (SHA-256 valid)")

        except Exception:
            if tmp_zip.exists():
                _secure_wipe(tmp_zip)
            raise

    @staticmethod
    def _hash_file(path: Path) -> bytes:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(CHUNK_SIZE):
                h.update(chunk)
        return h.digest()


def derive_keys(password: str, salt: bytes) -> tuple[bytes, bytes]:
    info("Running Argon2id key derivation... (may take 5-15 seconds)")
    raw = hash_secret_raw(
        password.encode(),
        salt,
        time_cost=ARGON2_TIME,
        memory_cost=ARGON2_MEM,
        parallelism=ARGON2_PARALLEL,
        hash_len=ARGON2_LEN,
        type=Type.ID,
    )
    return raw[:32], raw[32:64]


def cmd_encrypt(folder: str, password: str):
    source_dir  = Path(folder).resolve()
    output_dir  = source_dir.parent / (source_dir.name + "_encrypted")
    output_name = source_dir.name
    tmp_dir     = Path(tempfile.gettempdir()) / f"pam2_{uuid.uuid4().hex}"

    if not source_dir.exists():
        error(f"Folder not found: {source_dir}")
        sys.exit(1)

    output_dir.mkdir(parents=True, exist_ok=True)
    tmp_dir.mkdir(parents=True, exist_ok=True)
    _cleanup_registry.append(tmp_dir)

    print(f"\n{'='*60}")
    print(f"  Protected Asset Manager v2.0 -- ENCRYPT")
    print(f"{'='*60}")
    info(f"Source: {source_dir}")
    info(f"Output: {output_dir}")
    info(f"Temp:   {tmp_dir}")

    info("Checking disk space...")
    DiskSpaceManager.check_encrypt_space(source_dir, output_dir, tmp_dir)

    salt = secrets.token_bytes(32)
    info("Deriving keys (Argon2id)...")
    aes_key, hmac_key = derive_keys(password, salt)
    success("Keys derived")

    zip_path = tmp_dir / f"{output_name}.zip"
    _cleanup_registry.append(zip_path)

    zip_engine = ZIP64StreamEngine()
    zip_engine.create(source_dir, zip_path)

    info("Computing ZIP hash...")
    zip_hash = StreamEncryptEngine._hash_file(zip_path)
    success(f"Hash: {zip_hash.hex()[:32]}...")

    enc_engine     = StreamEncryptEngine()
    fragment_infos = enc_engine.encrypt_and_split(
        zip_path, output_dir, output_name, aes_key, hmac_key
    )

    info("Wiping temporary ZIP...")
    _secure_wipe(zip_path)
    shutil.rmtree(tmp_dir, ignore_errors=True)
    if tmp_dir in _cleanup_registry:
        _cleanup_registry.remove(tmp_dir)

    token_data = {
        "version"        : 2,
        "created"        : datetime.now().isoformat(),
        "source_name"    : output_name,
        "salt"           : salt.hex(),
        "zip_hash"       : zip_hash.hex(),
        "fragment_count" : FRAGMENT_COUNT,
        "fragments"      : fragment_infos,
        "algorithm"      : {
            "kdf"        : "argon2id",
            "cipher"     : "AES-256-GCM",
            "mac"        : "HMAC-SHA512",
            "kdf_params" : {
                "time_cost"  : ARGON2_TIME,
                "memory_cost": ARGON2_MEM,
                "parallelism": ARGON2_PARALLEL,
            }
        }
    }

    token_path = output_dir / f"{output_name}.token"
    with open(token_path, "w", encoding="utf-8") as f:
        json.dump(token_data, f, indent=2, ensure_ascii=False)

    print(f"\n{'='*60}")
    success("ENCRYPT COMPLETED")
    print(f"{'='*60}")
    info(f"Output:    {output_dir}")
    info(f"Token:     {token_path}")
    info(f"Fragments: {FRAGMENT_COUNT}x {output_name}{EXTENSION}*")
    print()
    info("IMPORTANT: Keep the token file in a safe location!")
    info("Without the token file and password, decryption is IMPOSSIBLE!")
    print()


def cmd_decrypt(frag_folder: str, password: str, token_file: str):
    frag_dir   = Path(frag_folder).resolve()
    token_path = Path(token_file).resolve()
    output_dir = frag_dir.parent / (frag_dir.name + "_decrypted")

    print(f"\n{'='*60}")
    print(f"  Protected Asset Manager v2.0 -- DECRYPT")
    print(f"{'='*60}")
    info(f"Fragments: {frag_dir}")
    info(f"Token:     {token_path}")
    info(f"Output:    {output_dir}")

    if not frag_dir.exists():
        error(f"Fragment folder not found: {frag_dir}")
        sys.exit(1)

    if not token_path.exists():
        error(f"Token file not found: {token_path}")
        sys.exit(1)

    info("Loading token...")
    with open(token_path, "r", encoding="utf-8") as f:
        token_data = json.load(f)

    salt        = bytes.fromhex(token_data["salt"])
    zip_hash    = bytes.fromhex(token_data["zip_hash"])
    frag_infos  = token_data["fragments"]
    source_name = token_data["source_name"]

    info(f"Created:    {token_data.get('created', 'unknown')}")
    info(f"Source:     {source_name}")
    info(f"Fragments:  {token_data['fragment_count']}")

    info("Deriving keys (Argon2id)...")
    aes_key, hmac_key = derive_keys(password, salt)
    success("Keys derived")

    info("Verifying fragments...")
    fragment_paths = []

    for inf in sorted(frag_infos, key=lambda x: x["index"]):
        frag_path = frag_dir / inf["name"]

        if not frag_path.exists():
            error(f"Fragment missing: {frag_path}")
            sys.exit(1)

        actual_hash = StreamEncryptEngine._hash_file(frag_path).hex()
        if actual_hash != inf["sha256"]:
            error(f"Fragment corrupted: {frag_path.name}")
            error(f"  Expected: {inf['sha256'][:32]}...")
            error(f"  Received: {actual_hash[:32]}...")
            sys.exit(1)

        fragment_paths.append(frag_path)
        success(f"Fragment {inf['index']+1:02d} OK ({frag_path.stat().st_size/1024**2:.1f} MB)")

    output_dir.mkdir(parents=True, exist_ok=True)
    tmp_zip = output_dir / "_assembled.zip"

    enc_engine = StreamEncryptEngine()
    enc_engine.decrypt_and_assemble(
        fragment_paths, tmp_zip, aes_key, hmac_key, zip_hash
    )

    info(f"Extracting ZIP to {output_dir}...")
    zip_engine = ZIP64StreamEngine()
    zip_engine.extract(tmp_zip, output_dir)

    info("Wiping temporary ZIP...")
    _secure_wipe(tmp_zip)

    print(f"\n{'='*60}")
    success("DECRYPT COMPLETED")
    print(f"{'='*60}")
    info(f"Output: {output_dir}")
    print()


def main():
    if len(sys.argv) < 2:
        print(r"    ___  ___  ____  ____________________________    ___   __________________  ")
        print(r"   / _ \/ _ \/ __ \/_  __/ __/ ___/_  __/ __/ _ \  / _ | / __/ __/ __/_  __/  ")
        print(r"  / ___/ , _/ /_/ / / / / _// /__  / / / _// // / / __ |_\ \_\ \/ _/  / /     ")
        print(r" /_/  /_/|_|\____/ /_/ /___/\___/ /_/ /___/____/ /_/ |_/___/___/___/ /_/      ")
        print("  _____MANAGER_________________________________________________________________")
        print()
        print("  ENCRYPT:")
        print("    python protectedassetmanager.py encrypt <folder> <password>")
        print()
        print("  DECRYPT:")
        print("    python protectedassetmanager.py decrypt <folder> <password> <token_file>")
        print()
        sys.exit(0)

    cmd = sys.argv[1].lower()

    if cmd == "encrypt":
        if len(sys.argv) < 4:
            error("Usage: encrypt <folder> <password>")
            sys.exit(1)
        cmd_encrypt(sys.argv[2], sys.argv[3])

    elif cmd == "decrypt":
        if len(sys.argv) < 5:
            error("Usage: decrypt <fragment_folder> <password> <token_file>")
            sys.exit(1)
        cmd_decrypt(sys.argv[2], sys.argv[3], sys.argv[4])

    else:
        error(f"Unknown command: {cmd}")
        error("Use: encrypt / decrypt")
        sys.exit(1)


if __name__ == "__main__":
    main()
