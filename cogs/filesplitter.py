import discord
from discord.ext import commands
from discord import app_commands
import os
import aiohttp
import io
import aiofiles
import asyncio
from pathlib import Path
import re
import time
import json
import base64
import urllib.parse
import hashlib
import logging
import shutil
from typing import Optional, Tuple, List, Dict, Any

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ------------------------------------------------------------------
# Logging
# ------------------------------------------------------------------
def setup_enhanced_logging():
    logger = logging.getLogger('FileSplitterBot')
    if not logger.handlers:
        logger.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
        )
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        try:
            file_handler = logging.FileHandler('filesplitter.log')
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except Exception:
            pass
    return logger

log = setup_enhanced_logging()

PROGRESS_FILE = "transfer_progress.json"

# ------------------------------------------------------------------
# New naming + embedded header constants
# ------------------------------------------------------------------
CHUNK_HEADER_MAGIC = b"FSCH"           # File Splitter CHunk
CHUNK_HEADER_VERSION = 1               # Bump if structure changes
# Header layout: MAGIC (4) + VER (1) + JSON_LEN (4 big-endian) + JSON(bytes) + payload
# JSON example for part:
# {"t":"part","path":"folder/file.bin","pi":1,"pt":12,"h":"<sha256 full>","enc":false}
# For consolidated:
# {"t":"con","gi":1,"gt":18,"h":"<sha256 full>","files":[{"p":"a/b.txt","s":123,"h":"sha256"},...]}
# NOTE: header is created BEFORE encryption, so on encrypted chunks we decrypt first, then parse.
#
# New filename schemes (short + self describing):
#  Large file part:  fs_<fileId>_<pi>of<pt>_h<hash8><encflag>.chunk
#  Consolidated group: fc_<gi>of<gt>_f<fc>_h<hash8><encflag>.cpack
#  Where:
#   fileId = first 10 hex of sha256(relative_path)
#   hash8  = first 8 (or 12/16) hex of raw (pre-encryption) chunk hash
#   encflag = 'e' if encrypted else '' (omit if not)
#
#  We still include FULL information inside the embedded header so reassembly does not rely
#  on verbose filenames (only used as quick index / manifest cross reference).

PART_FILENAME_RE = re.compile(r'^fs_(?P<fid>[0-9a-f]{10})_(?P<pi>\d+)of(?P<pt>\d+)_h(?P<h>[0-9a-f]{8,16})(?P<enc>e)?(?:\.chunk)?$')
CONSOLIDATED_FILENAME_RE = re.compile(r'^fc_(?P<gi>\d+)of(?P<gt>\d+)_f(?P<fc>\d+)_h(?P<h>[0-9a-f]{8,16})(?P<enc>e)?(?:\.cpack)?$')

# Backward compatibility patterns (legacy names)
LEGACY_CONSOLIDATED_RE = re.compile(r'consolidated_chunk_(\d+)_of_(\d+).*')
LEGACY_PART_RE = re.compile(r'\.part_(\d+)_of_(\d+)')

# ------------------------------------------------------------------
# Helper functions for naming & headers
# ------------------------------------------------------------------
def short_hash_hex(data: bytes, length: int = 8) -> str:
    return hashlib.sha256(data).hexdigest()[:length]

def path_file_id(rel_path: str) -> str:
    return hashlib.sha256(rel_path.encode('utf-8')).hexdigest()[:10]

def make_part_filename(rel_path: str, pi: int, pt: int, chunk_hash: str, encrypted: bool) -> str:
    # chunk_hash should already be truncated (8-16)
    fid = path_file_id(rel_path)
    return f"fs_{fid}_{pi}of{pt}_h{chunk_hash}{'e' if encrypted else ''}.chunk"

def make_consolidated_filename(group_index: int, total_groups: int, file_count: int, packed_hash: str, encrypted: bool) -> str:
    return f"fc_{group_index}of{total_groups}_f{file_count}_h{packed_hash}{'e' if encrypted else ''}.cpack"

def build_chunk_header(meta: dict) -> bytes:
    # meta must be JSON serializable
    payload = json.dumps(meta, separators=(',', ':')).encode('utf-8')
    header = CHUNK_HEADER_MAGIC + bytes([CHUNK_HEADER_VERSION]) + len(payload).to_bytes(4, 'big') + payload
    return header

def parse_chunk_header(raw: bytes) -> Tuple[Optional[dict], int]:
    try:
        if len(raw) < 9 or raw[0:4] != CHUNK_HEADER_MAGIC:
            return None, 0
        ver = raw[4]
        if ver != CHUNK_HEADER_VERSION:
            return None, 0
        json_len = int.from_bytes(raw[5:9], 'big')
        if 9 + json_len > len(raw):
            return None, 0
        meta_raw = raw[9:9+json_len]
        meta = json.loads(meta_raw.decode('utf-8'))
        return meta, 9 + json_len
    except Exception:
        return None, 0

# ------------------------------------------------------------------
# Cog
# ------------------------------------------------------------------
class FileSplitterCog(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.upload_dir = "downloads"
        chunk_size_mb = int(os.getenv("CHUNK_SIZE_MB", "8"))
        self.max_chunk_size = chunk_size_mb * 1024 * 1024
        self.encryption_enabled = os.getenv("ENABLE_ENCRYPTION", "false").lower() == "true"
        self.encryption_key = os.getenv("ENCRYPTION_KEY", "")
        self.fernet = None
        self.max_retry_attempts = int(os.getenv("MAX_RETRY_ATTEMPTS", "3"))
        self.retry_backoff_factor = float(os.getenv("RETRY_BACKOFF_FACTOR", "2.0"))
        self.enable_hashing = os.getenv("ENABLE_FILE_HASHING", "true").lower() == "true"
        self.uploaded_files = {}
        if self.encryption_enabled:
            self._init_encryption()

    async def cog_load(self):
        if not os.path.exists(self.upload_dir):
            os.makedirs(self.upload_dir)

    # ------------------------------------------------------------------
    # Encryption / Hash helpers
    # ------------------------------------------------------------------
    def _init_encryption(self):
        if self.encryption_key:
            password = self.encryption_key.encode()
            salt = b'discord_file_splitter_salt'
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password))
            self.fernet = Fernet(key)
        else:
            key = Fernet.generate_key()
            self.fernet = Fernet(key)

    def _encrypt_data(self, data: bytes):
        try:
            if not self.encryption_enabled or not self.fernet:
                return data
            return self.fernet.encrypt(data)
        except Exception as e:
            log.error(f"Encryption failed: {e}")
            return data

    def _decrypt_data(self, encrypted_data: bytes):
        try:
            if not self.encryption_enabled or not self.fernet:
                return encrypted_data
            return self.fernet.decrypt(encrypted_data)
        except Exception as e:
            log.error(f"Decryption failed: {e}")
            return encrypted_data

    def _calculate_file_hash(self, file_path):
        if not self.enable_hashing:
            return None
        h = hashlib.sha256()
        try:
            p = Path(file_path)
            if not p.exists() or not p.is_file():
                return None
            if p.stat().st_size > 10 * 1024 * 1024 * 1024:
                return "SKIPPED_TOO_LARGE"
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(64 * 1024), b''):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    def _calculate_chunk_hash(self, data):
        if not self.enable_hashing:
            return None
        try:
            if not data:
                return None
            return hashlib.sha256(data).hexdigest()
        except Exception:
            return None

    def _get_retry_delay(self, attempt_number):
        import random
        base_delay = min(30, (self.retry_backoff_factor ** attempt_number))
        jitter = random.uniform(0.1, 0.3) * base_delay
        return base_delay + jitter

    # ------------------------------------------------------------------
    # Validation / housekeeping
    # ------------------------------------------------------------------
    def _validate_path_input(self, file_path: str) -> Tuple[bool, str, Optional[Path]]:
        try:
            if not file_path or not file_path.strip():
                return False, "File path cannot be empty", None
            path_str = file_path.strip()
            dangerous = ['..', '~/', '/etc/', '/proc/', '/sys/', '/dev/', 'C:\\Windows', 'C:\\System32']
            for pat in dangerous:
                if pat in path_str:
                    return False, f"Potentially dangerous path pattern detected: {pat}", None
            try:
                resolved = Path(path_str).resolve()
            except Exception as e:
                return False, f"Invalid path format: {e}", None
            if not resolved.exists():
                return False, f"Path does not exist: {resolved}", None
            if not os.access(resolved, os.R_OK):
                return False, f"No read permission for path: {resolved}", None
            if resolved.is_file():
                size = resolved.stat().st_size
                if size > 25 * 1024 * 1024 * 1024:
                    return False, f"File too large: {size / (1024**3):.2f}GB (max 25GB)", None
            return True, "", resolved
        except Exception as e:
            return False, f"Unexpected error validating path: {e}", None

    def _validate_channel_name(self, channel_name: Optional[str]) -> Tuple[bool, str, Optional[str]]:
        try:
            if not channel_name:
                return True, "", None
            if not channel_name.strip():
                return False, "Channel name cannot be empty", None
            sanitized = channel_name.strip().lower()
            import string
            allowed = string.ascii_lowercase + string.digits + '-_'
            sanitized = ''.join(c if c in allowed else '-' for c in sanitized)
            sanitized = re.sub(r'-+', '-', sanitized).strip('-')
            if not sanitized:
                return False, "Channel name contains no valid characters", None
            if len(sanitized) > 100:
                return False, "Channel name too long", None
            return True, "", sanitized
        except Exception as e:
            return False, f"Unexpected error validating channel name: {e}", None

    def _cleanup_temp_resources(self, temp_files: List[str] = None, temp_dirs: List[str] = None):
        try:
            if temp_files:
                for t in temp_files:
                    try:
                        if os.path.exists(t):
                            os.remove(t)
                    except Exception:
                        pass
            if temp_dirs:
                for d in temp_dirs:
                    try:
                        if os.path.exists(d):
                            shutil.rmtree(d)
                    except Exception:
                        pass
        except Exception:
            pass

    # ------------------------------------------------------------------
    # File enumeration
    # ------------------------------------------------------------------
    def is_folder(self, path):
        return os.path.isdir(path)

    def get_all_files_in_folder(self, folder_path):
        all_files = []
        folder_path = Path(folder_path).resolve()
        folder_name = folder_path.name
        for root, _, files in os.walk(folder_path):
            for file in files:
                abs_path = Path(root) / file
                rel_path = abs_path.relative_to(folder_path)
                full_rel = Path(folder_name) / rel_path
                all_files.append((str(abs_path), str(full_rel).replace("\\", "/")))
        return all_files

    def calculate_directory_size(self, path):
        if os.path.isfile(path):
            return os.path.getsize(path)
        total = 0
        for root, _, files in os.walk(path):
            for f in files:
                p = os.path.join(root, f)
                try:
                    total += os.path.getsize(p)
                except Exception:
                    pass
        return total

    # ------------------------------------------------------------------
    # Filename encoding (legacy large-file path encoding kept for backward compat)
    # ------------------------------------------------------------------
    def encode_path_for_filename(self, path):
        url_encoded = urllib.parse.quote(path, safe='')
        b64_encoded = base64.b64encode(url_encoded.encode('utf-8')).decode('ascii')
        return b64_encoded.rstrip('=')

    def decode_path_from_filename(self, encoded_path):
        try:
            missing_padding = len(encoded_path) % 4
            if missing_padding:
                encoded_path += '=' * (4 - missing_padding)
            url_encoded = base64.b64decode(encoded_path).decode('utf-8')
            return urllib.parse.unquote(url_encoded)
        except Exception:
            return encoded_path

    # ------------------------------------------------------------------
    # Progress persistence
    # ------------------------------------------------------------------
    def load_progress(self, transfer_type, channel_id):
        if not os.path.exists(PROGRESS_FILE):
            return {}
        try:
            with open(PROGRESS_FILE, "r") as f:
                all_p = json.load(f)
            return all_p.get(f"{transfer_type}_{channel_id}", {})
        except Exception:
            return {}

    def save_progress(self, transfer_type, channel_id, progress_data):
        try:
            if os.path.exists(PROGRESS_FILE):
                with open(PROGRESS_FILE, "r") as f:
                    all_p = json.load(f)
            else:
                all_p = {}
            enhanced = progress_data.copy()
            enhanced.update({
                "last_updated": time.time(),
                "chunk_size_mb": self.max_chunk_size // (1024 * 1024),
                "encryption_enabled": self.encryption_enabled,
                "hashing_enabled": self.enable_hashing,
                "transfer_type": transfer_type
            })
            all_p[f"{transfer_type}_{channel_id}"] = enhanced
            with open(PROGRESS_FILE, "w") as f:
                json.dump(all_p, f, indent=2)
        except Exception:
            pass

    def clear_progress(self, transfer_type, channel_id):
        try:
            if os.path.exists(PROGRESS_FILE):
                with open(PROGRESS_FILE, "r") as f:
                    all_p = json.load(f)
                key = f"{transfer_type}_{channel_id}"
                if key in all_p:
                    del all_p[key]
                    with open(PROGRESS_FILE, "w") as f:
                        json.dump(all_p, f)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Chunk grouping
    # ------------------------------------------------------------------
    def _create_consolidated_files(self, file_list):
        consolidated_groups = []
        large_files = []
        current_group = []
        current_size = 0
        for abs_path, rel_path in file_list:
            fsize = os.path.getsize(abs_path)
            if fsize >= self.max_chunk_size:
                large_files.append((abs_path, rel_path, fsize))
            else:
                if current_size + fsize <= self.max_chunk_size:
                    current_group.append((abs_path, rel_path, fsize))
                    current_size += fsize
                else:
                    if current_group:
                        consolidated_groups.append(current_group)
                    current_group = [(abs_path, rel_path, fsize)]
                    current_size = fsize
        if current_group:
            consolidated_groups.append(current_group)
        return consolidated_groups, large_files

    def _create_consolidated_chunk_data(self, file_group):
        import struct
        parts = []
        file_metadata = []
        parts.append(struct.pack('>I', len(file_group)))
        running_len = 4
        for abs_path, rel_path, file_size in file_group:
            try:
                with open(abs_path, 'rb') as f:
                    file_data = f.read()
                path_bytes = rel_path.encode('utf-8')
                parts.append(struct.pack('>I', len(path_bytes)))
                parts.append(path_bytes)
                parts.append(struct.pack('>Q', len(file_data)))
                parts.append(file_data)
                running_len += 4 + len(path_bytes) + 8 + len(file_data)
                file_metadata.append({
                    'path': rel_path,
                    'size': len(file_data),
                    'offset': running_len - len(file_data)
                })
            except Exception:
                continue
        return b"".join(parts), file_metadata

    def _extract_files_from_consolidated_chunk(self, chunk_data):
        import struct
        files = []
        offset = 0
        try:
            if len(chunk_data) < 4:
                return files
            num_files = struct.unpack('>I', chunk_data[offset:offset+4])[0]
            offset += 4
            for _ in range(num_files):
                if offset + 4 > len(chunk_data):
                    break
                path_len = struct.unpack('>I', chunk_data[offset:offset+4])[0]
                offset += 4
                if offset + path_len > len(chunk_data):
                    break
                path = chunk_data[offset:offset+path_len].decode('utf-8')
                offset += path_len
                if offset + 8 > len(chunk_data):
                    break
                fsize = struct.unpack('>Q', chunk_data[offset:offset+8])[0]
                offset += 8
                if offset + fsize > len(chunk_data):
                    break
                fdata = chunk_data[offset:offset+fsize]
                offset += fsize
                files.append({'path': path, 'size': fsize, 'data': fdata})
        except Exception:
            return files
        return files

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------
    def get_eta(self, start_time, completed, total):
        elapsed = time.time() - start_time
        if completed == 0:
            return "calculating..."
        rate = elapsed / completed
        rem = total - completed
        eta_s = int(rate * rem)
        if eta_s < 60:
            return f"{eta_s}s"
        if eta_s < 3600:
            return f"{eta_s//60}m {eta_s%60}s"
        return f"{eta_s//3600}h {(eta_s%3600)//60}m"

    def get_transfer_speed(self, start_time, bytes_transferred):
        elapsed = time.time() - start_time
        if elapsed == 0:
            return 0.0
        return (bytes_transferred / (1024 * 1024)) / elapsed

    def format_transfer_speed(self, speed_mbps):
        if speed_mbps < 0.1:
            return f"{speed_mbps * 1024:.1f} KB/s"
        elif speed_mbps < 1.0:
            return f"{speed_mbps:.2f} MB/s"
        else:
            return f"{speed_mbps:.1f} MB/s"

    def _is_consolidated_entry(self, file_chunks: dict) -> bool:
        part = file_chunks.get(1)
        return bool(part and 'consolidated_data' in part)

    async def _handle_consolidated_file_batch(self, target_channel, chunks, file_info, total_size):
        start_time = time.time()
        total_written = 0
        written_files = []
        errors = []
        for file_path, file_chunks in chunks.items():
            part = file_chunks.get(1)
            if not part or 'consolidated_data' not in part:
                continue
            data = part['consolidated_data']
            out_path = Path(self.upload_dir) / file_path
            out_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                with open(out_path, 'wb') as f:
                    f.write(data)
                total_written += len(data)
                written_files.append(file_path)
            except Exception as e:
                errors.append(f"{file_path}: {e}")
        elapsed = time.time() - start_time
        speed_mbps = (total_written / (1024 * 1024)) / elapsed if elapsed > 0 else 0
        self.save_progress("download", target_channel.id, {
            "completed_chunks": written_files[:50],
            "total_size_bytes": total_size,
            "uploaded_size_bytes": total_written,
            "start_time": int(start_time),
            "errors": errors,
            "integrity_verified": len(errors) == 0,
            "formatted_speed": self.format_transfer_speed(speed_mbps),
            "encryption_enabled": self.encryption_enabled,
            "hashing_enabled": self.enable_hashing
        })
        percent = min(100, int((total_written / total_size) * 100)) if total_size > 0 else 100
        summary = (
            f"✅ Extracted {len(written_files)} files from consolidated chunk(s)\n"
            f"📊 Size: {total_written / (1024*1024):.2f} MB ({percent}%)\n"
            f"⚡ Speed: {speed_mbps:.2f} MB/s\n"
            f"⏱️ Time: {elapsed:.2f}s"
        )
        if errors:
            summary += f"\n❌ {len(errors)} errors (first 3): " + ", ".join(errors[:3])
        await target_channel.send(summary)
        await target_channel.send(
            "🎉 **Download Complete!**\n"
            f"📁 Files downloaded to: `{self.upload_dir}/`\n"
            f"📊 Total size: {total_size / (1024*1024*1024):.2f} GB\n"
            f"📊 Downloaded: {total_written / (1024*1024*1024):.2f} GB ({percent}%)\n"
            f"📊 Total files: {len(written_files):,}\n"
            f"✅ Successful: {len(written_files):,}\n"
            f"❌ Errors: {len(errors)}\n"
            f"{'🔴 Failed files: ' + ', '.join(errors[:5]) if errors else '🟢 All files downloaded successfully!'}"
        )
        self.clear_progress("download", target_channel.id)
        await self.bot.change_presence(activity=discord.Game(name="Idle"))

    # ------------------------------------------------------------------
    # Manifest helpers
    # ------------------------------------------------------------------
    def _build_manifest(self, root_name, file_list, consolidated_groups_data, large_files_meta, total_size_bytes):
        return {
            "version": 2,  # bump manifest version due to new naming/header scheme
            "generator": "FileSplitterBot",
            "created_utc": int(time.time()),
            "root_name": root_name,
            "chunk_size": self.max_chunk_size,
            "encryption": {"enabled": self.encryption_enabled},
            "hashing": {"enabled": self.enable_hashing, "algorithm": "sha256"},
            "totals": {
                "files": len(file_list),
                "bytes": total_size_bytes
            },
            "consolidated_groups": consolidated_groups_data,
            "large_files": large_files_meta
        }

    async def _upload_manifest(self, channel, manifest):
        try:
            data = json.dumps(manifest, indent=2).encode('utf-8')
            fname = f"{manifest['root_name']}.manifest.json"
            await channel.send("🧾 Uploading manifest...", file=discord.File(io.BytesIO(data), filename=fname))
        except Exception as e:
            await channel.send(f"⚠️ Failed to upload manifest: {e}")

    async def _find_manifest_message(self, channel):
        candidates = []
        async for msg in channel.history(limit=400):
            for att in msg.attachments:
                if att.filename.lower().endswith(".manifest.json"):
                    candidates.append((msg.created_at, att))
        if candidates:
            candidates.sort(key=lambda x: x[0] or 0, reverse=True)
            return candidates[0][1]
        return None

    async def _load_manifest_from_attachment(self, attachment):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(attachment.url) as resp:
                    if resp.status != 200:
                        return None, f"HTTP {resp.status} fetching manifest"
                    raw = await resp.read()
            manifest = json.loads(raw.decode('utf-8'))
            return manifest, None
        except Exception as e:
            return None, str(e)

    # ------------------------------------------------------------------
    # Manifest download path (updated for new naming)
    # ------------------------------------------------------------------
    async def _download_with_manifest(self, interaction, target_channel, manifest):
        root_name = manifest['root_name']
        output_root = self.upload_dir

        required = set()
        for g in manifest.get('consolidated_groups', []):
            required.add(g['packed_filename'])
        for lf in manifest.get('large_files', []):
            for pm in lf.get('parts_meta', []):
                required.add(pm['filename'])

        # improved duplicate suffix normalization
        DUP_BEFORE_EXT_RE = re.compile(r'\s+\(\d+\)(?=(\.[^.]+)$)')
        DUP_TRAILING_RE = re.compile(r'(?:\s+\(\d+\))+$')

        def strip_dupes(name: str) -> str:
            s = DUP_TRAILING_RE.sub('', name)
            while True:
                new_s = DUP_BEFORE_EXT_RE.sub('', s)
                if new_s == s:
                    break
                s = new_s
            s = DUP_TRAILING_RE.sub('', s)
            return s

        required_exact = set(required)
        normalized_map: Dict[str, List[str]] = {}
        for r in required:
            norm = strip_dupes(r)
            normalized_map.setdefault(norm, []).append(r)
            # encryption variant tolerance
            if norm.endswith('.enc'):
                base = norm[:-4]
                normalized_map.setdefault(base, []).append(r)
            else:
                encv = norm + '.enc'
                normalized_map.setdefault(encv, []).append(r)

        attachment_map: Dict[str, Tuple[str, int]] = {}
        await target_channel.send(f"🧾 Manifest detected for `{root_name}`. Collecting {len(required)} attachments (tolerant match)...")

        async for msg in target_channel.history(limit=None):
            for att in msg.attachments:
                fname = att.filename
                norm = strip_dupes(fname)

                if fname in required_exact and fname not in attachment_map:
                    attachment_map[fname] = (att.url, att.size)
                    continue

                # direct normalization
                if norm in normalized_map:
                    for candidate in normalized_map[norm]:
                        if candidate not in attachment_map:
                            attachment_map[candidate] = (att.url, att.size)
                            break

                # attempt variant removal/adding .enc
                if norm.endswith('.enc'):
                    base_no_enc = norm[:-4]
                    if base_no_enc in normalized_map:
                        for candidate in normalized_map[base_no_enc]:
                            if candidate not in attachment_map:
                                attachment_map[candidate] = (att.url, att.size)
                                break
                else:
                    enc_variant = norm + '.enc'
                    if enc_variant in normalized_map:
                        for candidate in normalized_map[enc_variant]:
                            if candidate not in attachment_map:
                                attachment_map[candidate] = (att.url, att.size)
                                break

            if len(attachment_map) == len(required):
                break

        # Fuzzy fallback if still missing small number
        missing_now = required_exact - set(attachment_map.keys())
        if missing_now and len(missing_now) <= 10:
            await target_channel.send("🧪 Running fuzzy fallback for missing attachments...")
            # Build quick index by removing hash segment & enc flag
            def base_core(n: str) -> str:
                n2 = strip_dupes(n)
                return re.sub(r'\.?(sha256_[0-9a-f]{8,32})', '', n2).rstrip('.')
            core_required = {r: base_core(r) for r in missing_now}
            all_atts = []
            async for msg in target_channel.history(limit=None):
                for att in msg.attachments:
                    all_atts.append(att)
            for att in all_atts:
                core_att = base_core(att.filename)
                for req, core_req in list(core_required.items()):
                    if core_att == core_req or core_att.startswith(core_req) or core_req.startswith(core_att):
                        if req not in attachment_map:
                            attachment_map[req] = (att.url, att.size)
                            missing_now.discard(req)
            # second pass partial prefix
        missing_now = required_exact - set(attachment_map.keys())

        if missing_now:
            sample = list(missing_now)[:5]
            await target_channel.send(
                "⚠️ Some required attachments not found even after tolerant / fuzzy matching.\n"
                f"Found: {len(attachment_map)}/{len(required)}\n"
                f"Example missing: {sample}"
            )
            return
        else:
            await target_channel.send(f"✅ Located all {len(required)} required attachments.")

        # Begin extraction
        start_time = time.time()
        results = {'written': 0, 'files': 0, 'errors': [], 'mismatch': []}

        # Consolidated groups
        if manifest.get('consolidated_groups'):
            await target_channel.send(f"📦 Extracting {len(manifest['consolidated_groups'])} consolidated group(s)...")

        for group in manifest.get('consolidated_groups', []):
            packed_name = group['packed_filename']
            if packed_name not in attachment_map:
                results['errors'].append(f"Missing group file {packed_name}")
                continue
            url, _ = attachment_map[packed_name]
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url) as resp:
                        if resp.status != 200:
                            results['errors'].append(f"{packed_name}: HTTP {resp.status}")
                            continue
                        blob = await resp.read()
                data = self._decrypt_data(blob) if self.encryption_enabled else blob
                # parse header
                meta, offset = parse_chunk_header(data)
                if meta and meta.get('t') == 'con':
                    packed_payload = data[offset:]
                else:
                    # legacy style (no embedded header)
                    packed_payload = data
                if group.get('packed_sha256_full') and self.enable_hashing:
                    calc_hash = self._calculate_chunk_hash(packed_payload)
                    if calc_hash != group['packed_sha256_full']:
                        results['mismatch'].append(f"Hash mismatch consolidated {packed_name}")
                extracted = self._extract_files_from_consolidated_chunk(packed_payload)
                expected_files = {f['path']: f for f in group['files']}
                for ef in extracted:
                    exp = expected_files.get(ef['path'])
                    if not exp:
                        results['mismatch'].append(f"Unexpected file {ef['path']}")
                        continue
                    if self.enable_hashing and exp.get('sha256'):
                        if hashlib.sha256(ef['data']).hexdigest() != exp['sha256']:
                            results['mismatch'].append(f"File hash mismatch {ef['path']}")
                            continue
                    out_path = Path(output_root) / ef['path']
                    out_path.parent.mkdir(parents=True, exist_ok=True)
                    with open(out_path, 'wb') as f:
                        f.write(ef['data'])
                    results['written'] += len(ef['data'])
                    results['files'] += 1
            except Exception as e:
                results['errors'].append(f"{packed_name}: {e}")

        # Large files (multipart)
        if manifest.get('large_files'):
            await target_channel.send(f"⬇️ Reconstructing {len(manifest['large_files'])} large file(s)...")
        for lf in manifest.get('large_files', []):
            path = lf['path']
            out_path = Path(output_root) / path
            out_path.parent.mkdir(parents=True, exist_ok=True)
            partial_path = out_path.with_suffix(out_path.suffix + '.partial')
            with open(partial_path, 'wb') as fw:
                for pm in lf.get('parts_meta', []):
                    fname = pm['filename']
                    if fname not in attachment_map:
                        results['errors'].append(f"{path}: missing part {pm['index']}")
                        break
                    url, _ = attachment_map[fname]
                    try:
                        async with aiohttp.ClientSession() as session:
                            async with session.get(url) as resp:
                                if resp.status != 200:
                                    results['errors'].append(f"{path} part {pm['index']}: HTTP {resp.status}")
                                    break
                                blob = await resp.read()
                        data = self._decrypt_data(blob) if self.encryption_enabled else blob
                        meta, offset = parse_chunk_header(data)
                        if meta and meta.get('t') == 'part':
                            payload = data[offset:]
                        else:
                            payload = data
                        if self.enable_hashing and pm.get('sha256_prefix'):
                            calc_hash = self._calculate_chunk_hash(payload)
                            if not calc_hash or calc_hash[:len(pm['sha256_prefix'])] != pm['sha256_prefix']:
                                results['mismatch'].append(f"{path} part {pm['index']} hash prefix mismatch")
                                break
                        fw.write(payload)
                        results['written'] += len(payload)
                    except Exception as e:
                        results['errors'].append(f"{path} part {pm['index']}: {e}")
                        break
            if partial_path.exists():
                if self.enable_hashing and lf.get('sha256_full'):
                    full_calc = self._calculate_file_hash(str(partial_path))
                    if full_calc != lf['sha256_full']:
                        results['mismatch'].append(f"{path} final hash mismatch")
                partial_path.rename(out_path)
                results['files'] += 1

        elapsed = time.time() - start_time
        speed = (results['written'] / (1024*1024)) / elapsed if elapsed > 0 else 0
        await target_channel.send(
            "🎉 **Manifest Download Complete**\n"
            f"📁 Output root: `{output_root}/`\n"
            f"📄 Files written: {results['files']}\n"
            f"📦 Bytes: {results['written'] / (1024*1024):.2f} MB\n"
            f"⚡ Speed: {speed:.2f} MB/s\n"
            f"❌ Errors: {len(results['errors'])}\n"
            f"⚠️ Hash mismatches: {len(results['mismatch'])}\n"
            f"{'First mismatch: ' + results['mismatch'][0] if results['mismatch'] else 'Integrity OK'}"
        )
        await self.bot.change_presence(activity=discord.Game(name="Idle"))

    # ------------------------------------------------------------------
    # Slash Command: Upload
    # ------------------------------------------------------------------
    @app_commands.command(name="upload", description="Uploads a large file or folder from a local path (with resume & ETA).")
    @app_commands.describe(file_path="The full path to the file or folder to upload.")
    @app_commands.describe(channel_name="The name of the channel for the upload (optional).")
    async def upload_file(self, interaction: discord.Interaction, file_path: str, channel_name: str = None):
        path_valid, path_error, absolute_path = self._validate_path_input(file_path)
        if not path_valid:
            await interaction.response.send_message(f"❌ **Path Error:** {path_error}", ephemeral=True)
            return
        channel_valid, channel_error, sanitized_channel_name = self._validate_channel_name(channel_name)
        if not channel_valid:
            await interaction.response.send_message(f"❌ **Channel Name Error:** {channel_error}", ephemeral=True)
            return
        await interaction.response.send_message(f"✅ **Validation complete.** Processing path: `{absolute_path}`...", ephemeral=True)

        temp_files_to_cleanup = []
        temp_dirs_to_cleanup = []
        new_channel = None
        try:
            is_folder = self.is_folder(absolute_path)
            original_name = absolute_path.name

            final_channel_name = sanitized_channel_name if sanitized_channel_name else original_name.lower().replace('.', '-').replace('_', '-')[:97]
            final_channel_name = re.sub(r'[^a-z0-9\-]', '-', final_channel_name)
            final_channel_name = re.sub(r'-+', '-', final_channel_name).strip('-') or "file-upload"

            for attempt in range(3):
                try:
                    name_attempt = final_channel_name if attempt == 0 else f"{final_channel_name}-{attempt+1}"
                    new_channel = await interaction.guild.create_text_channel(name=name_attempt)
                    self.uploaded_files[original_name] = new_channel.id
                    break
                except discord.errors.HTTPException as e:
                    if attempt == 2:
                        await interaction.followup.send(f"❌ **Channel Creation Failed:** {e}", ephemeral=True)
                        return
                    await asyncio.sleep(2 ** attempt)
            if not new_channel:
                await interaction.followup.send("❌ **Failed to create upload channel.**", ephemeral=True)
                return

            await interaction.followup.send(f"✅ **Channel created:** {new_channel.mention}", ephemeral=True)
            await new_channel.send(f"🚀 Starting upload of `{original_name}`{' (folder)' if is_folder else ''}...")

            total_size_bytes = self.calculate_directory_size(str(absolute_path))
            await new_channel.send(f"📊 Total size: {total_size_bytes / (1024*1024*1024):.2f} GB")

            if is_folder:
                file_list = self.get_all_files_in_folder(str(absolute_path))
                await new_channel.send(f"📁 Found {len(file_list)} files.")
            else:
                file_list = [(str(absolute_path), original_name)]

            # Pre-hash each file (for manifest & consolidated header)
            per_file_hash = {}
            if self.enable_hashing:
                await new_channel.send("🔍 Pre-hashing files for manifest (may take a while)...")
                for idx, (abs_p, rel_p) in enumerate(file_list):
                    try:
                        per_file_hash[rel_p] = self._calculate_file_hash(abs_p)
                    except Exception:
                        per_file_hash[rel_p] = None
                    if (idx & 31) == 0:
                        await asyncio.sleep(0)
                    if (idx + 1) % 200 == 0:
                        await new_channel.send(f"   • Hashed {idx+1}/{len(file_list)}")

            consolidated_groups, large_files = self._create_consolidated_files(file_list)

            progress_data = self.load_progress("upload", new_channel.id)
            completed_chunks = set(progress_data.get("completed_chunks", []))
            last_percentage = 0
            start_time = time.time() if not progress_data.get("start_time") else progress_data["start_time"]
            errors = progress_data.get("errors", [])
            uploaded_bytes = progress_data.get("uploaded_size_bytes", 0)

            consolidated_groups_manifest = []
            large_files_manifest = []

            # Upload consolidated groups with new filename + header
            for i, file_group in enumerate(consolidated_groups):
                group_index = i + 1
                consolid_id_core = f"consolidated_chunk_{group_index}_of_{len(consolidated_groups)}"  # legacy id for resume key
                if consolid_id_core in completed_chunks:
                    continue
                try:
                    raw_chunk_data, _meta_unused = self._create_consolidated_chunk_data(file_group)
                    packed_hash_full = self._calculate_chunk_hash(raw_chunk_data) or ""
                    header_meta = {
                        "t": "con",
                        "gi": group_index,
                        "gt": len(consolidated_groups),
                        "h": packed_hash_full,
                        "enc": self.encryption_enabled,
                        "files": [
                            {
                                "p": rel_path,
                                "s": file_size,
                                "h": per_file_hash.get(rel_path)
                            } for _, rel_path, file_size in file_group
                        ]
                    }
                    header = build_chunk_header(header_meta)
                    full_payload = header + raw_chunk_data
                    packed_hash_short = packed_hash_full[:12] if packed_hash_full else "0"*8
                    filename = make_consolidated_filename(group_index, len(consolidated_groups), len(file_group), packed_hash_short, self.encryption_enabled)
                    enc_payload = self._encrypt_data(full_payload)
                    file_obj = discord.File(io.BytesIO(enc_payload), filename=filename)
                    msg_text = f"📦 Consolidated {group_index}/{len(consolidated_groups)} ({len(file_group)} files)"
                    if self.encryption_enabled:
                        msg_text += " 🔐"
                    if packed_hash_full:
                        msg_text += " ✓"
                    retries = self.max_retry_attempts
                    while retries > 0:
                        try:
                            await new_channel.send(msg_text, file=file_obj)
                            await asyncio.sleep(1)
                            completed_chunks.add(consolid_id_core)
                            uploaded_bytes += sum(sz for _, _, sz in file_group)
                            break
                        except discord.errors.HTTPException as e:
                            retries -= 1
                            delay = self._get_retry_delay(self.max_retry_attempts - retries)
                            await new_channel.send(f"❌ Error consolidated group {group_index}: {e} retry {delay:.1f}s ({retries} left)")
                            await asyncio.sleep(delay)
                        except Exception as e:
                            await new_channel.send(f"💥 Unexpected error: {e}")
                            retries = 0
                    consolidated_groups_manifest.append({
                        "index": group_index,
                        "packed_filename": filename,
                        "packed_sha256_full": packed_hash_full,
                        "file_count": len(file_group),
                        "files": [
                            {
                                "path": rel_path,
                                "size": file_size,
                                "sha256": per_file_hash.get(rel_path)
                            } for _, rel_path, file_size in file_group
                        ]
                    })
                except Exception as e:
                    errors.append(f"group {group_index}: {e}")
                    await new_channel.send(f"❌ Consolidated group {group_index} failed: {e}")

            # Upload large files (multi-part)
            for abs_path, rel_path, file_size in large_files:
                total_parts = (file_size + self.max_chunk_size - 1) // self.max_chunk_size
                await new_channel.send(f"⬆️ Uploading large file `{rel_path}` parts: {total_parts}")
                part_meta_list = []
                try:
                    async with aiofiles.open(abs_path, "rb") as f:
                        part_index = 0
                        while True:
                            raw_chunk = await f.read(self.max_chunk_size)
                            if not raw_chunk:
                                break
                            part_index += 1
                            legacy_id = f"{rel_path}.part_{part_index}_of_{total_parts}"  # for resume tracking (not used for new name)
                            if legacy_id in completed_chunks:
                                uploaded_bytes += len(raw_chunk)
                                continue
                            chunk_hash_full = self._calculate_chunk_hash(raw_chunk) or ""
                            header_meta = {
                                "t": "part",
                                "path": rel_path,
                                "pi": part_index,
                                "pt": total_parts,
                                "h": chunk_hash_full,
                                "enc": self.encryption_enabled
                            }
                            header = build_chunk_header(header_meta)
                            payload = header + raw_chunk
                            short_hash = chunk_hash_full[:12] if chunk_hash_full else "0"*8
                            filename = make_part_filename(rel_path, part_index, total_parts, short_hash, self.encryption_enabled)
                            enc_payload = self._encrypt_data(payload)
                            file_obj = discord.File(io.BytesIO(enc_payload), filename=filename)
                            msg_txt = f"📤 `{rel_path}` {part_index}/{total_parts}"
                            if self.encryption_enabled:
                                msg_txt += " 🔐"
                            if chunk_hash_full:
                                msg_txt += " ✓"
                            retries = self.max_retry_attempts
                            success = False
                            while retries > 0:
                                try:
                                    await new_channel.send(msg_txt, file=file_obj)
                                    await asyncio.sleep(0.6)
                                    success = True
                                    break
                                except discord.errors.HTTPException as e:
                                    retries -= 1
                                    delay = self._get_retry_delay(self.max_retry_attempts - retries)
                                    await new_channel.send(f"❌ Part {part_index}: {e} retry {delay:.1f}s ({retries} left)")
                                    await asyncio.sleep(delay)
                                except Exception as e:
                                    await new_channel.send(f"💥 Unexpected part error: {e}")
                                    retries = 0
                            if not success:
                                errors.append(f"{rel_path} part {part_index}")
                                continue
                            completed_chunks.add(legacy_id)
                            uploaded_bytes += len(raw_chunk)
                            part_meta_list.append({
                                "index": part_index,
                                "filename": filename,
                                "sha256_prefix": chunk_hash_full[:16] if chunk_hash_full else None
                            })
                            percent = int((uploaded_bytes / total_size_bytes) * 100) if total_size_bytes else 100
                            if percent // 5 > last_percentage // 5 or percent == 100:
                                eta = self.get_eta(start_time, uploaded_bytes, total_size_bytes)
                                await self.bot.change_presence(activity=discord.Game(name=f"Uploading {percent}% ({eta} left)"))
                                last_percentage = percent
                            transfer_speed = self.get_transfer_speed(start_time, uploaded_bytes)
                            self.save_progress("upload", new_channel.id, {
                                "completed_chunks": list(completed_chunks),
                                "total_size_bytes": total_size_bytes,
                                "uploaded_size_bytes": uploaded_bytes,
                                "start_time": start_time,
                                "errors": errors,
                                "transfer_speed_mbps": transfer_speed,
                                "formatted_speed": self.format_transfer_speed(transfer_speed)
                            })
                    large_files_manifest.append({
                        "path": rel_path,
                        "size": file_size,
                        "parts": total_parts,
                        "sha256_full": per_file_hash.get(rel_path),
                        "parts_meta": part_meta_list
                    })
                    await new_channel.send(f"✅ Finished large file `{rel_path}`")
                except Exception as e:
                    errors.append(f"{rel_path}: {e}")
                    await new_channel.send(f"💥 Large file error `{rel_path}`: {e}")

            manifest = self._build_manifest(
                original_name,
                file_list,
                consolidated_groups_manifest,
                large_files_manifest,
                total_size_bytes
            )
            await self._upload_manifest(new_channel, manifest)

            elapsed = int(time.time() - start_time)
            final_percentage = int((uploaded_bytes / total_size_bytes) * 100) if total_size_bytes > 0 else 100
            final_percentage = min(100, final_percentage)
            self.clear_progress("upload", new_channel.id)
            await new_channel.send(
                f"🎉 **Upload Complete!** `{original_name}`\n"
                f"🧾 Manifest (v{manifest['version']}) attached.\n"
                f"📊 Total size (raw): {total_size_bytes / (1024*1024*1024):.2f} GB\n"
                f"📊 Uploaded (raw): {uploaded_bytes / (1024*1024*1024):.2f} GB ({final_percentage}%)\n"
                f"📦 Consolidated groups: {len(consolidated_groups_manifest)}\n"
                f"🧩 Large files: {len(large_files_manifest)}\n"
                f"❌ Errors: {len(errors)}\n"
                f"⏱️ Time: {elapsed//60}m {elapsed%60}s\n"
                f"{'🔴 Issues: ' + ', '.join(errors[:5]) + ('...' if len(errors) > 5 else '') if errors else '🟢 All chunks uploaded successfully!'}"
            )
            await self.bot.change_presence(activity=discord.Game(name="Idle"))
        except Exception as e:
            log.error(f"Critical error during upload: {e}")
            try:
                if new_channel:
                    await new_channel.send(f"💥 **Critical Upload Error:** {e}")
                    self.clear_progress("upload", new_channel.id)
                else:
                    await interaction.followup.send(f"💥 **Critical Upload Error:** {e}", ephemeral=True)
                await self.bot.change_presence(activity=discord.Game(name="Idle"))
            except Exception:
                pass
        finally:
            try:
                self._cleanup_temp_resources(temp_files_to_cleanup, temp_dirs_to_cleanup)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Slash Command: Download (non-manifest fallback + header aware)
    # ------------------------------------------------------------------
    @app_commands.command(name="download", description="Downloads and rebuilds a file or folder from a channel (with resume & ETA).")
    @app_commands.describe(channel_name="Name of the channel to download from (optional, uses current channel if not specified)")
    async def download_file(self, interaction: discord.Interaction, channel_name: str = None):
        await interaction.response.defer()
        temp_files_to_cleanup = []
        temp_dirs_to_cleanup = []
        target_channel = None
        try:
            if channel_name:
                channel_valid, channel_error, sanitized = self._validate_channel_name(channel_name)
                if not channel_valid:
                    await interaction.followup.send(f"❌ **Channel Name Error:** {channel_error}", ephemeral=True)
                    return
                target_channel = discord.utils.get(interaction.guild.text_channels, name=sanitized)
                if not target_channel:
                    fallback = channel_name.lower().replace(' ', '-')
                    target_channel = discord.utils.get(interaction.guild.text_channels, name=fallback)
                if not target_channel:
                    await interaction.followup.send(f"❌ **Channel not found:** '{channel_name}'", ephemeral=True)
                    return
            else:
                target_channel = interaction.channel

            perms = target_channel.permissions_for(interaction.guild.me)
            if not perms.read_messages or not perms.read_message_history:
                await interaction.followup.send("❌ Missing permissions to read channel/history.", ephemeral=True)
                return

            manifest_attachment = await self._find_manifest_message(target_channel)
            if manifest_attachment:
                manifest, m_err = await self._load_manifest_from_attachment(manifest_attachment)
                if manifest and manifest.get('version') in (1,2):
                    await interaction.followup.send("🧾 **Manifest detected — using accelerated download path.**", ephemeral=True)
                    await self._download_with_manifest(interaction, target_channel, manifest)
                    return
                else:
                    await interaction.followup.send(f"⚠️ Manifest load failed ({m_err or 'invalid format'}). Falling back.", ephemeral=True)

            await interaction.followup.send(f"🔍 **Scanning** {target_channel.mention} **for chunks (no manifest)**", ephemeral=True)

            # Without manifest, we rely on header parsing & filename patterns
            chunks: Dict[str, Dict[int, dict]] = {}
            file_info: Dict[str, dict] = {}
            consolidated_pseudo: Dict[int, dict] = {}  # consolidated groups hold raw for extraction

            async for message in target_channel.history(limit=None):
                for att in message.attachments:
                    fname = att.filename

                    # New scheme consolidated
                    m_con = CONSOLIDATED_FILENAME_RE.match(fname)
                    if m_con:
                        gi = int(m_con.group('gi'))
                        consolidated_pseudo[gi] = {
                            'url': att.url,
                            'size': att.size,
                            'message_id': message.id,
                            'total_groups': int(m_con.group('gt'))
                        }
                        continue

                    # New scheme part
                    m_part = PART_FILENAME_RE.match(fname)
                    if m_part:
                        # We'll need to fetch header for actual rel_path (avoid partial)
                        try:
                            async with aiohttp.ClientSession() as session:
                                async with session.get(att.url) as resp:
                                    if resp.status != 200:
                                        continue
                                    blob = await resp.read()
                            # Attempt decrypt if encrypted marker present
                            if m_part.group('enc') and self.encryption_enabled:
                                blob = self._decrypt_data(blob)
                            meta, offset = parse_chunk_header(blob)
                            if not meta or meta.get('t') != 'part':
                                continue
                            rel_path = meta['path']
                            pi = meta['pi']
                            pt = meta['pt']
                            raw_payload_size = len(blob) - offset
                            if rel_path not in chunks:
                                chunks[rel_path] = {}
                                file_info[rel_path] = {'total_parts': pt, 'size': 0}
                            chunks[rel_path][pi] = {
                                'url': att.url,
                                'size': raw_payload_size,
                                'message_id': message.id,
                                'encrypted': bool(m_part.group('enc')),
                                'header_size': offset
                            }
                            file_info[rel_path]['size'] += raw_payload_size
                        except Exception:
                            continue
                        continue

                    # Legacy consolidated
                    if 'consolidated_chunk_' in fname:
                        lm = LEGACY_CONSOLIDATED_RE.search(fname)
                        if lm:
                            part_num = int(lm.group(1))
                            total = int(lm.group(2))
                            consolidated_pseudo[part_num] = {
                                'url': att.url,
                                'size': att.size,
                                'message_id': message.id,
                                'total_groups': total
                            }
                        continue

                    # Legacy part
                    if '.part_' in fname and '_of_' in fname:
                        pm = LEGACY_PART_RE.search(fname)
                        if not pm:
                            continue
                        try:
                            part_num = int(pm.group(1))
                            total_parts = int(pm.group(2))
                            base_name = fname.split('.part_')[0]
                            # decode original path
                            original_path = self.decode_path_from_filename(base_name)
                            if original_path not in chunks:
                                chunks[original_path] = {}
                                file_info[original_path] = {'total_parts': total_parts, 'size': 0}
                            chunks[original_path][part_num] = {
                                'url': att.url,
                                'size': att.size,
                                'message_id': message.id,
                                'encrypted': fname.endswith('.enc')
                            }
                            file_info[original_path]['size'] += att.size
                        except Exception:
                            continue

            # Expand consolidated pseudo groups
            for gi, info in consolidated_pseudo.items():
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(info['url']) as resp:
                            if resp.status != 200:
                                continue
                            blob = await resp.read()
                    if self.encryption_enabled:
                        # attempt decrypt (if it fails, treat as plain)
                        blob_try = self._decrypt_data(blob)
                        blob = blob_try
                    meta, offset = parse_chunk_header(blob)
                    if meta and meta.get('t') == 'con':
                        payload = blob[offset:]
                    else:
                        payload = blob
                    files = self._extract_files_from_consolidated_chunk(payload)
                    for fobj in files:
                        rp = fobj['path']
                        if rp not in chunks:
                            chunks[rp] = {}
                            file_info[rp] = {'total_parts': 1, 'size': fobj['size']}
                        chunks[rp][1] = {
                            'consolidated_data': fobj['data'],
                            'size': fobj['size'],
                            'message_id': info['message_id']
                        }
                except Exception as e:
                    await target_channel.send(f"❌ Consolidated group {gi} failed: {e}")

            if not chunks:
                await interaction.followup.send("❌ No chunks recognized (no manifest).", ephemeral=True)
                return

            # Summary
            files_summary = []
            total_size = 0
            for fp, info in file_info.items():
                found_parts = len(chunks[fp])
                expected_parts = info['total_parts']
                total_size += info['size']
                status = "✅ Complete" if found_parts == expected_parts else f"⚠️ {found_parts}/{expected_parts} parts"
                files_summary.append(f"📄 `{fp}` - {info['size']/1024/1024:.1f} MB - {status}")
            summary_text = f"🎯 Found {len(chunks)} file(s) ({total_size / (1024 * 1024):.2f} MB total)\n" + "\n".join(files_summary[:10])
            if len(files_summary) > 10:
                summary_text += f"\n... and {len(files_summary)-10} more"
            await target_channel.send(summary_text)

            # Fast path: all single consolidated entries
            if all(file_info[fp]['total_parts'] == 1 and self._is_consolidated_entry(chunks[fp]) for fp in chunks):
                await target_channel.send("⚡ Consolidated fast path extraction...")
                await self._handle_consolidated_file_batch(target_channel, chunks, file_info, total_size)
                return

            progress_data = self.load_progress("download", target_channel.id)
            completed_files = set(progress_data.get("completed_chunks", []))
            start_time = time.time() if not progress_data.get("start_time") else progress_data["start_time"]
            errors = progress_data.get("errors", [])
            downloaded_bytes = progress_data.get("uploaded_size_bytes", 0)

            total_files = len(chunks)
            completed_count = len(completed_files)
            await target_channel.send(f"⬇️ Starting reconstruction ({completed_count}/{total_files} already)")

            for rel_path, file_chunks in chunks.items():
                if rel_path in completed_files:
                    continue
                total_parts = file_info[rel_path]['total_parts']
                # Single consolidated file
                if total_parts == 1 and self._is_consolidated_entry(file_chunks):
                    try:
                        out_path = Path(self.upload_dir) / rel_path
                        out_path.parent.mkdir(parents=True, exist_ok=True)
                        with open(out_path, 'wb') as f:
                            f.write(file_chunks[1]['consolidated_data'])
                        downloaded_bytes += file_chunks[1]['size']
                        completed_files.add(rel_path)
                        completed_count += 1
                        continue
                    except Exception as e:
                        errors.append(f"{rel_path}: {e}")
                        await target_channel.send(f"❌ Extract error {rel_path}: {e}")
                        continue

                # Multipart
                out_path = Path(self.upload_dir) / rel_path
                out_path.parent.mkdir(parents=True, exist_ok=True)
                partial_path = out_path.with_suffix(out_path.suffix + '.partial')
                resume_part = 1
                if partial_path.exists():
                    existing_size = partial_path.stat().st_size
                    resume_part = (existing_size // self.max_chunk_size) + 1
                    await target_channel.send(f"🔄 Resuming `{rel_path}` at part {resume_part}")
                with open(partial_path, 'ab' if resume_part > 1 else 'wb') as fw:
                    for part_num in range(resume_part, total_parts + 1):
                        if part_num not in file_chunks:
                            errors.append(f"{rel_path}: missing part {part_num}")
                            await target_channel.send(f"❌ Missing part {part_num} for `{rel_path}`")
                            break
                        finfo = file_chunks[part_num]
                        if 'consolidated_data' in finfo:
                            fw.write(finfo['consolidated_data'])
                            downloaded_bytes += finfo['size']
                            continue
                        retries = self.max_retry_attempts
                        while retries > 0:
                            try:
                                async with aiohttp.ClientSession() as session:
                                    async with session.get(finfo['url']) as resp:
                                        if resp.status != 200:
                                            raise aiohttp.ClientError(f"HTTP {resp.status}")
                                        blob = await resp.read()
                                if finfo.get('encrypted') and self.encryption_enabled:
                                    blob = self._decrypt_data(blob)
                                # parse header for new scheme
                                meta, offset = parse_chunk_header(blob)
                                payload = blob[offset:] if meta and meta.get('t') == 'part' else blob
                                fw.write(payload)
                                downloaded_bytes += len(payload)
                                break
                            except Exception as e:
                                retries -= 1
                                if retries > 0:
                                    delay = self._get_retry_delay(self.max_retry_attempts - retries)
                                    await target_channel.send(f"⚠️ Part {part_num} retry in {delay:.1f}s ({retries} left)")
                                    await asyncio.sleep(delay)
                                else:
                                    errors.append(f"{rel_path}: part {part_num} failed")
                                    await target_channel.send(f"❌ Part {part_num} failed for `{rel_path}`: {e}")
                        if retries == 0:
                            break
                        if part_num % 10 == 0 and total_parts > 10:
                            await target_channel.send(f"📊 `{rel_path}` {int((part_num/total_parts)*100)}% ({part_num}/{total_parts})")
                if partial_path.exists():
                    partial_path.rename(out_path)
                    completed_files.add(rel_path)
                    completed_count += 1
                    percent = int((downloaded_bytes / total_size) * 100) if total_size else 100
                    eta = self.get_eta(start_time, downloaded_bytes, total_size)
                    await self.bot.change_presence(activity=discord.Game(name=f"Downloading {percent}% ({eta} left)"))
                    transfer_speed = self.get_transfer_speed(start_time, downloaded_bytes)
                    self.save_progress("download", target_channel.id, {
                        "completed_chunks": list(completed_files),
                        "total_size_bytes": total_size,
                        "uploaded_size_bytes": downloaded_bytes,
                        "start_time": start_time,
                        "errors": errors,
                        "integrity_verified": True,
                        "transfer_speed_mbps": transfer_speed,
                        "formatted_speed": self.format_transfer_speed(transfer_speed)
                    })

            elapsed = int(time.time() - start_time)
            final_percentage = int((downloaded_bytes / total_size) * 100) if total_size else 100
            self.clear_progress("download", target_channel.id)
            await target_channel.send(
                f"🎉 **Download Complete (No Manifest)!**\n"
                f"📁 Output: `{self.upload_dir}/`\n"
                f"📦 Total size: {total_size/1024/1024:.2f} MB\n"
                f"⬇️ Downloaded: {downloaded_bytes/1024/1024:.2f} MB ({final_percentage}%)\n"
                f"📄 Files: {total_files}\n"
                f"✅ Success: {completed_count}\n"
                f"❌ Errors: {len(errors)}\n"
                f"⏱️ Time: {elapsed//60}m {elapsed%60}s\n"
                f"{'Issues: ' + ', '.join(errors[:5]) if errors else 'All good!'}"
            )
            await self.bot.change_presence(activity=discord.Game(name="Idle"))
        except Exception as e:
            log.error(f"Critical error during download: {e}")
            try:
                if target_channel:
                    await target_channel.send(f"💥 **Critical Download Error:** {e}")
                    self.clear_progress("download", target_channel.id)
                else:
                    await interaction.followup.send(f"💥 **Critical Download Error:** {e}", ephemeral=True)
                await self.bot.change_presence(activity=discord.Game(name="Idle"))
            except Exception:
                pass
        finally:
            try:
                self._cleanup_temp_resources(temp_files_to_cleanup, temp_dirs_to_cleanup)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Test command
    # ------------------------------------------------------------------
    @app_commands.command(name="test_bulletproofing", description="Test enhanced error handling and validation systems")
    async def test_bulletproofing(self, interaction: discord.Interaction):
        await interaction.response.send_message("🔧 **Testing Enhanced Systems...**", ephemeral=True)
        test_results = []
        try:
            valid, _, _ = self._validate_path_input("/nonexistent/path")
            test_results.append(f"✅ Path validation (invalid): {'PASS' if not valid else 'FAIL'}")
            valid, error, _ = self._validate_path_input("/tmp")
            test_results.append(f"✅ Path validation (valid): {'PASS' if valid else f'FAIL - {error}'}")
        except Exception as e:
            test_results.append(f"❌ Path validation crashed: {e}")
        try:
            valid, _, name = self._validate_channel_name("Test Channel!")
            test_results.append(f"✅ Channel validation: {'PASS' if valid and name == 'test-channel' else f'FAIL - got: {name}'}")
        except Exception as e:
            test_results.append(f"❌ Channel validation crashed: {e}")
        try:
            test_size = self.calculate_directory_size("/tmp")
            test_results.append(f"✅ Directory operations: PASS ({test_size} bytes)")
        except Exception as e:
            test_results.append(f"❌ Directory operations: {e}")
        try:
            import tempfile
            with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
                tmp_file.write(b"test data for hashing")
                tmp_path = tmp_file.name
            file_hash = self._calculate_file_hash(tmp_path)
            os.unlink(tmp_path)
            test_results.append(f"✅ Hash calculation: {'PASS' if file_hash else 'SKIP (disabled)'}")
        except Exception as e:
            test_results.append(f"❌ Hash calculation: {e}")
        try:
            test_data = b"test encryption data"
            encrypted = self._encrypt_data(test_data)
            decrypted = self._decrypt_data(encrypted)
            success = (not self.encryption_enabled) or (test_data == decrypted)
            test_results.append(f"✅ Encryption: {'PASS' if success else 'FAIL'}")
        except Exception as e:
            test_results.append(f"❌ Encryption: {e}")
        try:
            import tempfile
            temps = []
            for _ in range(2):
                with tempfile.NamedTemporaryFile(delete=False) as tmp:
                    temps.append(tmp.name)
            self._cleanup_temp_resources(temps)
            remaining = sum(1 for f in temps if os.path.exists(f))
            test_results.append(f"✅ Cleanup: {'PASS' if remaining == 0 else f'FAIL - {remaining} remain'}")
        except Exception as e:
            test_results.append(f"❌ Cleanup: {e}")
        await interaction.followup.send(f"🧪 **Test Results:**\n" + "\n".join(test_results), ephemeral=True)


async def setup(bot):
    await bot.add_cog(FileSplitterCog(bot))