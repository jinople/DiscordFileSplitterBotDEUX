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
import tempfile
import shutil
import stat
from typing import Optional, Tuple, List, Dict, Any
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PROGRESS_FILE = "transfer_progress.json"

class FileSplitterCog(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.upload_dir = "downloads"
        
        # Configure chunk size from environment variable
        chunk_size_mb = int(os.getenv("CHUNK_SIZE_MB", "8"))
        self.max_chunk_size = chunk_size_mb * 1024 * 1024
        
        # Configure encryption settings
        self.encryption_enabled = os.getenv("ENABLE_ENCRYPTION", "false").lower() == "true"
        self.encryption_key = os.getenv("ENCRYPTION_KEY", "")
        self.fernet = None
        
        # Configure retry and error handling
        self.max_retry_attempts = int(os.getenv("MAX_RETRY_ATTEMPTS", "3"))
        self.retry_backoff_factor = float(os.getenv("RETRY_BACKOFF_FACTOR", "2.0"))
        
        # Configure file integrity checking
        self.enable_hashing = os.getenv("ENABLE_FILE_HASHING", "true").lower() == "true"
        
        self.uploaded_files = {}
        
        # Initialize encryption if enabled
        if self.encryption_enabled:
            self._init_encryption()

    async def cog_load(self):
        if not os.path.exists(self.upload_dir):
            os.makedirs(self.upload_dir)
    
    def _init_encryption(self):
        """Initialize encryption with key derivation from password or random key"""
        if self.encryption_key:
            # Derive key from provided password
            password = self.encryption_key.encode()
            salt = b'discord_file_splitter_salt'  # Use consistent salt
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password))
            self.fernet = Fernet(key)
        else:
            # Generate random key if none provided
            key = Fernet.generate_key()
            self.fernet = Fernet(key)
            # Note: Generated encryption key - add to .env file as ENCRYPTION_KEY for consistent decryption
    
    def _encrypt_data(self, data):
        """Encrypt data if encryption is enabled with comprehensive error handling"""
        try:
            if not self.encryption_enabled or not self.fernet:
                return data
                
            if not data:
                logging.warning("Attempting to encrypt empty data")
                return data
                
            if isinstance(data, str):
                data = data.encode('utf-8')
                
            return self.fernet.encrypt(data)
            
        except Exception as e:
            logging.error(f"Encryption failed: {e}")
            # Return original data if encryption fails - operation can continue
            return data
    
    def _decrypt_data(self, encrypted_data):
        """Decrypt data if encryption is enabled with comprehensive error handling"""
        try:
            if not self.encryption_enabled or not self.fernet:
                return encrypted_data
                
            if not encrypted_data:
                logging.warning("Attempting to decrypt empty data")
                return encrypted_data
                
            return self.fernet.decrypt(encrypted_data)
            
        except Exception as e:
            logging.error(f"Decryption failed: {e}")
            # Return original data if decryption fails
            return encrypted_data
    
    def _calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of a file with comprehensive error handling"""
        if not self.enable_hashing:
            return None
        
        hash_sha256 = hashlib.sha256()
        
        try:
            path_obj = Path(file_path)
            
            if not path_obj.exists():
                logging.warning(f"Cannot hash non-existent file: {file_path}")
                return None
                
            if not path_obj.is_file():
                logging.warning(f"Cannot hash non-file: {file_path}")
                return None
                
            # Check file size before hashing
            try:
                file_size = path_obj.stat().st_size
                if file_size > 10 * 1024 * 1024 * 1024:  # 10GB limit for hashing
                    logging.warning(f"Skipping hash for very large file: {file_path} ({file_size / (1024**3):.2f}GB)")
                    return "SKIPPED_TOO_LARGE"
            except OSError as e:
                logging.warning(f"Cannot get file size for hashing: {file_path}: {e}")
                return None
            
            # Use larger chunks for better performance
            chunk_size = 64 * 1024  # 64KB chunks
            bytes_processed = 0
            
            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    hash_sha256.update(chunk)
                    bytes_processed += len(chunk)
                    
                    # Progress logging for very large files
                    if bytes_processed % (100 * 1024 * 1024) == 0:  # Every 100MB
                        logging.debug(f"Hashing progress: {bytes_processed / (1024**2):.1f}MB processed")
                        
            return hash_sha256.hexdigest()
            
        except PermissionError:
            logging.warning(f"Permission denied while hashing file: {file_path}")
            return None
        except IOError as e:
            logging.warning(f"IO error while hashing file {file_path}: {e}")
            return None
        except Exception as e:
            logging.error(f"Unexpected error while hashing file {file_path}: {e}")
            return None
    
    def _calculate_chunk_hash(self, data):
        """Calculate SHA-256 hash of chunk data with error handling"""
        if not self.enable_hashing:
            return None
            
        try:
            if not data:
                return None
                
            if isinstance(data, str):
                data = data.encode('utf-8')
                
            return hashlib.sha256(data).hexdigest()
            
        except Exception as e:
            logging.warning(f"Error calculating chunk hash: {e}")
            return None
    
    def _get_retry_delay(self, attempt_number):
        """Calculate exponential backoff delay for retries"""
        import random
        # Add jitter to prevent thundering herd
        base_delay = min(30, (self.retry_backoff_factor ** attempt_number))
        jitter = random.uniform(0.1, 0.3) * base_delay
        return base_delay + jitter

    def _validate_path_input(self, file_path: str) -> Tuple[bool, str, Optional[Path]]:
        """
        Comprehensive path validation with security checks.
        Returns: (is_valid, error_message, resolved_path)
        """
        try:
            if not file_path or not file_path.strip():
                return False, "File path cannot be empty", None
            
            # Sanitize and resolve path
            path_str = file_path.strip()
            
            # Check for dangerous path patterns
            dangerous_patterns = ['..', '~/', '/etc/', '/proc/', '/sys/', '/dev/', 'C:\\Windows', 'C:\\System32']
            for pattern in dangerous_patterns:
                if pattern in path_str:
                    return False, f"Potentially dangerous path pattern detected: {pattern}", None
            
            try:
                resolved_path = Path(path_str).resolve()
            except (OSError, ValueError) as e:
                return False, f"Invalid path format: {str(e)}", None
            
            # Check if path exists
            if not resolved_path.exists():
                return False, f"Path does not exist: {resolved_path}", None
            
            # Check read permissions
            try:
                if not os.access(resolved_path, os.R_OK):
                    return False, f"No read permission for path: {resolved_path}", None
            except OSError as e:
                return False, f"Cannot check permissions for path: {str(e)}", None
            
            # Check file size limits (25GB max for safety)
            if resolved_path.is_file():
                max_size = 25 * 1024 * 1024 * 1024  # 25GB
                try:
                    size = resolved_path.stat().st_size
                    if size > max_size:
                        return False, f"File too large: {size / (1024**3):.2f}GB (max: 25GB)", None
                except OSError as e:
                    return False, f"Cannot get file size: {str(e)}", None
            elif resolved_path.is_dir():
                # For directories, do a quick size check
                try:
                    total_size = self.calculate_directory_size(str(resolved_path))
                    max_dir_size = 100 * 1024 * 1024 * 1024  # 100GB max for directories
                    if total_size > max_dir_size:
                        return False, f"Directory too large: {total_size / (1024**3):.2f}GB (max: 100GB)", None
                except Exception as e:
                    # Log warning but don't fail - size check is advisory
                    logging.warning(f"Could not calculate directory size: {e}")
            
            return True, "", resolved_path
            
        except Exception as e:
            return False, f"Unexpected error validating path: {str(e)}", None

    def _validate_channel_name(self, channel_name: Optional[str]) -> Tuple[bool, str, Optional[str]]:
        """
        Validate and sanitize channel name.
        Returns: (is_valid, error_message, sanitized_name)
        """
        try:
            if not channel_name:
                return True, "", None
            
            if not channel_name.strip():
                return False, "Channel name cannot be empty", None
            
            sanitized = channel_name.strip()
            
            # Discord channel name restrictions
            if len(sanitized) > 100:
                return False, "Channel name too long (max 100 characters)", None
            
            if len(sanitized) < 1:
                return False, "Channel name too short", None
            
            # Remove invalid characters and convert to lowercase
            import string
            allowed_chars = string.ascii_lowercase + string.digits + '-_'
            sanitized = ''.join(c if c in allowed_chars else '-' for c in sanitized.lower())
            
            # Remove consecutive dashes and trim
            sanitized = re.sub(r'-+', '-', sanitized).strip('-')
            
            if not sanitized:
                return False, "Channel name contains no valid characters", None
            
            return True, "", sanitized
            
        except Exception as e:
            return False, f"Unexpected error validating channel name: {str(e)}", None

    def _safe_create_channel(self, guild, name: str) -> Tuple[bool, str, Optional[discord.TextChannel]]:
        """
        Safely create a Discord channel with error handling.
        Returns: (success, error_message, channel)
        """
        try:
            # Additional channel name cleanup
            safe_name = name[:97] + "..." if len(name) > 100 else name
            safe_name = re.sub(r'[^a-z0-9\-_]', '-', safe_name.lower())
            safe_name = re.sub(r'-+', '-', safe_name).strip('-')
            
            if not safe_name:
                safe_name = "file-upload"
            
            return True, "", None  # Will be handled by actual async call
            
        except Exception as e:
            return False, f"Error preparing channel creation: {str(e)}", None

    def _cleanup_temp_resources(self, temp_files: List[str] = None, temp_dirs: List[str] = None):
        """Safely cleanup temporary files and directories"""
        try:
            if temp_files:
                for temp_file in temp_files:
                    try:
                        if os.path.exists(temp_file):
                            os.remove(temp_file)
                    except Exception as e:
                        logging.warning(f"Failed to cleanup temp file {temp_file}: {e}")
            
            if temp_dirs:
                for temp_dir in temp_dirs:
                    try:
                        if os.path.exists(temp_dir):
                            shutil.rmtree(temp_dir)
                    except Exception as e:
                        logging.warning(f"Failed to cleanup temp directory {temp_dir}: {e}")
                        
        except Exception as e:
            logging.error(f"Error during cleanup: {e}")

    def is_folder(self, path):
        """Check if path is a directory with enhanced error handling"""
        try:
            return os.path.isdir(path)
        except (OSError, TypeError):
            return False

    def get_all_files_in_folder(self, folder_path):
        """Get all files in a folder with their relative paths preserved and comprehensive error handling"""
        all_files = []
        
        try:
            folder_path = Path(folder_path).resolve()
            folder_name = folder_path.name
            
            if not folder_path.exists() or not folder_path.is_dir():
                logging.error(f"Invalid folder path: {folder_path}")
                return all_files
            
            file_count = 0
            max_files = 10000  # Safety limit
            
            for root, dirs, files in os.walk(folder_path):
                # Filter out inaccessible directories
                dirs[:] = [d for d in dirs if os.access(os.path.join(root, d), os.R_OK)]
                
                for file in files:
                    if file_count >= max_files:
                        logging.warning(f"File count limit reached ({max_files}), stopping enumeration")
                        break
                        
                    try:
                        abs_path = Path(root) / file
                        
                        # Skip if file is not readable
                        if not os.access(abs_path, os.R_OK):
                            logging.warning(f"Skipping unreadable file: {abs_path}")
                            continue
                        
                        # Skip very large files (per-file limit)
                        try:
                            size = abs_path.stat().st_size
                            if size > 5 * 1024 * 1024 * 1024:  # 5GB per file
                                logging.warning(f"Skipping very large file: {abs_path} ({size / (1024**3):.2f}GB)")
                                continue
                        except OSError:
                            logging.warning(f"Cannot get size for file: {abs_path}")
                            continue
                        
                        rel_path_from_folder = abs_path.relative_to(folder_path)
                        full_rel_path = Path(folder_name) / rel_path_from_folder
                        all_files.append((str(abs_path), str(full_rel_path).replace("\\", "/")))
                        file_count += 1
                        
                    except (OSError, ValueError) as e:
                        logging.warning(f"Error processing file {file} in {root}: {e}")
                        continue
                        
                if file_count >= max_files:
                    break
                    
        except Exception as e:
            logging.error(f"Error walking directory {folder_path}: {e}")
            
        return all_files

    def calculate_directory_size(self, path):
        """Calculate total size of directory or file in bytes with enhanced error handling"""
        total_size = 0
        
        try:
            path_obj = Path(path)
            
            if path_obj.is_file():
                try:
                    return path_obj.stat().st_size
                except OSError as e:
                    logging.warning(f"Cannot get size of file {path}: {e}")
                    return 0
            
            if not path_obj.is_dir():
                logging.warning(f"Path is neither file nor directory: {path}")
                return 0
                
            file_count = 0
            max_files = 10000  # Safety limit
            
            for root, dirs, files in os.walk(path):
                # Filter out inaccessible directories
                dirs[:] = [d for d in dirs if os.access(os.path.join(root, d), os.R_OK)]
                
                for file in files:
                    if file_count >= max_files:
                        logging.warning(f"File count limit reached ({max_files}) during size calculation")
                        break
                        
                    file_path = os.path.join(root, file)
                    try:
                        if os.access(file_path, os.R_OK):
                            total_size += os.path.getsize(file_path)
                        file_count += 1
                    except (OSError, IOError) as e:
                        logging.warning(f"Cannot get size of {file_path}: {e}")
                        continue
                        
                if file_count >= max_files:
                    break
                    
        except Exception as e:
            logging.error(f"Error calculating directory size for {path}: {e}")
            
        return total_size

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
            original_path = urllib.parse.unquote(url_encoded)
            return original_path
        except Exception:
            return encoded_path

    def load_progress(self, transfer_type, channel_id):
        """Load progress data with enhanced error handling"""
        try:
            if not os.path.exists(PROGRESS_FILE):
                return {}
                
            # Check if file is readable
            if not os.access(PROGRESS_FILE, os.R_OK):
                logging.warning(f"Cannot read progress file: {PROGRESS_FILE}")
                return {}
                
            with open(PROGRESS_FILE, "r", encoding='utf-8') as f:
                all_progress = json.load(f)
                
            key = f"{transfer_type}_{channel_id}"
            return all_progress.get(key, {})
            
        except json.JSONDecodeError as e:
            logging.error(f"Invalid JSON in progress file: {e}")
            # Try to backup corrupted file
            try:
                backup_name = f"{PROGRESS_FILE}.backup.{int(time.time())}"
                shutil.copy2(PROGRESS_FILE, backup_name)
                logging.info(f"Backed up corrupted progress file to: {backup_name}")
            except Exception:
                pass
            return {}
        except Exception as e:
            logging.error(f"Error loading progress: {e}")
            return {}

    def save_progress(self, transfer_type, channel_id, progress_data):
        """Save progress data with atomic operations and enhanced error handling"""
        try:
            # Read existing data
            all_progress = {}
            if os.path.exists(PROGRESS_FILE):
                try:
                    with open(PROGRESS_FILE, "r", encoding='utf-8') as f:
                        all_progress = json.load(f)
                except (json.JSONDecodeError, IOError) as e:
                    logging.warning(f"Could not read existing progress file: {e}")
                    all_progress = {}
            
            # Validate progress data
            if not isinstance(progress_data, dict):
                logging.error("Progress data must be a dictionary")
                return False
                
            # Enhance progress data with additional metadata
            enhanced_data = progress_data.copy()
            enhanced_data.update({
                "last_updated": time.time(),
                "chunk_size_mb": self.max_chunk_size // (1024 * 1024),
                "encryption_enabled": self.encryption_enabled,
                "hashing_enabled": self.enable_hashing,
                "transfer_type": transfer_type,
                "version": "1.0"  # For future compatibility
            })
            
            # Update progress
            key = f"{transfer_type}_{channel_id}"
            all_progress[key] = enhanced_data
            
            # Atomic write using temporary file
            temp_file = f"{PROGRESS_FILE}.tmp.{int(time.time())}.{os.getpid()}"
            try:
                with open(temp_file, "w", encoding='utf-8') as f:
                    json.dump(all_progress, f, indent=2, ensure_ascii=False)
                
                # Atomic move
                if os.name == 'nt':  # Windows
                    if os.path.exists(PROGRESS_FILE):
                        os.remove(PROGRESS_FILE)
                    os.rename(temp_file, PROGRESS_FILE)
                else:  # Unix-like
                    os.rename(temp_file, PROGRESS_FILE)
                    
                return True
                
            except Exception as e:
                logging.error(f"Error writing progress file: {e}")
                # Cleanup temp file
                try:
                    if os.path.exists(temp_file):
                        os.remove(temp_file)
                except Exception:
                    pass
                return False
                
        except Exception as e:
            logging.error(f"Error saving progress: {e}")
            return False

    def clear_progress(self, transfer_type, channel_id):
        """Clear progress data with enhanced error handling"""
        try:
            if not os.path.exists(PROGRESS_FILE):
                return True
                
            with open(PROGRESS_FILE, "r", encoding='utf-8') as f:
                all_progress = json.load(f)
            
            key = f"{transfer_type}_{channel_id}"
            if key in all_progress:
                del all_progress[key]
                
                # Atomic write
                temp_file = f"{PROGRESS_FILE}.tmp.{int(time.time())}.{os.getpid()}"
                try:
                    with open(temp_file, "w", encoding='utf-8') as f:
                        json.dump(all_progress, f, indent=2, ensure_ascii=False)
                    
                    if os.name == 'nt':  # Windows
                        if os.path.exists(PROGRESS_FILE):
                            os.remove(PROGRESS_FILE)
                        os.rename(temp_file, PROGRESS_FILE)
                    else:  # Unix-like
                        os.rename(temp_file, PROGRESS_FILE)
                        
                except Exception as e:
                    logging.error(f"Error clearing progress: {e}")
                    try:
                        if os.path.exists(temp_file):
                            os.remove(temp_file)
                    except Exception:
                        pass
                    return False
                    
            return True
            
        except Exception as e:
            logging.error(f"Error clearing progress: {e}")
            return False

    def _create_consolidated_files(self, file_list):
        """Group small files into consolidated chunks and return processing plan"""
        consolidated_groups = []
        large_files = []
        current_group = []
        current_group_size = 0
        
        for abs_path, rel_path in file_list:
            file_size = os.path.getsize(abs_path)
            
            # Files >= 8MB are processed individually
            if file_size >= self.max_chunk_size:
                large_files.append((abs_path, rel_path, file_size))
            else:
                # Try to add to current group
                if current_group_size + file_size <= self.max_chunk_size:
                    current_group.append((abs_path, rel_path, file_size))
                    current_group_size += file_size
                else:
                    # Current group is full, start new one
                    if current_group:
                        consolidated_groups.append(current_group)
                    current_group = [(abs_path, rel_path, file_size)]
                    current_group_size = file_size
        
        # Add remaining group
        if current_group:
            consolidated_groups.append(current_group)
            
        return consolidated_groups, large_files

    def _create_consolidated_chunk_data(self, file_group):
        """Create consolidated chunk data with metadata for multiple files"""
        import struct
        
        chunk_data = b""
        file_metadata = []
        
        # Header: number of files (4 bytes)
        chunk_data += struct.pack('>I', len(file_group))
        
        # For each file: path_length (4 bytes), path (variable), size (8 bytes), data (variable)
        for abs_path, rel_path, file_size in file_group:
            try:
                with open(abs_path, 'rb') as f:
                    file_data = f.read()
                
                # Encode path as UTF-8
                path_bytes = rel_path.encode('utf-8')
                
                # Add metadata: path_length, path, size
                chunk_data += struct.pack('>I', len(path_bytes))
                chunk_data += path_bytes
                chunk_data += struct.pack('>Q', len(file_data))
                chunk_data += file_data
                
                file_metadata.append({
                    'path': rel_path,
                    'size': len(file_data),
                    'offset': len(chunk_data) - len(file_data)
                })
                
            except Exception as e:
                # Skip files that can't be read
                continue
                
        return chunk_data, file_metadata

    def _extract_files_from_consolidated_chunk(self, chunk_data):
        """Extract individual files from a consolidated chunk"""
        import struct
        
        files = []
        offset = 0
        
        try:
            # Read number of files (4 bytes)
            if len(chunk_data) < 4:
                return files
            
            num_files = struct.unpack('>I', chunk_data[offset:offset+4])[0]
            offset += 4
            
            # Read each file
            for i in range(num_files):
                if offset + 4 > len(chunk_data):
                    break
                    
                # Read path length (4 bytes)
                path_length = struct.unpack('>I', chunk_data[offset:offset+4])[0]
                offset += 4
                
                if offset + path_length > len(chunk_data):
                    break
                    
                # Read path
                path = chunk_data[offset:offset+path_length].decode('utf-8')
                offset += path_length
                
                if offset + 8 > len(chunk_data):
                    break
                    
                # Read file size (8 bytes)
                file_size = struct.unpack('>Q', chunk_data[offset:offset+8])[0]
                offset += 8
                
                if offset + file_size > len(chunk_data):
                    break
                    
                # Read file data
                file_data = chunk_data[offset:offset+file_size]
                offset += file_size
                
                files.append({
                    'path': path,
                    'size': file_size,
                    'data': file_data
                })
                
        except Exception as e:
            # Error parsing consolidated chunk
            return files
            
        return files

    def clear_progress(self, transfer_type, channel_id):
        try:
            if os.path.exists(PROGRESS_FILE):
                with open(PROGRESS_FILE, "r") as f:
                    all_progress = json.load(f)
                key = f"{transfer_type}_{channel_id}"
                if key in all_progress:
                    del all_progress[key]
                    with open(PROGRESS_FILE, "w") as f:
                        json.dump(all_progress, f)
        except Exception as e:
            # Silent error handling for progress clear
            pass

    def get_eta(self, start_time, completed, total):
        elapsed = time.time() - start_time
        if completed == 0:
            return "calculating..."
        rate = elapsed / completed
        remaining = total - completed
        eta_seconds = int(rate * remaining)
        if eta_seconds < 60:
            return f"{eta_seconds}s"
        elif eta_seconds < 3600:
            return f"{eta_seconds//60}m {eta_seconds%60}s"
        else:
            return f"{eta_seconds//3600}h {(eta_seconds%3600)//60}m"
    
    def get_transfer_speed(self, start_time, bytes_transferred):
        """Calculate transfer speed in MB/s"""
        elapsed = time.time() - start_time
        if elapsed == 0:
            return 0.0
        return (bytes_transferred / (1024 * 1024)) / elapsed
    
    def format_transfer_speed(self, speed_mbps):
        """Format transfer speed for display"""
        if speed_mbps < 0.1:
            return f"{speed_mbps * 1024:.1f} KB/s"
        elif speed_mbps < 1.0:
            return f"{speed_mbps:.2f} MB/s"
        else:
            return f"{speed_mbps:.1f} MB/s"

    @app_commands.command(name="upload", description="Uploads a large file or folder from a local path (with resume & ETA).")
    @app_commands.describe(file_path="The full path to the file or folder to upload.")
    @app_commands.describe(channel_name="The name of the channel for the upload (optional).")
    async def upload_file(self, interaction: discord.Interaction, file_path: str, channel_name: str = None):
        # Comprehensive input validation
        path_valid, path_error, absolute_path = self._validate_path_input(file_path)
        if not path_valid:
            await interaction.response.send_message(f"❌ **Path Error:** {path_error}", ephemeral=True)
            return
        
        channel_valid, channel_error, sanitized_channel_name = self._validate_channel_name(channel_name)
        if not channel_valid:
            await interaction.response.send_message(f"❌ **Channel Name Error:** {channel_error}", ephemeral=True)
            return
        
        # Initial response
        await interaction.response.send_message(f"✅ **Validation complete.** Processing path: `{absolute_path}`...", ephemeral=True)
        
        try:
            # Determine if folder and get basic info
            is_folder = self.is_folder(absolute_path)
            original_name = absolute_path.name
            
            # Create sanitized channel name
            if sanitized_channel_name:
                final_channel_name = sanitized_channel_name
            else:
                final_channel_name = original_name.lower().replace('.', '-').replace('_', '-')[:97]
                final_channel_name = re.sub(r'[^a-z0-9\-]', '-', final_channel_name)
                final_channel_name = re.sub(r'-+', '-', final_channel_name).strip('-')
                if not final_channel_name:
                    final_channel_name = "file-upload"
            
            # Create Discord channel with enhanced error handling
            new_channel = None
            max_channel_attempts = 3
            
            for attempt in range(max_channel_attempts):
                try:
                    # Add attempt suffix if not first try
                    channel_name_attempt = final_channel_name
                    if attempt > 0:
                        channel_name_attempt = f"{final_channel_name}-{attempt + 1}"
                        
                    new_channel = await interaction.guild.create_text_channel(name=channel_name_attempt)
                    self.uploaded_files[original_name] = new_channel.id
                    break
                    
                except discord.errors.HTTPException as e:
                    if attempt == max_channel_attempts - 1:
                        await interaction.followup.send(f"❌ **Channel Creation Failed:** {e}", ephemeral=True)
                        return
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                    
                except Exception as e:
                    await interaction.followup.send(f"❌ **Unexpected Error Creating Channel:** {e}", ephemeral=True)
                    return
            
            if not new_channel:
                await interaction.followup.send("❌ **Failed to create upload channel after multiple attempts.**", ephemeral=True)
                return
            
            await interaction.followup.send(f"✅ **Channel created:** {new_channel.mention}", ephemeral=True)
            
            # Send initial upload message with safety checks
            try:
                await new_channel.send(f"🚀 **Starting upload of** `{original_name}`{' (folder)' if is_folder else ''}...")
                await new_channel.send(f"🔧 **Configuration:** Chunk size: {self.max_chunk_size // (1024*1024)}MB, "
                                     f"Encryption: {'✅' if self.encryption_enabled else '❌'}, "
                                     f"Hashing: {'✅' if self.enable_hashing else '❌'}")
            except Exception as e:
                logging.error(f"Failed to send initial upload messages: {e}")
                # Continue anyway - this is not critical
            
            # Calculate total directory size with timeout protection
            try:
                await new_channel.send("📊 **Calculating total size...** (This may take a moment for large directories)")
                total_size_bytes = self.calculate_directory_size(str(absolute_path))
                
                if total_size_bytes == 0:
                    await new_channel.send("⚠️ **Warning:** Could not calculate size or directory is empty")
                else:
                    await new_channel.send(f"📊 **Total size:** {total_size_bytes / (1024*1024*1024):.2f} GB")
                    
            except Exception as e:
                logging.error(f"Error calculating directory size: {e}")
                await new_channel.send(f"⚠️ **Size calculation failed:** {e}")
                total_size_bytes = 0  # Continue with unknown size
            
            # Build file list with comprehensive error handling
            file_list = []
            try:
                if is_folder:
                    await new_channel.send("📁 **Scanning folder structure...** (Large folders may take time)")
                    file_list = self.get_all_files_in_folder(str(absolute_path))
                    
                    if not file_list:
                        await new_channel.send("❌ **No accessible files found in the folder.**")
                        return
                        
                    await new_channel.send(f"📁 **Found {len(file_list)} accessible files:**")
                    
                    # Show first few files
                    for i, (abs_path, rel_path) in enumerate(file_list[:3]):
                        try:
                            file_size = os.path.getsize(abs_path)
                            await new_channel.send(f"   📄 `{rel_path}` ({file_size / (1024*1024):.2f} MB)")
                        except Exception:
                            await new_channel.send(f"   📄 `{rel_path}` (size unknown)")
                            
                    if len(file_list) > 3:
                        await new_channel.send(f"   ... and {len(file_list) - 3} more files")
                else:
                    # Single file
                    file_list = [(str(absolute_path), original_name)]
                    file_size = absolute_path.stat().st_size
                    await new_channel.send(f"📄 **Single file:** `{original_name}` ({file_size / (1024*1024):.2f} MB)")
                    
            except Exception as e:
                logging.error(f"Error building file list: {e}")
                await new_channel.send(f"❌ **Error scanning files:** {e}")
                return
            
            # Continue with upload process wrapped in comprehensive error handling
            try:
                # Group files for consolidation
                consolidated_groups, large_files = self._create_consolidated_files(file_list)
                
                # Calculate total chunks needed
                chunk_index_map = []
                
                # Add consolidated chunks (each group becomes 1 chunk)
                for i, group in enumerate(consolidated_groups):
                    group_paths = [rel_path for _, rel_path, _ in group]
                    chunk_index_map.append(("consolidated", i+1, len(consolidated_groups), group_paths))
                
                # Add large file chunks (processed individually)
                for abs_path, rel_path, file_size in large_files:
                    total_parts = (file_size + self.max_chunk_size - 1) // self.max_chunk_size
                    chunk_index_map.extend([(rel_path, i+1, total_parts, None) for i in range(total_parts)])
            
                    total_chunks = len(chunk_index_map)

                    progress_data = self.load_progress("upload", new_channel.id)
                    completed_chunks = set(progress_data.get("completed_chunks", []))
                    last_percentage = 0
                    start_time = time.time() if not progress_data.get("start_time") else progress_data["start_time"]
                    errors = progress_data.get("errors", [])
                    uploaded_bytes = progress_data.get("uploaded_size_bytes", 0)

                    await new_channel.send(f"📊 Total chunks to upload: {total_chunks}")
                    if consolidated_groups:
                        await new_channel.send(f"📦 Consolidating {sum(len(group) for group in consolidated_groups)} small files into {len(consolidated_groups)} chunks")

                    # Upload consolidated chunks first
                    for i, file_group in enumerate(consolidated_groups):
                        consolidated_chunk_id = f"consolidated_chunk_{i+1}_of_{len(consolidated_groups)}"
                        
                        if consolidated_chunk_id in completed_chunks:
                            continue
                            
                        try:
                            # Create consolidated chunk data
                            chunk_data, file_metadata = self._create_consolidated_chunk_data(file_group)
                            group_size = len(chunk_data)
                            
                            file_paths = [rel_path for _, rel_path, _ in file_group]
                            await new_channel.send(f"📦 Creating consolidated chunk {i+1}/{len(consolidated_groups)} ({group_size:,} bytes, {len(file_group)} files):")
                            for _, rel_path, file_size in file_group[:3]:
                                await new_channel.send(f"   📄 {rel_path} ({file_size:,} bytes)")
                            if len(file_group) > 3:
                                await new_channel.send(f"   ... and {len(file_group) - 3} more files")
                            
                            # Calculate hash before encryption
                            chunk_hash = self._calculate_chunk_hash(chunk_data) if self.enable_hashing else None
                            
                            # Encrypt chunk if encryption is enabled  
                            processed_chunk = self._encrypt_data(chunk_data)
                            
                            # Create enhanced filename with metadata
                            metadata_suffix = ".consolidated"
                            if chunk_hash:
                                metadata_suffix += f".sha256_{chunk_hash[:16]}"
                            if self.encryption_enabled:
                                metadata_suffix += ".enc"
                            
                            enhanced_chunk_id = f"{consolidated_chunk_id}{metadata_suffix}"
                            chunk_file = discord.File(fp=io.BytesIO(processed_chunk), filename=enhanced_chunk_id)
                            
                            upload_msg = f"📦 Consolidated chunk {i+1}/{len(consolidated_groups)} ({len(file_group)} files)"
                            if self.encryption_enabled:
                                upload_msg += " 🔐"
                            if chunk_hash:
                                upload_msg += " ✓"
                                
                            retries = self.max_retry_attempts
                            while retries > 0:
                                try:
                                    await new_channel.send(upload_msg, file=chunk_file)
                                    await asyncio.sleep(1)
                                    completed_chunks.add(consolidated_chunk_id)
                                    uploaded_bytes += group_size
                                    break
                                except discord.errors.HTTPException as e:
                                    retries -= 1
                                    delay = self._get_retry_delay(self.max_retry_attempts - retries)
                                    await new_channel.send(f"❌ Error with consolidated chunk {i+1}: {e}. Retrying in {delay}s... ({retries} left)")
                                    await asyncio.sleep(delay)
                                except Exception as e:
                                    await new_channel.send(f"💥 Unexpected error: {e}")
                                    retries = 0
                                    
                        except Exception as e:
                            await new_channel.send(f"❌ Failed to create consolidated chunk {i+1}: {e}")
                            errors.append(f"Consolidated chunk {i+1}: {e}")

                    # Upload large files (processed individually)
                    for abs_path, rel_path, file_size in large_files:
                        total_parts = (file_size + self.max_chunk_size - 1) // self.max_chunk_size
                        await new_channel.send(f"⬆️ Uploading `{rel_path}` ({file_size:,} bytes, {total_parts} parts)...")
                        
                        try:
                            async with aiofiles.open(abs_path, "rb") as f:
                                for i in range(total_parts):
                                    encoded_path = self.encode_path_for_filename(rel_path)
                                    chunk_id = f"{encoded_path}.part_{i+1}_of_{total_parts}"
                                    if i == 0:
                                        await new_channel.send(f"🔧 Encoding `{rel_path}` → `{encoded_path}`")
                                    if chunk_id in completed_chunks:
                                        continue
                                    if (i + 1) % 50 == 0:
                                        await asyncio.sleep(5)
                                    retries = self.max_retry_attempts
                                    chunk_uploaded_flag = False
                                    while retries > 0:
                                        try:
                                            chunk = await f.read(self.max_chunk_size)
                                            if not chunk:
                                                break
                                            
                                            # Calculate hash before encryption
                                            chunk_hash = self._calculate_chunk_hash(chunk) if self.enable_hashing else None
                                            
                                            # Encrypt chunk if encryption is enabled  
                                            processed_chunk = self._encrypt_data(chunk)
                                            
                                            # Create enhanced filename with metadata
                                            metadata_suffix = ""
                                            if chunk_hash:
                                                metadata_suffix += f".sha256_{chunk_hash[:16]}"
                                            if self.encryption_enabled:
                                                metadata_suffix += ".enc"
                                            
                                            enhanced_chunk_id = f"{chunk_id}{metadata_suffix}"
                                            chunk_file = discord.File(fp=io.BytesIO(processed_chunk), filename=enhanced_chunk_id)
                                            
                                            upload_msg = f"📦 `{rel_path}` - Part {i+1}/{total_parts}"
                                            if self.encryption_enabled:
                                                upload_msg += " 🔐"
                                            if chunk_hash:
                                                upload_msg += " ✓"
                                                
                                            await new_channel.send(upload_msg, file=chunk_file)
                                            await asyncio.sleep(1)
                                            chunk_uploaded_flag = True
                                            uploaded_bytes += len(chunk)  # Track original bytes uploaded
                                            break
                                        except discord.errors.HTTPException as e:
                                            retries -= 1
                                            delay = self._get_retry_delay(self.max_retry_attempts - retries)
                                            await new_channel.send(f"❌ Error with part {i+1}: {e}. Retrying in {delay}s... ({retries} left)")
                                            await asyncio.sleep(delay)
                                        except Exception as e:
                                            await new_channel.send(f"💥 Unexpected error: {e}")
                                            retries = 0
                                    if not chunk_uploaded_flag:
                                        await new_channel.send(f"🔴 Upload failed for `{rel_path}` part {i+1}. File incomplete.")
                                        errors.append(chunk_id)
                                        continue
                                    completed_chunks.add(chunk_id)
                                    
                                    # Calculate percentage based on bytes, not chunks
                                    byte_percentage = int((uploaded_bytes / total_size_bytes) * 100) if total_size_bytes > 0 else 0
                                    eta = self.get_eta(start_time, uploaded_bytes, total_size_bytes)
                                    
                                    if byte_percentage // 5 > last_percentage // 5 or byte_percentage == 100:
                                        await self.bot.change_presence(activity=discord.Game(name=f"Uploading: {byte_percentage}% ({eta} left)"))
                                        last_percentage = byte_percentage
                                        
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
                            await new_channel.send(f"✅ Upload complete for `{rel_path}`.")
                        except Exception as e:
                            await new_channel.send(f"💥 Error during upload of `{rel_path}`: {e}")
                            errors.append(f"{rel_path}: {e}")

                    elapsed = int(time.time() - start_time)
                    final_percentage = int((uploaded_bytes / total_size_bytes) * 100) if total_size_bytes > 0 else 100
                    self.clear_progress("upload", new_channel.id)
                    await new_channel.send(
                        f"🎉 **Upload Complete!** `{original_name}`\n"
                        f"📊 Total size: {total_size_bytes / (1024*1024*1024):.2f} GB\n"
                        f"📊 Uploaded: {uploaded_bytes / (1024*1024*1024):.2f} GB ({final_percentage}%)\n"
                        f"📊 Total chunks: {total_chunks:,}\n"
                        f"❌ Errors: {len(errors)}\n"
                        f"⏱️ Time: {elapsed//60}m {elapsed%60}s\n"
                        f"{'🔴 Failed chunks: ' + ', '.join(errors[:5]) + ('...' if len(errors) > 5 else '') if errors else '🟢 All chunks uploaded successfully!'}"
                    )
                    await self.bot.change_presence(activity=discord.Game(name="Idle"))
                
        except Exception as e:
            logging.error(f"Critical error during upload: {e}")
            try:
                if 'new_channel' in locals() and new_channel:
                    await new_channel.send(f"💥 **Critical Upload Error:** {e}\n"
                                         f"Upload has been terminated. Please try again or contact support.")
                    self.clear_progress("upload", new_channel.id)
                else:
                    await interaction.followup.send(f"💥 **Critical Upload Error:** {e}", ephemeral=True)
                await self.bot.change_presence(activity=discord.Game(name="Idle"))
            except Exception as cleanup_error:
                logging.error(f"Error during upload cleanup: {cleanup_error}")
        finally:
            # Final cleanup
            try:
                temp_files = getattr(self, '_temp_files_to_cleanup', [])
                temp_dirs = getattr(self, '_temp_dirs_to_cleanup', [])
                self._cleanup_temp_resources(temp_files, temp_dirs)
            except Exception as e:
                logging.error(f"Error during final cleanup: {e}")

    @app_commands.command(name="download", description="Downloads and rebuilds a file or folder from a channel (with resume & ETA).")
    @app_commands.describe(channel_name="Name of the channel to download from (optional, uses current channel if not specified)")
    async def download_file(self, interaction: discord.Interaction, channel_name: str = None):
        await interaction.response.defer()
        
        # Determine target channel
        if channel_name:
            target_channel = discord.utils.get(interaction.guild.text_channels, name=channel_name.lower().replace(' ', '-'))
            if not target_channel:
                await interaction.followup.send(f"❌ Channel '{channel_name}' not found.", ephemeral=True)
                return
        else:
            target_channel = interaction.channel
        
        await interaction.followup.send(f"🔍 Scanning {target_channel.mention} for downloadable files...", ephemeral=True)
        
        # Scan channel for file chunks (both regular and consolidated)
        chunks = {}
        file_info = {}
        consolidated_chunks = {}
        
        async for message in target_channel.history(limit=None):
            if message.attachments:
                for attachment in message.attachments:
                    filename = attachment.filename
                    
                    # Check for consolidated chunks first
                    if 'consolidated_chunk_' in filename:
                        try:
                            # Parse consolidated chunk filename
                            # Format: consolidated_chunk_X_of_Y[.consolidated][.sha256_HASH][.enc]
                            base_name = filename.split('.consolidated')[0]
                            remaining_parts = filename[len(base_name):]
                            
                            # Extract hash and encryption info
                            chunk_hash = None
                            is_encrypted = remaining_parts.endswith('.enc')
                            
                            if '.sha256_' in remaining_parts:
                                hash_parts = remaining_parts.split('.sha256_')
                                if len(hash_parts) > 1:
                                    hash_with_ext = hash_parts[1]
                                    if '.enc' in hash_with_ext:
                                        chunk_hash = hash_with_ext.split('.enc')[0]
                                    else:
                                        chunk_hash = hash_with_ext
                                    
                                    if len(chunk_hash) == 16:
                                        pass  # Valid hash
                                    else:
                                        chunk_hash = None
                            
                            # Parse consolidated chunk part number
                            part_match = re.search(r'consolidated_chunk_(\d+)_of_(\d+)', base_name)
                            if part_match:
                                part_num = int(part_match.group(1))
                                total_parts = int(part_match.group(2))
                                
                                consolidated_chunks[part_num] = {
                                    'url': attachment.url,
                                    'size': attachment.size,
                                    'message_id': message.id,
                                    'encrypted': is_encrypted,
                                    'total_parts': total_parts
                                }
                                
                                if chunk_hash:
                                    consolidated_chunks[part_num]['hash'] = chunk_hash
                                    
                        except Exception:
                            continue
                    
                    # Check if it matches regular chunk pattern 
                    elif '.part_' in filename and '_of_' in filename:
                        try:
                            # Extract encoded path and part info
                            base_name = filename.split('.part_')[0]
                            remaining_parts = filename.split('.part_')[1]
                            
                            # Extract hash and encryption info from filename
                            chunk_hash = None
                            is_encrypted = remaining_parts.endswith('.enc')
                            
                            if '.sha256_' in remaining_parts:
                                hash_parts = remaining_parts.split('.sha256_')
                                if len(hash_parts) > 1:
                                    # Extract hash, handling .enc extension
                                    hash_with_ext = hash_parts[1]
                                    if '.enc' in hash_with_ext:
                                        chunk_hash = hash_with_ext.split('.enc')[0]
                                    else:
                                        chunk_hash = hash_with_ext
                                    
                                    # Only use hash if it's the full 16 characters (not truncated)
                                    if len(chunk_hash) == 16:
                                        pass  # Hash is valid
                                    else:
                                        chunk_hash = None  # Truncated, skip verification
                                remaining_parts = hash_parts[0]
                            
                            # Parse part_X_of_Y
                            part_match = re.match(r'(\d+)_of_(\d+)', remaining_parts)
                            if not part_match:
                                continue
                                
                            part_num = int(part_match.group(1))
                            total_parts = int(part_match.group(2))
                            
                            # Decode the original path
                            try:
                                original_path = self.decode_path_from_filename(base_name)
                            except Exception:
                                original_path = base_name
                            
                            if original_path not in chunks:
                                chunks[original_path] = {}
                                file_info[original_path] = {'total_parts': total_parts, 'size': 0}
                            
                            chunk_info = {
                                'url': attachment.url,
                                'size': attachment.size,
                                'message_id': message.id,
                                'encrypted': is_encrypted
                            }
                            
                            if chunk_hash:
                                chunk_info['hash'] = chunk_hash
                            
                            chunks[original_path][part_num] = chunk_info
                            file_info[original_path]['size'] += attachment.size
                            
                        except Exception as e:
                            # Silent error handling for chunk parsing
                            continue
        
        # Process consolidated chunks to extract individual files
        if consolidated_chunks:
            await interaction.followup.send(f"🔍 Processing {len(consolidated_chunks)} consolidated chunks...", ephemeral=True)
            
            for part_num, chunk_info in consolidated_chunks.items():
                try:
                    # Download consolidated chunk
                    async with aiohttp.ClientSession() as session:
                        async with session.get(chunk_info['url']) as response:
                            if response.status == 200:
                                encrypted_chunk_data = await response.read()
                                
                                # Decrypt if needed
                                try:
                                    chunk_data = self._decrypt_data(encrypted_chunk_data)
                                except Exception as e:
                                    if self.encryption_enabled:
                                        await target_channel.send(f"🔒 Failed to decrypt consolidated chunk {part_num}: {e}")
                                        continue
                                    else:
                                        chunk_data = encrypted_chunk_data
                                
                                # Verify hash if available
                                if 'hash' in chunk_info and self.enable_hashing:
                                    calculated_hash = self._calculate_chunk_hash(chunk_data)
                                    if calculated_hash and calculated_hash[:16] != chunk_info['hash']:
                                        await target_channel.send(f"🔒 Hash mismatch for consolidated chunk {part_num}!")
                                        continue
                                
                                # Extract individual files from consolidated chunk
                                extracted_files = self._extract_files_from_consolidated_chunk(chunk_data)
                                
                                for file_data in extracted_files:
                                    file_path = file_data['path']
                                    
                                    if file_path not in chunks:
                                        chunks[file_path] = {}
                                        file_info[file_path] = {'total_parts': 1, 'size': file_data['size']}
                                    
                                    chunks[file_path][1] = {
                                        'consolidated_data': file_data['data'],
                                        'size': file_data['size'],
                                        'message_id': chunk_info['message_id']
                                    }
                except Exception as e:
                    await target_channel.send(f"❌ Error processing consolidated chunk {part_num}: {e}")
                    continue
        
        if not chunks and not consolidated_chunks:
            await interaction.followup.send("❌ No downloadable files found in this channel.", ephemeral=True)
            return
        
        # Display found files
        files_summary = []
        total_size = 0
        for file_path, info in file_info.items():
            found_parts = len(chunks[file_path])
            expected_parts = info['total_parts']
            size_mb = info['size'] / (1024 * 1024)
            total_size += info['size']
            status = "✅ Complete" if found_parts == expected_parts else f"⚠️ {found_parts}/{expected_parts} parts"
            files_summary.append(f"📄 `{file_path}` - {size_mb:.1f} MB - {status}")
        
        summary_text = f"🎯 Found {len(chunks)} files ({total_size / (1024 * 1024 * 1024):.2f} GB total):\n" + "\n".join(files_summary[:10])
        if len(files_summary) > 10:
            summary_text += f"\n... and {len(files_summary) - 10} more files"
        
        await target_channel.send(summary_text)
        
        # Load progress
        progress_data = self.load_progress("download", target_channel.id)
        completed_files = set(progress_data.get("completed_chunks", []))
        start_time = time.time() if not progress_data.get("start_time") else progress_data["start_time"]
        errors = progress_data.get("errors", [])
        downloaded_bytes = progress_data.get("uploaded_size_bytes", 0)  # Reuse same field name
        
        total_files = len(chunks)
        completed_count = len(completed_files)
        
        await target_channel.send(f"⬇️ Starting download... ({completed_count}/{total_files} files already completed)")
        
        # Download and reconstruct files
        for file_path, file_chunks in chunks.items():
            if file_path in completed_files:
                continue
                
            try:
                # Create directory structure
                output_path = Path(self.upload_dir) / file_path
                output_path.parent.mkdir(parents=True, exist_ok=True)
                
                # Check if we need to resume
                partial_path = output_path.with_suffix(output_path.suffix + '.partial')
                resume_part = 1
                if partial_path.exists():
                    # Calculate which part to resume from
                    existing_size = partial_path.stat().st_size
                    resume_part = (existing_size // self.max_chunk_size) + 1
                    await target_channel.send(f"🔄 Resuming `{file_path}` from part {resume_part}")
                
                total_parts = file_info[file_path]['total_parts']
                await target_channel.send(f"⬇️ Downloading `{file_path}` ({total_parts} parts)...")
                
                file_downloaded_bytes = 0
                
                # Download chunks in order (or use consolidated data)
                with open(partial_path, 'ab' if resume_part > 1 else 'wb') as output_file:
                    for part_num in range(resume_part, total_parts + 1):
                        if part_num not in file_chunks:
                            await target_channel.send(f"❌ Missing part {part_num} for `{file_path}`")
                            errors.append(f"{file_path}: missing part {part_num}")
                            break
                        
                        chunk_info = file_chunks[part_num]
                        
                        # Handle consolidated chunk data (already extracted)
                        if 'consolidated_data' in chunk_info:
                            chunk_data = chunk_info['consolidated_data']
                            output_file.write(chunk_data)
                            file_downloaded_bytes += len(chunk_data)
                            continue
                        
                        # Handle regular chunk data
                        retries = self.max_retry_attempts
                        
                        while retries > 0:
                            try:
                                async with aiohttp.ClientSession() as session:
                                    async with session.get(chunk_info['url']) as response:
                                        if response.status == 200:
                                            encrypted_chunk_data = await response.read()
                                            
                                            # Decrypt chunk if encryption is enabled
                                            try:
                                                chunk_data = self._decrypt_data(encrypted_chunk_data)
                                            except Exception as e:
                                                if self.encryption_enabled:
                                                    await target_channel.send(f"🔒 Decryption failed for part {part_num}: {e}")
                                                    retries = 0
                                                    break
                                                else:
                                                    chunk_data = encrypted_chunk_data
                                            
                                            # Verify hash if available (compare only truncated portion)
                                            if 'hash' in chunk_info and self.enable_hashing:
                                                calculated_hash = self._calculate_chunk_hash(chunk_data)
                                                if calculated_hash and calculated_hash[:16] != chunk_info['hash']:
                                                    await target_channel.send(f"🔒 Hash mismatch for part {part_num}! Expected: {chunk_info['hash']}..., Got: {calculated_hash[:16]}...")
                                                    retries -= 1
                                                    if retries > 0:
                                                        delay = self._get_retry_delay(self.max_retry_attempts - retries)
                                                        await asyncio.sleep(delay)
                                                        continue
                                                    else:
                                                        errors.append(f"{file_path}: hash verification failed for part {part_num}")
                                                        break
                                            
                                            output_file.write(chunk_data)
                                            file_downloaded_bytes += len(chunk_data)
                                            downloaded_bytes += len(chunk_data)
                                            break
                                        else:
                                            raise aiohttp.ClientError(f"HTTP {response.status}")
                            except Exception as e:
                                retries -= 1
                                if retries > 0:
                                    delay = self._get_retry_delay(self.max_retry_attempts - retries)
                                    await target_channel.send(f"⚠️ Error downloading part {part_num}, retrying in {delay}s... ({retries} left)")
                                    await asyncio.sleep(delay)
                                else:
                                    await target_channel.send(f"❌ Failed to download part {part_num}: {e}")
                                    errors.append(f"{file_path}: part {part_num} failed")
                                    break
                        
                        if retries == 0:
                            break
                        
                        # Progress update every 10 parts
                        if part_num % 10 == 0:
                            progress_pct = int((part_num / total_parts) * 100)
                            await target_channel.send(f"📊 `{file_path}`: {progress_pct}% ({part_num}/{total_parts})")
                        
                        await asyncio.sleep(0.5)  # Rate limiting
                
                # Move completed file to final location
                if partial_path.exists():
                    # Perform final integrity check if enabled
                    integrity_verified = True
                    if self.enable_hashing:
                        await target_channel.send(f"🔍 Verifying integrity of `{file_path}`...")
                        final_hash = self._calculate_file_hash(str(partial_path))
                        if final_hash:
                            await target_channel.send(f"🔒 Final SHA-256: {final_hash[:16]}...")
                        else:
                            await target_channel.send("⚠️ Could not calculate file hash for verification")
                            integrity_verified = False
                    
                    partial_path.rename(output_path)
                    completed_files.add(file_path)
                    completed_count += 1
                    
                    if integrity_verified:
                        await target_channel.send(f"✅ Completed `{file_path}` with integrity verification")
                    else:
                        await target_channel.send(f"⚠️ Completed `{file_path}` (integrity check failed)")
                    
                    # Update progress
                    overall_progress = int((downloaded_bytes / total_size) * 100) if total_size > 0 else 0
                    eta = self.get_eta(start_time, downloaded_bytes, total_size)
                    await self.bot.change_presence(activity=discord.Game(name=f"Downloading: {overall_progress}% ({eta} left)"))
                    
                    transfer_speed = self.get_transfer_speed(start_time, downloaded_bytes)
                    self.save_progress("download", target_channel.id, {
                        "completed_chunks": list(completed_files),
                        "total_size_bytes": total_size,
                        "uploaded_size_bytes": downloaded_bytes,
                        "start_time": start_time,
                        "errors": errors,
                        "integrity_verified": integrity_verified,
                        "transfer_speed_mbps": transfer_speed,
                        "formatted_speed": self.format_transfer_speed(transfer_speed)
                    })
                else:
                    await target_channel.send(f"❌ Failed to complete `{file_path}` - partial file missing")
                
            except Exception as e:
                await target_channel.send(f"💥 Error processing `{file_path}`: {e}")
                errors.append(f"{file_path}: {e}")
        
        # Final summary
        elapsed = int(time.time() - start_time)
        final_percentage = int((downloaded_bytes / total_size) * 100) if total_size > 0 else 100
        self.clear_progress("download", target_channel.id)
        
        await target_channel.send(
            f"🎉 **Download Complete!**\n"
            f"📁 Files downloaded to: `{self.upload_dir}/`\n"
            f"📊 Total size: {total_size / (1024*1024*1024):.2f} GB\n"
            f"📊 Downloaded: {downloaded_bytes / (1024*1024*1024):.2f} GB ({final_percentage}%)\n"
            f"📊 Total files: {total_files:,}\n"
            f"✅ Successful: {completed_count:,}\n"
            f"❌ Errors: {len(errors)}\n"
            f"⏱️ Time: {elapsed//60}m {elapsed%60}s\n"
            f"{'🔴 Failed files: ' + ', '.join(errors[:5]) + ('...' if len(errors) > 5 else '') if errors else '🟢 All files downloaded successfully!'}"
        )
        
        await self.bot.change_presence(activity=discord.Game(name="Idle"))

async def setup(bot):
    await bot.add_cog(FileSplitterCog(bot))
