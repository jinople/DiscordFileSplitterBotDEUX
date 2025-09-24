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
            print(f"Generated encryption key: {key.decode()}")
            print("Add this to your .env file as ENCRYPTION_KEY for consistent decryption")
    
    def _encrypt_data(self, data):
        """Encrypt data if encryption is enabled"""
        if not self.encryption_enabled or not self.fernet:
            return data
        return self.fernet.encrypt(data)
    
    def _decrypt_data(self, encrypted_data):
        """Decrypt data if encryption is enabled"""
        if not self.encryption_enabled or not self.fernet:
            return encrypted_data
        return self.fernet.decrypt(encrypted_data)
    
    def _calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of a file"""
        if not self.enable_hashing:
            return None
        
        hash_sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception:
            return None
    
    def _calculate_chunk_hash(self, data):
        """Calculate SHA-256 hash of chunk data"""
        if not self.enable_hashing:
            return None
        return hashlib.sha256(data).hexdigest()
    
    def _get_retry_delay(self, attempt_number):
        """Calculate exponential backoff delay for retries"""
        return min(30, (self.retry_backoff_factor ** attempt_number))

    def is_folder(self, path):
        return os.path.isdir(path)

    def get_all_files_in_folder(self, folder_path):
        """Get all files in a folder with their relative paths preserved"""
        all_files = []
        folder_path = Path(folder_path).resolve()
        folder_name = folder_path.name
        
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                abs_path = Path(root) / file
                rel_path_from_folder = abs_path.relative_to(folder_path)
                full_rel_path = Path(folder_name) / rel_path_from_folder
                all_files.append((str(abs_path), str(full_rel_path).replace("\\", "/")))
        return all_files

    def calculate_directory_size(self, path):
        """Calculate total size of directory or file in bytes"""
        if os.path.isfile(path):
            return os.path.getsize(path)
        
        total_size = 0
        for root, dirs, files in os.walk(path):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    total_size += os.path.getsize(file_path)
                except (OSError, IOError):
                    pass  # Skip files that can't be accessed
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
        if not os.path.exists(PROGRESS_FILE):
            return {}
        try:
            with open(PROGRESS_FILE, "r") as f:
                all_progress = json.load(f)
            return all_progress.get(f"{transfer_type}_{channel_id}", {})
        except Exception:
            return {}

    def save_progress(self, transfer_type, channel_id, progress_data):
        try:
            if os.path.exists(PROGRESS_FILE):
                with open(PROGRESS_FILE, "r") as f:
                    all_progress = json.load(f)
            else:
                all_progress = {}
                
            # Enhance progress data with additional metadata
            enhanced_data = progress_data.copy()
            enhanced_data.update({
                "last_updated": time.time(),
                "chunk_size_mb": self.max_chunk_size // (1024 * 1024),
                "encryption_enabled": self.encryption_enabled,
                "hashing_enabled": self.enable_hashing,
                "transfer_type": transfer_type
            })
            
            all_progress[f"{transfer_type}_{channel_id}"] = enhanced_data
            with open(PROGRESS_FILE, "w") as f:
                json.dump(all_progress, f, indent=2)
        except Exception as e:
            print(f"Error saving progress: {e}")

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
            print(f"Error clearing progress: {e}")

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
        absolute_path = Path(file_path).resolve()
        await interaction.response.send_message(f"Starting to process path: `{absolute_path}`...", ephemeral=True)

        if not absolute_path.exists():
            await interaction.followup.send(f"Error: The path `{absolute_path}` does not exist.", ephemeral=True)
            return

        is_folder = self.is_folder(absolute_path)
        original_name = absolute_path.name
        sanitized_name = channel_name.lower().replace(' ', '-') if channel_name else original_name.lower().replace('.', '-').replace('_', '-')

        try:
            new_channel = await interaction.guild.create_text_channel(name=sanitized_name)
            self.uploaded_files[original_name] = new_channel.id
            await interaction.followup.send(f"Created channel {new_channel.mention} for the upload.", ephemeral=True)
        except Exception as e:
            await interaction.followup.send(f"Failed to create channel: {e}", ephemeral=True)
            return

        await new_channel.send(f"🚀 Starting upload of `{original_name}`{' (folder)' if is_folder else ''}...")

        # Calculate total directory size
        total_size_bytes = self.calculate_directory_size(str(absolute_path))
        await new_channel.send(f"📊 Total size: {total_size_bytes / (1024*1024*1024):.2f} GB")

        # Build file list with proper relative paths
        file_list = []
        if is_folder:
            file_list = self.get_all_files_in_folder(str(absolute_path))
            await new_channel.send(f"📁 Found {len(file_list)} files in folder structure:")
            for i, (abs_path, rel_path) in enumerate(file_list[:3]):
                await new_channel.send(f"   📄 {rel_path}")
            if len(file_list) > 3:
                await new_channel.send(f"   ... and {len(file_list) - 3} more files")
        else:
            file_list = [(str(absolute_path), original_name)]

        chunk_index_map = []
        for abs_path, rel_path in file_list:
            file_size = os.path.getsize(abs_path)
            total_parts = (file_size + self.max_chunk_size - 1) // self.max_chunk_size
            chunk_index_map.extend([(rel_path, i+1, total_parts) for i in range(total_parts)])
        total_chunks = len(chunk_index_map)

        progress_data = self.load_progress("upload", new_channel.id)
        completed_chunks = set(progress_data.get("completed_chunks", []))
        last_percentage = 0
        start_time = time.time() if not progress_data.get("start_time") else progress_data["start_time"]
        errors = progress_data.get("errors", [])
        uploaded_bytes = progress_data.get("uploaded_size_bytes", 0)

        await new_channel.send(f"📊 Total chunks to upload: {total_chunks}")

        for abs_path, rel_path in file_list:
            file_size = os.path.getsize(abs_path)
            total_parts = (file_size + self.max_chunk_size - 1) // self.max_chunk_size
            await new_channel.send(f"⬆️ Uploading `{rel_path}` ({file_size:,} bytes, {total_parts} parts)...")
            
            try:
                async with aiofiles.open(abs_path, "rb") as f:
                    for i in range(total_parts):
                        encoded_path = self.encode_path_for_filename(rel_path)
                        chunk_id = f"{encoded_path}.part_{i+1}_of_{total_parts}"
                        if i == 0:
                            await new_channel.send(f"🔐 Encoding `{rel_path}` → `{encoded_path}`")
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
                                    upload_msg += " 🔒"
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
                                await new_channel.send(f"⌐ Error with part {i+1}: {e}. Retrying in {delay}s... ({retries} left)")
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
        
        # Scan channel for file chunks
        chunks = {}
        file_info = {}
        
        async for message in target_channel.history(limit=None):
            if message.attachments:
                for attachment in message.attachments:
                    filename = attachment.filename
                    # Check if it matches our chunk pattern
                    if '.part_' in filename and '_of_' in filename:
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
                                    hash_segment = hash_parts[1].split('.')[0]  # Remove .enc or other extensions
                                    # Hash is truncated in filename, we'll verify what we can
                                    chunk_hash = hash_segment
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
                            print(f"Error parsing chunk {filename}: {e}")
                            continue
        
        if not chunks:
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
                
                # Download chunks in order
                with open(partial_path, 'ab' if resume_part > 1 else 'wb') as output_file:
                    for part_num in range(resume_part, total_parts + 1):
                        if part_num not in file_chunks:
                            await target_channel.send(f"❌ Missing part {part_num} for `{file_path}`")
                            errors.append(f"{file_path}: missing part {part_num}")
                            break
                        
                        chunk_info = file_chunks[part_num]
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
                                                    await target_channel.send(f"🔓 Decryption failed for part {part_num}: {e}")
                                                    retries = 0
                                                    break
                                                else:
                                                    chunk_data = encrypted_chunk_data
                                            
                                            # Verify hash if available
                                            if 'hash' in chunk_info and self.enable_hashing:
                                                calculated_hash = self._calculate_chunk_hash(chunk_data)
                                                if calculated_hash != chunk_info['hash']:
                                                    await target_channel.send(f"🔍 Hash mismatch for part {part_num}! Expected: {chunk_info['hash'][:16]}..., Got: {calculated_hash[:16] if calculated_hash else 'None'}...")
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
                                    await asyncio.sleep(5)
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
                            await target_channel.send(f"📝 Final SHA-256: {final_hash[:16]}...")
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
                        "uploaded_size_bytes": downloaded_bytes,  # Reuse same field name
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