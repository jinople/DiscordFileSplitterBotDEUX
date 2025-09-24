# Discord File Splitter Bot

A Discord bot that splits large files into smaller chunks for upload to Discord channels and can reassemble them later. This tool helps work around Discord's file size limitations while maintaining file integrity.

> ⚠️ **Important Notice**  
> This is experimental software. Use at your own risk and responsibility.  
> Not affiliated with or endorsed by Discord Inc. Please respect Discord's Terms of Service and don't abuse their platform.

## Features

- **File Splitting**: Automatically splits large files into chunks that fit Discord's upload limits (~8MB)
- **Folder Support**: Upload entire folder structures while preserving directory layout
- **Resume Capability**: Pause and resume transfers with progress tracking
- **Integrity Verification**: Hash verification to ensure file completeness during reassembly
- **Slash Commands**: Modern Discord slash command interface
- **Progress Monitoring**: Real-time upload/download progress with ETA calculations

## Architecture

| Component | Technology | File(s) | Purpose |
|-----------|-----------|---------|---------|
| Bot Core | Python 3.10+ | `main.py` | Discord bot with slash commands |
| File Handler | Python | `cogs/filesplitter.py` | File chunking and reassembly logic |
| Logger | Python | `log.py` | Centralized logging system |
| Optional Web UI | Node.js | `server.js` | Experimental web interface |
| Launch Scripts | Shell/Batch | `start.*` | Convenience startup scripts |

## Requirements

- **Python 3.10+** with pip
- **Node.js 18+** (optional, for web interface only)
- **Discord Bot Token** with appropriate permissions
- **Git** for repository management

## Quick Start

### 1. Environment Setup

```bash
# Clone the repository
git clone https://github.com/jinople/DiscordFileSplitterBotDEUX.git
cd DiscordFileSplitterBotDEUX

# Copy environment template
cp .env.example .env
```

### 2. Configure Environment Variables

Edit `.env` with your Discord bot configuration:

| Variable | Description | Example |
|----------|-------------|---------|
| `TOKEN` | Discord bot token (keep private!) | `"your_bot_token_here"` |
| `PREFIX` | Command prefixes (comma-separated) | `". ,"` |
| `GUILD_ID` | (Optional) Restrict bot to specific server | `"123456789012345678"` |

### 3. Python Installation

```bash
# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Linux/macOS:
source .venv/bin/activate
# Windows:
.venv\Scripts\activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Optional: Node.js Setup

```bash
npm install
```

### 5. Run the Bot

```bash
python main.py

# Optional: Start web interface
node server.js
```

## Usage

The bot provides the following slash commands:

| Command | Description |
|---------|-------------|
| `/upload <file_path>` | Upload a file or folder, splitting it into chunks |
| `/download [channel]` | Download and reassemble files from a channel |

### Example Workflow

1. **Upload a file**: `/upload /path/to/large-file.zip`
   - Bot creates a dedicated channel for the upload
   - File is split into ~8MB chunks and uploaded
   - Progress is tracked and displayed

2. **Download/Reassemble**: `/download`
   - Bot scans the channel for file chunks
   - Downloads and reassembles the original file(s)
   - Verifies file integrity

## File Chunking Details

- **Chunk Size**: ~8MB per chunk (configurable)
- **Naming Convention**: Encoded filenames with chunk indices
- **Integrity**: SHA256 hash verification on reassembly
- **Progress Tracking**: JSON-based transfer state management

## Development

### Code Quality Tools

**Python**:
```bash
pip install black ruff
black .           # Format code
ruff check .      # Lint code
```

**Node.js** (optional):
```bash
npm install --save-dev eslint prettier
```

### Project Structure

```
├── main.py                 # Bot entry point
├── log.py                  # Logging configuration  
├── cogs/
│   └── filesplitter.py     # Main bot functionality
├── server.js               # Optional web interface
├── .env.example            # Environment template
└── requirements.txt        # Python dependencies
```

## Security Considerations

- **Never commit `.env`** - Contains sensitive bot token
- **Rotate tokens immediately** if accidentally exposed
- **Use minimal Discord permissions** required for functionality
- **Monitor bot usage** to prevent abuse

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Follow existing code style
4. Test your changes
5. Submit a pull request

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Roadmap

- [ ] Enhanced resume capabilities
- [ ] Configurable chunk sizes via environment variables  
- [ ] Optional file encryption
- [ ] Web/TUI monitoring interface
- [ ] Improved error handling and recovery
- [ ] Support for additional file integrity checks