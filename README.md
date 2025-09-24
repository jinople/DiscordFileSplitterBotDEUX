# DiscordFileSplitterBotDEUX

Personal experimental Discord bot + helper script that chops bigger files into smaller chunks and (eventually) can reassemble them later. Mostly just me messing around.

⚠️ Use at your own risk.  
Not endorsed by Discord. Don’t spam, don’t abuse, don’t treat this like a production “infinite storage” tool. It’s tinkering code, not a stealth platform.

## What It Does (Idea Stage → Partial)
- Splits a file into chunk-sized pieces under typical Discord upload limits.
- Tracks in-progress transfers (mechanism still evolving).
- Intended to reassemble original files from chunk messages.
- Command prefix list (comma-separated).
- Optional single-guild restriction (`GUILD_ID`) to keep scope tight.

## Components
| Component | Language | File(s) | Purpose |
|-----------|----------|---------|---------|
| Bot core | Python | `main.py` | Commands + chunk logic |
| Logging helper | Python | `log.py` | Basic logging |
| (Optional) Node helper | Node.js | `server.js` | Future UI / experimental API |
| Launch scripts | Shell / Batch | `start.sh`, `start.bat`, `start-electron.bat` | Convenience |
| Runtime progress (ignored) | JSON | `transfer_progress.json` (ignored now) | Ephemeral state |
| Example schema | JSON | `transfer_progress.example.json` | Shows structure |

## Requirements
- Python 3.10+
- Node 18+ (only if you actually use the Node side)
- Discord bot token
- Git + virtualenv basics

## Setup
```bash
cp .env.example .env
# edit .env
```

| Var | Meaning |
|-----|---------|
| TOKEN | Bot token (keep private) |
| PREFIX | Comma-separated prefixes (first is main) |
| GUILD_ID | (Optional) Limit bot to one guild |

## Install (Python)
```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt
```

## Install (Node – optional)
```bash
npm install
```

## Run
```bash
python main.py
# Optional helper:
node server.js
```

## Commands (Planned / Placeholder)
| Command | Intent |
|---------|--------|
| upload <file> | Split + send |
| retrieve <id> | Reassemble |
| status | Show progress |
| cancel <id> | Cancel a transfer (future) |

## Chunking (Fill Out As You Stabilize)
Document later:
- Chunk size chosen (e.g. ~8 MB with buffer)
- Naming convention
- How you map chunk → message → original file
- Integrity check (hash? size? both?)

## Progress Tracking
Real runtime state now ignored:
- `transfer_progress.json` is no longer tracked
- `transfer_progress.example.json` documents schema

## Dev Quality (Optional)
Python:
```bash
pip install black ruff
black .
ruff check .
```
Node (if you care later):
```bash
npm install --save-dev eslint prettier
```

## Roadmap (Loose Ideas)
- Actual resume support
- Slash commands
- Adjustable chunk size via env
- Optional encryption
- Simple web or TUI monitor
- Hash verification on reassembly

## Contributing
Super casual. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security-ish Stuff
- Don’t commit `.env`
- Rotate leaked tokens fast
- Keep intents minimal

## License
See [LICENSE](LICENSE)

## Final Vibe
Just experimenting. If you run it, you own the consequences. Have fun.
