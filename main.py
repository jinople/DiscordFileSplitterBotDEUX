import discord
from discord.ext import commands
import asyncio
import os
from dotenv import load_dotenv
from log import logger
import signal
import argparse

# Load .env
load_dotenv()
TOKEN = os.getenv("TOKEN")
GUILD_ID = os.getenv("GUILD_ID")
PREFIX = os.getenv("PREFIX", ".").split(" ")

# Set up argument parsing
parser = argparse.ArgumentParser(description="FileBot for Discord")
parser.add_argument("--useragent", type=str, help="Specify the user agent")
parser.add_argument("--loglevel", type=str, choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], help="Set the logging level")
args = parser.parse_args()

# Configure logging level based on argument
if args.loglevel:
    logger.setLevel(args.loglevel)

async def load_cogs(bot, directory="cogs"):
    tasks = []
    for filename in os.listdir(directory):
        if filename.endswith(".py") and not filename.startswith("_"):
            ext = f"{directory}.{filename[:-3]}"
            task = asyncio.create_task(bot.load_extension(ext))
            task.ext = ext
            tasks.append(task)
            logger.info(f"Prepared to load {ext}")

    for task in tasks:
        try:
            await task
            logger.info(f"Successfully loaded {task.ext}")
        except Exception as e:
            logger.error(f"Failed to load {ext}", exc_info=e)

class FileBot(commands.Bot):
    def __init__(self):
        intents = discord.Intents.default()
        intents.message_content = True

        super().__init__(command_prefix=PREFIX, intents=intents)
        self.logger = logger
        self.timeout = 10.0
        self.config = {}

    async def setup_hook(self):
        await load_cogs(self)
        logger.info("Cogs loaded, bot is ready")

    async def on_ready(self):
        logger.info(f"Logged in as {self.user} (ID: {self.user.id})")
        logger.info("------")
        await self.change_presence(status=discord.Status.idle)
        guild = discord.Object(id=GUILD_ID)
        self.tree.copy_global_to(guild=guild)
        await self.tree.sync(guild=guild)
        logger.info("Slash commands synced to guild.")
        
    def get_config(self, key, default=None):
        if not hasattr(self, 'config'):
            self.logger.warning(f"Config not available, using default for {key}")
            return default
        
        config_entry = self.config.get(key, None)
        return default if config_entry is None else config_entry
    
    @commands.command()
    async def sync(self, ctx):
        await ctx.send("Syncing commands...", ephemeral=True)
        await self.tree.sync()
        await ctx.send("Commands synced!", ephemeral=True)

    def get_config(self, key, default=None):
        if not hasattr(self, 'config'):
            self.logger.warning(f"Config not available, using default for {key}")
            return default
        
        config_entry = self.config.get(key, None)
        return default if config_entry is None else config_entry

async def shutdown_bot():
    if bot:
        logger.info("Unloading all cogs")
        try:
            await asyncio.gather(*(bot.unload_extension(ext) for ext in list(bot.extensions)))
        except Exception as e:
            logger.error("Error unloading cogs during shutdown", exc_info=e)

        logger.info("Closing bot connection...")
        await bot.close()

def handle_exit(sig, frame):
    logger.info(f"Received signal {sig}, shutting down gracefully...")
    loop = asyncio.get_event_loop()
    loop.create_task(shutdown_bot())

async def main():
    global bot
    if not TOKEN:
        raise RuntimeError("DISCORD_TOKEN not found in .env file")

    bot = FileBot()
    if getattr(args, "useragent", None):
        bot.http.super_properties["browser_user_agent"] = args.useragent   
    async with bot:
        max_retries = 5
        retry_count = 0
        backoff_time = 5

        while retry_count < max_retries:
            try:
                await bot.start(TOKEN)
                break
            except discord.errors.ConnectionClosed as e:
                retry_count += 1
                logger.error(f"Connection closed. Retrying ({retry_count}/{max_retries}) in {backoff_time}s: {e}")
                if retry_count < max_retries:
                    await asyncio.sleep(backoff_time)
                    backoff_time *= 2
                else:
                    logger.critical("Maximum retries reached. Shutting down.")
            except discord.errors.HTTPException as e:
                if hasattr(e, "retry_after"):
                    retry_after = getattr(e, "retry_after", 5)
                    logger.warning(f"Rate limited. Retrying in {retry_after}s")
                    await asyncio.sleep(retry_after)
                else:
                    logger.error(f"HTTP Error: {e}")
                    break
            except Exception as e:
                logger.error("Unexpected exception during bot start", exc_info=e)
                break

if __name__ == "__main__":
    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)
    asyncio.run(main())