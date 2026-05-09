import os
from dotenv import load_dotenv

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
VT_API_KEY = os.getenv("VT_API_KEY", "").strip()
MAX_FILE_MB = int(os.getenv("MAX_FILE_MB", "50"))

DOWNLOAD_DIR = "downloads"
