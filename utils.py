import hashlib
from pathlib import Path


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_filename(name: str) -> str:
    blocked = '<>:"/\\|?*\0'
    cleaned = "".join("_" if c in blocked else c for c in name)
    return cleaned[:180] or "uploaded.apk"
