import asyncio
import aiohttp
from pathlib import Path


class VirusTotalClient:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {"x-apikey": api_key}
        self.base_url = "https://www.virustotal.com/api/v3"

    async def get_file_report(self, file_hash: str) -> dict | None:
        url = f"{self.base_url}/files/{file_hash}"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=self.headers) as resp:
                if resp.status == 200:
                    return await resp.json()
                if resp.status == 404:
                    return None
                text = await resp.text()
                raise RuntimeError(f"VirusTotal report xatosi: HTTP {resp.status} - {text[:300]}")

    async def upload_file(self, file_path: str) -> dict:
        path = Path(file_path)
        # VirusTotal public API: oddiy /files endpoint 32 MB gacha.
        # 32 MB dan katta fayl uchun upload_url olinadi.
        upload_url = f"{self.base_url}/files"
        if path.stat().st_size > 32 * 1024 * 1024:
            upload_url = await self.get_large_upload_url()

        form = aiohttp.FormData()
        with open(path, "rb") as f:
            form.add_field(
                "file",
                f,
                filename=path.name,
                content_type="application/vnd.android.package-archive"
            )

            async with aiohttp.ClientSession() as session:
                async with session.post(upload_url, headers=self.headers, data=form) as resp:
                    data = await resp.json(content_type=None)
                    if resp.status not in (200, 201):
                        raise RuntimeError(f"VirusTotal upload xatosi: HTTP {resp.status} - {data}")
                    return data

    async def get_large_upload_url(self) -> str:
        url = f"{self.base_url}/files/upload_url"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=self.headers) as resp:
                data = await resp.json(content_type=None)
                if resp.status != 200:
                    raise RuntimeError(f"Upload URL olishda xatolik: HTTP {resp.status} - {data}")
                return data["data"]

    async def get_analysis(self, analysis_id: str) -> dict:
        url = f"{self.base_url}/analyses/{analysis_id}"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=self.headers) as resp:
                data = await resp.json(content_type=None)
                if resp.status != 200:
                    raise RuntimeError(f"Analysis olishda xatolik: HTTP {resp.status} - {data}")
                return data

    async def wait_for_analysis(self, analysis_id: str, attempts: int = 12, delay: int = 10) -> dict | None:
        for _ in range(attempts):
            data = await self.get_analysis(analysis_id)
            status = data.get("data", {}).get("attributes", {}).get("status")
            if status == "completed":
                return data
            await asyncio.sleep(delay)
        return None


def vt_score_from_stats(stats: dict) -> int:
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    # Ko'p antiviruslar aniqlasa xavf balli tez oshadi.
    return min(100, malicious * 12 + suspicious * 6)


def vt_label(stats: dict) -> str:
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))

    if malicious >= 5:
        return "🔴 VIRUSTOTAL: XAVFLI"
    if malicious >= 1 or suspicious >= 2:
        return "🟠 VIRUSTOTAL: SHUBHALI"
    if suspicious == 1:
        return "🟡 VIRUSTOTAL: EHTIYOT BO‘LING"
    return "🟢 VIRUSTOTAL: JIDDIY XAVF ANIQLANMADI"
