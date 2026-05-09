from apk_static import static_risk_label
from vt_client import vt_score_from_stats, vt_label


def final_label(total_score: int, vt_stats: dict | None) -> str:
    malicious = int((vt_stats or {}).get("malicious", 0))
    suspicious = int((vt_stats or {}).get("suspicious", 0))

    if malicious >= 5 or total_score >= 75:
        return "🔴 UMUMIY XULOSA: APK XAVFLI"
    if malicious >= 1 or suspicious >= 2 or total_score >= 45:
        return "🟠 UMUMIY XULOSA: APK SHUBHALI"
    if total_score >= 20:
        return "🟡 UMUMIY XULOSA: EHTIYOTKORLIK TALAB QILINADI"
    return "🟢 UMUMIY XULOSA: JIDDIY XAVF ANIQLANMADI"


def fmt_list(items, limit=8):
    if not items:
        return "—"
    sliced = items[:limit]
    text = "\n".join(f"• {x}" for x in sliced)
    if len(items) > limit:
        text += f"\n• ... yana {len(items) - limit} ta"
    return text


def build_report_text(
    file_name: str,
    file_hash: str,
    static_result: dict,
    vt_file_report: dict | None = None,
    vt_analysis_report: dict | None = None,
) -> str:
    vt_stats = None

    if vt_file_report:
        vt_stats = vt_file_report["data"]["attributes"].get("last_analysis_stats", {})
    elif vt_analysis_report:
        vt_stats = vt_analysis_report["data"]["attributes"].get("stats", {})

    static_score = int(static_result.get("score", 0))
    vt_score = vt_score_from_stats(vt_stats) if vt_stats else 0
    total_score = min(100, int(static_score * 0.45 + vt_score * 0.55))

    dangerous_permissions = [
        f'{x["permission"].replace("android.permission.", "")} (+{x["points"]})'
        for x in static_result.get("dangerous_permissions", [])
    ]

    suspicious_patterns = [
        f'{x["pattern"]} (+{x["points"]})'
        for x in static_result.get("suspicious_patterns", [])
    ]

    vt_block = "VirusTotal natijasi hali mavjud emas."
    if vt_stats:
        vt_block = (
            f'{vt_label(vt_stats)}\n'
            f'🔴 Zararli: {vt_stats.get("malicious", 0)}\n'
            f'🟠 Shubhali: {vt_stats.get("suspicious", 0)}\n'
            f'🟢 Xavfsiz: {vt_stats.get("harmless", 0)}\n'
            f'⚪ Aniqlanmadi: {vt_stats.get("undetected", 0)}'
        )

    errors = static_result.get("errors") or []
    errors_text = ""
    if errors:
        errors_text = "\n\n⚠️ Texnik izoh:\n" + "\n".join(f"• {e}" for e in errors[:3])

    return f"""
🛡 <b>APK VIRUS TAHLIL NATIJASI</b>

📄 <b>Fayl:</b> {file_name}
📦 <b>Package:</b> {static_result.get("package") or "aniqlanmadi"}
🏷 <b>Ilova nomi:</b> {static_result.get("app_name") or "aniqlanmadi"}
🔢 <b>Versiya:</b> {static_result.get("version_name") or "aniqlanmadi"}

🔐 <b>SHA-256:</b>
<code>{file_hash}</code>

<b>1) Lokal statik tahlil</b>
{static_risk_label(static_score)}
📊 Lokal xavf balli: <b>{static_score}/100</b>

<b>Xavfli ruxsatlar:</b>
{fmt_list(dangerous_permissions)}

<b>Shubhali DEX belgilar:</b>
{fmt_list(suspicious_patterns)}

<b>2) VirusTotal tahlili</b>
{vt_block}

<b>3) Yakuniy baho</b>
{final_label(total_score, vt_stats)}
📊 Umumiy xavf balli: <b>{total_score}/100</b>

⚠️ <b>Eslatma:</b> bu tahlil APK faylni ishga tushirmaydi. Natija 100% kafolat emas, lekin zararli APKlarni saralash uchun amaliy yordam beradi.
{errors_text}
""".strip()
