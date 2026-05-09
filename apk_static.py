import re
import zipfile
from pathlib import Path

# Yuqori xavfli Android permissionlar.
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS": 15,
    "android.permission.SEND_SMS": 20,
    "android.permission.RECEIVE_SMS": 15,
    "android.permission.READ_CONTACTS": 10,
    "android.permission.WRITE_CONTACTS": 10,
    "android.permission.RECORD_AUDIO": 12,
    "android.permission.CAMERA": 8,
    "android.permission.ACCESS_FINE_LOCATION": 10,
    "android.permission.ACCESS_COARSE_LOCATION": 6,
    "android.permission.READ_CALL_LOG": 15,
    "android.permission.WRITE_CALL_LOG": 15,
    "android.permission.CALL_PHONE": 10,
    "android.permission.READ_PHONE_STATE": 8,
    "android.permission.SYSTEM_ALERT_WINDOW": 15,
    "android.permission.REQUEST_INSTALL_PACKAGES": 18,
    "android.permission.BIND_ACCESSIBILITY_SERVICE": 25,
    "android.permission.QUERY_ALL_PACKAGES": 8,
    "android.permission.FOREGROUND_SERVICE": 4,
    "android.permission.POST_NOTIFICATIONS": 2,
}

# DEX ichidan qidiriladigan shubhali belgilar.
SUSPICIOUS_PATTERNS = {
    "DexClassLoader": 15,
    "PathClassLoader": 8,
    "Runtime.getRuntime": 12,
    "ProcessBuilder": 10,
    "su": 10,
    "chmod": 8,
    "keylogger": 25,
    "AccessibilityService": 20,
    "android.provider.Telephony": 12,
    "content://sms": 20,
    "getDeviceId": 10,
    "getSubscriberId": 10,
    "getLine1Number": 10,
    "sendTextMessage": 20,
    "HttpURLConnection": 5,
    "Base64": 4,
    "loadLibrary": 6,
    "dalvik.system": 10,
}


def _load_apk_object(apk_path: str):
    """
    Androguard versiyalari bo'yicha import yo'li farq qilishi mumkin.
    Shuning uchun ikkita yo'lni sinab ko'ramiz.
    """
    try:
        from androguard.core.apk import APK
        return APK(apk_path)
    except Exception:
        from androguard.core.bytecodes.apk import APK
        return APK(apk_path)


def extract_dex_strings(apk_path: str, max_bytes_per_dex: int = 8_000_000) -> str:
    """
    APK ichidagi classes*.dex fayllardan ASCII/UTF-8 ko'rinadigan satrlarni ajratadi.
    APK ishga tushirilmaydi, faqat arxiv sifatida o'qiladi.
    """
    combined = []
    with zipfile.ZipFile(apk_path, "r") as z:
        for name in z.namelist():
            if name.startswith("classes") and name.endswith(".dex"):
                data = z.read(name)[:max_bytes_per_dex]
                # Kamida 4 belgili printable satrlar.
                found = re.findall(rb"[\x20-\x7E]{4,}", data)
                combined.extend(s.decode("utf-8", errors="ignore") for s in found[:5000])
    return "\n".join(combined)


def analyze_apk_static(apk_path: str) -> dict:
    result = {
        "package": None,
        "app_name": None,
        "version_name": None,
        "min_sdk": None,
        "target_sdk": None,
        "permissions": [],
        "dangerous_permissions": [],
        "suspicious_patterns": [],
        "score": 0,
        "errors": [],
    }

    try:
        apk = _load_apk_object(apk_path)

        result["package"] = apk.get_package()
        result["app_name"] = apk.get_app_name()
        result["version_name"] = apk.get_androidversion_name()
        result["min_sdk"] = apk.get_min_sdk_version()
        result["target_sdk"] = apk.get_target_sdk_version()

        permissions = list(apk.get_permissions() or [])
        result["permissions"] = permissions

        score = 0
        for perm in permissions:
            if perm in DANGEROUS_PERMISSIONS:
                points = DANGEROUS_PERMISSIONS[perm]
                score += points
                result["dangerous_permissions"].append({
                    "permission": perm,
                    "points": points
                })

        try:
            dex_text = extract_dex_strings(apk_path)
            for pattern, points in SUSPICIOUS_PATTERNS.items():
                if pattern in dex_text:
                    score += points
                    result["suspicious_patterns"].append({
                        "pattern": pattern,
                        "points": points
                    })
        except Exception as e:
            result["errors"].append(f"DEX satrlarini o'qishda xatolik: {e}")

        result["score"] = min(score, 100)
        return result

    except Exception as e:
        result["errors"].append(f"APK statik tahlilida xatolik: {e}")
        return result


def static_risk_label(score: int) -> str:
    if score >= 70:
        return "🔴 JUDA YUQORI XAVF"
    if score >= 45:
        return "🟠 YUQORI XAVF"
    if score >= 20:
        return "🟡 O‘RTA XAVF"
    return "🟢 PAST XAVF"
