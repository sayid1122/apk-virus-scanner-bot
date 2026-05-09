# Telegram APK Virus Scanner Bot

Bu loyiha Telegram bot orqali `.apk` fayllarni xavfsiz tahlil qilish uchun tayyorlandi.

Bot quyidagilarni bajaradi:

- `.apk` faylni Telegram orqali qabul qiladi;
- faylni serverga yuklaydi;
- SHA-256 hash hisoblaydi;
- VirusTotal bazasidan hash bo‘yicha tekshiradi;
- agar VirusTotal bazasida bo‘lmasa, faylni skan qilish uchun yuboradi;
- Androguard orqali lokal statik APK tahlil qiladi;
- xavfli permissionlar va shubhali DEX belgilarni aniqlaydi;
- yakuniy xavf balli chiqaradi.

## Muhim xavfsizlik eslatmasi

Bot APK faylni ishga tushirmaydi. Faqat statik tahlil va VirusTotal API orqali tekshiradi.

Maxfiy, ichki yoki tijoriy APK fayllarni VirusTotal public API orqali yuborishda ehtiyot bo‘ling. Public API orqali yuborilgan fayllar xavfsizlik hamjamiyati bilan ulashilishi mumkin.

## 1. O‘rnatish

Python 3.10 yoki undan yuqori versiya tavsiya qilinadi.

```bash
pip install -r requirements.txt
```

## 2. Tokenlarni sozlash

`.env.example` faylidan nusxa oling:

```bash
copy .env.example .env
```

Linux/macOS:

```bash
cp .env.example .env
```

`.env` ichini to‘ldiring:

```env
BOT_TOKEN=Telegram_bot_tokeningiz
VT_API_KEY=VirusTotal_API_keyingiz
MAX_FILE_MB=50
```

Telegram tokenni BotFather orqali olasiz.

VirusTotal API keyni VirusTotal akkauntingizdan olasiz.

## 3. Botni ishga tushirish

```bash
python bot.py
```

Keyin Telegram’da botga `.apk` fayl yuboring.

## 4. Loyiha tuzilishi

```text
apk_virus_scanner_bot/
├─ bot.py              # Telegram bot asosiy fayli
├─ vt_client.py        # VirusTotal API bilan ishlash
├─ apk_static.py       # APK lokal statik tahlili
├─ formatter.py        # Natijani chiroyli formatlash
├─ utils.py            # Hash va yordamchi funksiyalar
├─ config.py           # .env sozlamalari
├─ requirements.txt    # Kutubxonalar
├─ .env.example        # Tokenlar namunasi
└─ README_UZ.md        # Qo‘llanma
```

## 5. Bot natijasi qanday chiqadi?

Bot quyidagi ma’lumotlarni chiqaradi:

- fayl nomi;
- package nomi;
- ilova nomi;
- versiya;
- SHA-256;
- lokal xavf balli;
- xavfli ruxsatlar;
- shubhali DEX belgilar;
- VirusTotal zararli/shubhali/xavfsiz statistikasi;
- umumiy xavf balli.

## 6. Kengaytirish g‘oyalari

Keyinchalik quyidagilarni qo‘shish mumkin:

- admin panel;
- SQLite yoki PostgreSQL bazaga natijalarni saqlash;
- foydalanuvchilar bo‘yicha limit;
- faqat adminlar uchun to‘liq hisobot;
- PDF hisobot;
- YARA qoidalari orqali qo‘shimcha lokal tekshiruv;
- karantin papkasi;
- Docker orqali serverga joylash.

## 7. Windows’da tez ishga tushirish

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
python bot.py
```

## 8. Linux serverda tez ishga tushirish

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
nano .env
python bot.py
```

Doimiy ishlatish uchun `systemd`, `pm2` yoki Docker ishlatish mumkin.
