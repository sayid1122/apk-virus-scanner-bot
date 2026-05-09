import asyncio
import os
from pathlib import Path

from aiogram import Bot, Dispatcher, F
from aiogram.enums import ParseMode
from aiogram.filters import CommandStart, Command
from aiogram.types import Message
from aiogram.client.default import DefaultBotProperties

from config import BOT_TOKEN, VT_API_KEY, MAX_FILE_MB, DOWNLOAD_DIR
from utils import sha256_file, safe_filename
from apk_static import analyze_apk_static
from vt_client import VirusTotalClient
from formatter import build_report_text


if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN .env faylda ko'rsatilmagan.")
if not VT_API_KEY:
    raise RuntimeError("VT_API_KEY .env faylda ko'rsatilmagan.")

Path(DOWNLOAD_DIR).mkdir(exist_ok=True)

bot = Bot(
    token=BOT_TOKEN,
    default=DefaultBotProperties(parse_mode=ParseMode.HTML)
)
dp = Dispatcher()
vt = VirusTotalClient(VT_API_KEY)


async def wait_virustotal_and_send(
    chat_id: int,
    file_name: str,
    file_hash: str,
    static_result: dict,
    analysis_id: str
):
    """
    VirusTotal natijasi tayyor bo'lguncha orqa fonda kutadi.
    Natija tayyor bo'lsa, foydalanuvchiga avtomatik hisobot yuboradi.
    """
    try:
        # 18 marta * 10 soniya = taxminan 3 daqiqa kutadi.
        analysis = await vt.wait_for_analysis(analysis_id, attempts=18, delay=10)

        if analysis:
            report_text = build_report_text(
                file_name=file_name,
                file_hash=file_hash,
                static_result=static_result,
                vt_analysis_report=analysis,
            )
            await bot.send_message(chat_id, report_text)
        else:
            await bot.send_message(
                chat_id,
                "⏳ VirusTotal skani hali tugamadi.\n\n"
                "Bu APK skan navbatida bo‘lishi mumkin. Bir ozdan keyin shu faylni qayta yuborsangiz, "
                "bot hash bo‘yicha tayyor natijani olib beradi."
            )

    except Exception as e:
        await bot.send_message(
            chat_id,
            "❌ VirusTotal natijasini kutish vaqtida xatolik yuz berdi.\n\n"
            f"<code>{str(e)[:800]}</code>"
        )


@dp.message(CommandStart())
async def start_handler(message: Message):
    await message.answer(
        "Assalomu alaykum!\n\n"
        "Menga <b>.apk</b> fayl yuboring. Men uni quyidagilar bo‘yicha tekshiraman:\n"
        "• VirusTotal bazasi va antivirus natijalari;\n"
        "• APK ruxsatlari;\n"
        "• DEX ichidagi shubhali belgilar;\n"
        "• umumiy xavf balli.\n\n"
        "Buyruq: /help"
    )


@dp.message(Command("help"))
async def help_handler(message: Message):
    await message.answer(
        "<b>Foydalanish tartibi:</b>\n"
        "Men IIV Akademiyasi 2-o'quv kursi kursatlari tomonidan yaratilgan botman.Oyxo'jayev S va Maxkamov Sh\n\n"
        "1. Botga .apk fayl yuboring.\n"
        "2. Bot faylni ishga tushirmasdan tahlil qiladi.\n"
        "3. Natijada xavf balli va tavsiyalar chiqadi.\n\n"
        "<b>Yangi imkoniyat:</b> agar VirusTotal natijasi darrov tayyor bo‘lmasa, "
        "bot o‘zi orqa fonda kutadi va natija tayyor bo‘lganda avtomatik xabar yuboradi.\n\n"
        "<b>Eslatma:</b> maxfiy yoki yopiq APK fayllarni VirusTotal’ga yuborishdan oldin ehtiyot bo‘ling, "
        "chunki public API orqali yuborilgan namunalar xavfsizlik hamjamiyati bilan ulashilishi mumkin."
    )


@dp.message(F.document)
async def apk_handler(message: Message):
    document = message.document
    file_name = document.file_name or "uploaded.apk"

    if not file_name.lower().endswith(".apk"):
        await message.answer("Iltimos, faqat <b>.apk</b> formatdagi fayl yuboring.")
        return

    size_mb = (document.file_size or 0) / (1024 * 1024)
    if size_mb > MAX_FILE_MB:
        await message.answer(
            f"Fayl hajmi juda katta: <b>{size_mb:.1f} MB</b>.\n"
            f"Ruxsat etilgan maksimal hajm: <b>{MAX_FILE_MB} MB</b>."
        )
        return

    progress_msg = await message.answer("✅ APK qabul qilindi. Yuklab olinmoqda...")

    safe_name = safe_filename(file_name)
    local_path = Path(DOWNLOAD_DIR) / f"{message.from_user.id}_{message.message_id}_{safe_name}"

    try:
        file_info = await bot.get_file(document.file_id)
        await bot.download_file(file_info.file_path, destination=local_path)

        await progress_msg.edit_text("🔎 SHA-256 hisoblanmoqda va lokal statik tahlil qilinmoqda...")
        file_hash = sha256_file(local_path)
        static_result = analyze_apk_static(str(local_path))

        await progress_msg.edit_text("🌐 VirusTotal bazasidan tekshirilmoqda...")
        vt_report = await vt.get_file_report(file_hash)

        if vt_report:
            report_text = build_report_text(
                file_name=file_name,
                file_hash=file_hash,
                static_result=static_result,
                vt_file_report=vt_report,
            )
            await progress_msg.edit_text(report_text)
            return

        await progress_msg.edit_text(
            "🌐 Bu APK VirusTotal bazasida topilmadi.\n"
            "Fayl VirusTotal’ga skan qilish uchun yuborilmoqda..."
        )

        uploaded = await vt.upload_file(str(local_path))
        analysis_id = uploaded["data"]["id"]

        # Avval qisqa kutib ko'ramiz: agar tez tugasa, darrov natijani chiqaramiz.
        await progress_msg.edit_text(
            "⏳ VirusTotal tahlili boshlandi. Natija tayyor bo‘lsa, hoziroq chiqaraman..."
        )

        quick_analysis = await vt.wait_for_analysis(analysis_id, attempts=3, delay=5)

        if quick_analysis:
            report_text = build_report_text(
                file_name=file_name,
                file_hash=file_hash,
                static_result=static_result,
                vt_analysis_report=quick_analysis,
            )
            await progress_msg.edit_text(report_text)
        else:
            # Lokal natijani darrov ko'rsatamiz.
            partial_text = build_report_text(
                file_name=file_name,
                file_hash=file_hash,
                static_result=static_result,
            )
            await progress_msg.edit_text(
                partial_text
                + "\n\n⏳ VirusTotal skani davom etmoqda.\n"
                "Natija tayyor bo‘lganda bot avtomatik ravishda shu chatga yuboradi."
            )

            # Orqa fonda 3 daqiqagacha kutadi va tayyor bo'lsa avtomatik yuboradi.
            asyncio.create_task(
                wait_virustotal_and_send(
                    chat_id=message.chat.id,
                    file_name=file_name,
                    file_hash=file_hash,
                    static_result=static_result,
                    analysis_id=analysis_id,
                )
            )

    except Exception as e:
        await progress_msg.edit_text(
            "❌ Tahlil vaqtida xatolik yuz berdi.\n\n"
            f"<code>{str(e)[:800]}</code>"
        )
    finally:
        try:
            if local_path.exists():
                os.remove(local_path)
        except Exception:
            pass


@dp.message()
async def fallback_handler(message: Message):
    await message.answer("Tekshirish uchun menga <b>.apk</b> fayl yuboring.")


async def main():
    print("APK Virus Scanner Bot ishga tushdi...")
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
