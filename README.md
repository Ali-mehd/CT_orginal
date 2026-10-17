# ConfigTool

برنامه‌ی ویندوز برای پیدا کردن، تست و اتصال به کانفیگ‌های رایگان (vmess / vless / trojan / ss / hysteria2 / tuic / anytls).
کانفیگ‌ها از منابع عمومی GitHub و کانال‌های اضافه‌شده جمع می‌شن، از شبکه‌ی خود کاربر تست می‌شن و بهترین‌شون وصل می‌شه.

## ساختار
- `app/` هسته‌ی پایتون و رابط کاربری
  - `cfgweb.py` سرور محلی و منطق اصلی
  - `cfgscan.py` جمع‌آوری و تست کانفیگ‌ها
  - `cfgforge.py` و `report.py` ابزارهای کمکی و گزارش
  - `ui.html` رابط کاربری
- `launcher/` لانچر Go (پوسته‌ی exe). payload رو باز می‌کنه، هسته رو بی‌پنجره اجرا می‌کنه و پنجره‌ی WebView2 رو نشون می‌ده
- `scripts/build-windows.sh` ساخت کامل exe
- `.github/workflows/build-windows.yml` اجرای همین اسکریپت روی GitHub

## ساخت exe روی GitHub
1. توی ریپو برو تب **Actions**، workflow به اسم **build-windows** رو انتخاب کن و **Run workflow** بزن.
2. بعد از چند دقیقه فایل `ConfigTool.exe` (و فایل SHA-256 کنارش) توی بخش Artifacts همون اجرا هست.
3. برای انتشار رسمی یه تگ مثل `v1.0` بزن. workflow خودش exe رو توی Releases می‌ذاره.

## ساخت روی لینوکس
نیازها: `curl tar unzip zip python3 go(1.22)` و `binutils-mingw-w64-x86-64`، بعد `bash scripts/build-windows.sh`. خروجی توی `dist/` می‌ره.

## نکات
- پایتون قابل‌حمل، xray و sing-box با نسخه‌ی ثابت و چک SHA-256 دانلود می‌شن (نسخه‌ها بالای `scripts/build-windows.sh` هست).
- فهرست سیاه IP موقع ساخت از لیست‌های عمومی تولید می‌شه. اگه `app/snapshot.txt` (کانفیگ‌های آفلاین) کنار برنامه باشه توی exe هم جاسازی می‌شه.
- برنامه امضای دیجیتال نداره، پس SmartScreen یا آنتی‌ویروس ممکنه هشدار بدن.
- هر کانفیگ رایگان ذاتاً غیرقابل اعتماده و صاحب سرور مقصد، ترافیک رو می‌بینه.

## لایسنس
کد برنامه زیر MIT است. اجزای همراه (Python، xray، sing-box و کتابخانه‌های Go) لایسنس خودشون رو دارن؛ جزئیات توی `THIRD_PARTY_NOTICES.md`.
