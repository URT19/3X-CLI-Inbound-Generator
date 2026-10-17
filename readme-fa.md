# راهنمای سریع ۳X CLI Inbound Generator (فارسی)

اسکریپت ترمینالی برای ساخت خودکار اینباند روی پنل سنایی (3x-ui نسخه 3.9.0 به بعد). فقط Python استاندارد لازم دارد.

> در همه مثال‌ها `example.com` و `203.0.113.10` نمونه‌اند؛ مقدار خودتان را بگذارید.

---

## ۱) سرور خام: نصب پیش‌نیازها

```bash
sudo apt update && sudo apt install -y python3 openssl curl unzip wget
```

## ۲) نصب پنل سنایی (اگر هنوز نصب نیست)

```bash
bash <(curl -Ls https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh)
```

آدرس، پورت و مسیر (WebBasePath) پنل در پایان نصب چاپ می‌شود. نمونه:
`https://203.0.113.10:2053/abcd1234/`

## ۳) دانلود و اجرای اسکریپت

```bash
cd ~
wget https://github.com/URT19/3X-CLI-Inbound-Generator/releases/download/v1.33.0/3X-CLI-Inbound-Generator-1.33.0.zip
unzip 3X-CLI-Inbound-Generator-1.33.0.zip
cd 3X-CLI-Inbound-Generator-*
python3 main.py
```

---

## ۴) اتصال پنل سنایی به اسکریپت (API Token)

**الف) ساخت توکن در پنل**

1. وارد پنل شوید.
2. **Settings** ← تب **Security** ← بخش **API Tokens** ← دکمه **New token**.
3. یک نام بدهید (مثلاً `inbound-gen`) و بسازید.
4. توکن را **همان لحظه کپی کنید**؛ دوباره نشان داده نمی‌شود.

**ب) وارد کردن در اسکریپت**

منوی اصلی ← `2` (Panel connection) ← `2` (Edit address and token):

```
Panel address [none]: https://203.0.113.10:2053/abcd1234
API token (blank keeps the current one): ********
```

اگر اسکریپت روی همان سرور پنل اجرا می‌شود، آدرس لوکال هم کار می‌کند:
`127.0.0.1:2053/abcd1234`

**ج) تست اتصال**

منوی `2` ← `1` (Check connection). باید این پیام را ببینید:

```
Connection OK: the panel reports N inbounds.
```

> توکن در `config/settings.json` ذخیره می‌شود؛ آن را جایی منتشر نکنید.

---

## ۵) تنظیمات شبکه (یک‌بار)

منوی `3` (Network settings):

| گزینه | کاربرد | مثال |
|---|---|---|
| `3` | IP مستقیم سرور | `203.0.113.10` |
| `4` | دامنه مستقیم (بدون CDN) | `direct.example.com` |
| `5` | دامنه CDN (پشت کلودفلر) | `cdn.example.com` |
| `2` | IPهای کلودفلر (برای حالت IP) | |

## ۶) گواهی SSL

منوی `5` ← `1`: دامنه را بدهید؛ اسکریپت وضعیت گواهی را بررسی می‌کند و در صورت نبود، با acme.sh صادر می‌کند.
گواهی‌ها اینجا ذخیره می‌شوند:

```
/cert_folder/cert/example.com/fullchain.pem
/cert_folder/cert/example.com/privkey.pem
```

(DNS دامنه باید به سرور اشاره کند.)

---

## ۷) ساخت اینباندها

منوی `4` (Generate Inbounds):

| گزینه | ساخت |
|---|---|
| `1` | اینباندهای DIRECT |
| `2` | اینباندهای CDN (پشت کلودفلر) |
| `3` | FAKE SITE |
| `4` | RELAY |
| `6` | ماتریس تست XHTTP برای CDN |

**مثال: ساخت همه‌ی اینباندهای CDN**

```
Main menu: 4  ->  2
دامنه CDN را انتخاب کنید (یا همان ذخیره‌شده را تأیید کنید)
Add ECH config list ... [Y/n]:   Enter      (پیش‌فرض: بله)
Apply finalmask ... [y/N]:       Enter      (پیش‌فرض: خیر)
Template number, or a for all [a]:  Enter   (همه)
```

شش قالب CDN با پورت ثابت ساخته می‌شود:

| قالب | پورت |
|---|---|
| WS | 8443 |
| HTTPUpgrade | 2053 |
| XHTTP (packet-up) | 2083 |
| gRPC | 2087 |
| VMess WS | 2096 |
| XHTTP (stream-up) | 44300 |

> قالب پورت `44300` در کلودفلر پورت مجاز نیست؛ باید در Cloudflare یک **Origin Rule** بسازید که یک پورت کلودفلر (مثلاً `2083`) را به `44300` مپ کند.
>
> در تنظیمات DNS کلودفلر، رکورد دامنه CDN باید **Proxied** (ابر نارنجی) باشد.

**مثال: فقط یک قالب** — به‌جای `a` شماره قالب را بزنید، مثلاً `12`.

بعد از ساخت، لینک/ساب اینباندها را از خود پنل بردارید.

---

## ۸) کارهای بعدی

| منو | کار |
|---|---|
| `6` | مدیریت اینباندهای موجود پنل |
| `8` | خروجی JSON و YAML از اینباندها |
| `9` | گزارش‌ها |
| `10` | بکاپ و بازیابی (`Create backup` / `Restore`) |

## ۹) آپدیت اسکریپت

زیپ جدید را در **پوشه‌ی تازه** باز کنید (روی پوشه‌ی قدیمی unzip نکنید؛ قالب‌های حذف‌شده می‌مانند)، سپس تنظیمات را کپی کنید:

```bash
cp old-folder/config/settings.json new-folder/config/settings.json
```

## ۱۰) اجرای تست‌ها (اختیاری)

```bash
python3 -m unittest discover -s tests
```
