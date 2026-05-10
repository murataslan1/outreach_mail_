# Outreach Mailer — Toplu Kurumsal Mail Gönderim Aracı

Sivil toplum kuruluşları, vakıflar veya küçük ekipler için tasarlanmış **Python stdlib-only** toplu mail gönderim aracı. Hedef şirketlere iş birliği teklifi, tanıtım veya bağış talebi mailları gönderirken **deliverability**, **güvenlik** ve **yanıt oranı** önceliklendirilmiştir.

**Temel özellikler:**
- 3 farklı mail şablonu: tek tip (V1), revize tek tip (V2), per-company kişiselleştirilmiş (V3)
- Bireysel gönderim (BCC blast değil) → spam riski düşer
- Yapılandırılabilir drip mod (mailler arası gecikme + günlük limit)
- Idempotent resume (yarıda kalan batch otomatik kalan kısımdan devam eder)
- DNS pre-flight: SPF/DKIM/DMARC/MX kontrolü
- macOS Keychain ile parola izolasyonu (parola asla disk'te düz metin değil)
- Header injection sanitization
- Exception/log scrubbing (parola sızıntısı önleme)
- Tek harici bağımlılık: **yok** — sadece Python 3.8+ stdlib

---

## İçindekiler

1. [Bu araç ne yapar?](#1-bu-araç-ne-yapar)
2. [Önce neye ihtiyacınız var?](#2-önce-neye-ihtiyacınız-var)
3. [Adım adım kurulum](#3-adım-adım-kurulum)
4. [Hangi mail şablonu? (V1, V2, V3)](#4-hangi-mail-şablonu)
5. [Test etme](#5-test-etme)
6. [Gönderim](#6-gönderim)
7. [Sorun giderme](#7-sorun-giderme)
8. [Güvenlik notları](#8-güvenlik-notları)
9. [Dosya rehberi](#9-dosya-rehberi)

---

## 1. Bu araç ne yapar?

CSV'deki alıcı listesindeki her şirkete sırayla mail gönderir. Her mail:
- **Tek tek** gönderilir (BCC blast değil — spam riskini önler)
- **30 saniye arayla** gönderilir (mail sağlayıcı limiti aşılmaz)
- **Şirket adına özel** hitap içerir (V3 ise ek olarak kişiselleştirilmiş içerik)
- TLS şifreli SMTP üzerinden domain mail hesabıyla gider
- **Parola asla bir dosyaya yazılmaz** — macOS Keychain'de güvenli tutulur

**Yaklaşık zaman:**
- İlk kurulum: 10-15 dakika
- Test gönderimleri: 15-30 dakika
- Drip gönderim: günde 8 mail × N gün

---

## 2. Önce neye ihtiyacınız var?

| Gereksinim | Nasıl kontrol ederim? |
|---|---|
| **macOS** bilgisayar | Keychain entegrasyonu için gerekli |
| **Python 3.8+** | Terminal'de: `python3 --version` |
| **Domain mailbox** ve parolası | Hostinger / Google Workspace / Zoho / Yandex / cPanel |
| Kendi alanınızdaki mail adresine erişim | Webmail veya mail uygulamasında açabiliyor olmalısınız |

> **Terminal nasıl açılır?**
> Spotlight'ta (Cmd+Space) "Terminal" yazın, Enter.

> **Python yoksa:** https://www.python.org/downloads/

---

## 3. Adım adım kurulum

### Adım 1 — Repo'yu klonlayın

```
git clone <repo-url>
cd <repo-klasoru>
```

### Adım 2 — Alıcı listesini hazırlayın

`recipients.csv.example`'ı kopyalayıp kendi alıcılarınızla doldurun:

```
cp recipients.csv.example recipients.csv
```

CSV formatı:
- `company_name`: Şirket adı (mailda hitap için)
- `email`: Hedef e-posta adresi
- `program`: (V3 için) şirketin gönüllülük/CSR programının adı
- `donem`: (V3 için) tipik gönüllülük dönemi (ör. "Tüm yıl", "Ekim", "Nisan-Mayıs")

V1/V2 sadece `company_name` ve `email`'i kullanır. V3 dördünü de kullanır.

### Adım 3 — `.env` dosyası oluşturun (parola HARİÇ)

```
cp .env.example .env
chmod 600 .env
```

`.env`'i editörle açıp aşağıdakileri doldurun:
- `SMTP_HOST` (sağlayıcınıza göre — `.env.example`'da örnekler var)
- `SMTP_PORT` (genelde 465)
- `SMTP_USER` (mail adresiniz)
- `KEYCHAIN_SERVICE` (örn. `outreach-mailer-smtp`)
- `FROM_NAME` (mailda görünen ad)
- `NGO_NAME`, `NGO_EMAIL`, `NGO_URL` (mail içeriğine enjekte edilir)

**`.env`'ye parola YAZMAYIN** — script Keychain'den okur.

### Adım 4 — Parolayı Keychain'e güvenli ekleyin

```
security add-generic-password \
  -a <SMTP_USER değeriniz> \
  -s <KEYCHAIN_SERVICE değeriniz> \
  -w
```

Enter'a bastıktan sonra **invisible prompt** açılır:
- Parolanızı yazıp Enter
- **Ekranda görünmez**, **shell history'e girmez**, **bir dosyaya yazılmaz**
- macOS Keychain'de şifreli olarak saklanır

Doğrulamak için (parolayı OKUMAZ, sadece varlık testi):
```
python3 send_emails.py --check-keychain
```

### Adım 5 — DNS sağlığını kontrol edin

```
python3 send_emails.py --check-dns
```

4 satır görmelisiniz:
- ✓ SPF bulundu
- ✓ DMARC bulundu
- ✓ DKIM bulundu (selector tespit edildi)
- ✓ MX kaydı

**Bu 4 işaret = mailleriniz Gmail/Outlook'ta spam'e düşme riski düşük.** Eksikse mail sağlayıcınızın desteğine yazın.

---

## 4. Hangi mail şablonu?

### V1 — Tek tip, hızlı
- Tüm alıcılara aynı metin
- Sadece `{{company_name}}` ve `{{ngo_name}}` dinamik
- **Hiçbir hazırlık gerekmez**, hemen gönderilebilir
- Beklenen yanıt oranı: %2-5

### V2 — Revize tek tip
- Somut etki rakamı + net toplantı CTA'sı
- Aşağıdaki yerleri **siz doldurmadan gönderemezsiniz** (`email_v2_revised.txt` içinde):
  - `[X]`, `[Y]`, `[Z]` — somut etki rakamları (kaç il, kaç şube, kaç kişi vb.)
  - `[Adınız Soyadınız]`, `[Unvanınız]`, `[Telefon]`
- Beklenen yanıt oranı: %5-10

### V3 — Kişiselleştirilmiş (önerilen)
- Her şirket için **otomatik kişiselleştirme**:
  - Şirketin gönüllülük programının adı (CSV'den)
  - "Sayın Sürdürülebilirlik Ekibi" / "Kurumsal İletişim Ekibi" gibi otomatik birim hitabı (e-posta prefix'inden)
  - Şirketin gönüllülük dönemine uyumlu cümle (CSV'den)
- V2 ile aynı manuel placeholder'ları doldurmanız gerekir
- Beklenen yanıt oranı: %15-25

**Karar veremezseniz V3'ü seçin.**

---

## 5. Test etme

Gerçek alıcılara göndermeden önce mutlaka test:

### Test 1: Render (görsel kontrol, gönderim yok)

```
python3 send_emails.py --template v3 --dry-run
```

**Hiçbir mail göndermez** — her şirket için mailın nasıl görüneceğini terminal'de yazar. Türkçe karakterler, hitap, imza kontrol edin.

### Test 2: Kendinize gerçek mail at

```
python3 send_emails.py --template v3 --test you@your-domain.com
```

Sadece **1 mail** gönderir. Gelen kutunuzda:
- Spam'e mi düştü, inbox'a mı?
- Türkçe karakterler doğru mu?
- Görünen gönderici doğru mu?
- İmza ve link doğru mu?

### Test 3: Spam skoru

https://www.mail-tester.com adresinden tek seferlik bir adres alın, sonra:

```
python3 send_emails.py --template v3 --test <mail-tester-adres>
```

Mail-tester'da skoru kontrol edin. **8/10 veya üstü** olmalı.

---

## 6. Gönderim

### İlk dalga: 5 mail

```
python3 send_emails.py --template v3 --limit 5 --delay 60
```

- 5 alıcı seçilir
- Her mail arasında 60 saniye bekleme
- Toplam ~5 dakika

**1-2 saat bekleyin.** `send_log.csv`'yi açın. Bounce var mı? Yoksa devam.

### Sonraki dalgalar: günde 8 mail

```
python3 send_emails.py --template v3 --limit 8 --delay 30
```

- Önceki dalgalardakiler otomatik atlanır (`send_log.csv` üzerinden)
- 8 yeni alıcıya gönderir, 30 saniye arayla = 4 dakika

**Her gün aynı komutu çalıştırın → N günde alıcı listeniz tamamlanır.**

### İlerleme kontrolü

```
python3 -c "
import csv
sent = set()
with open('send_log.csv') as f:
    for r in csv.DictReader(f):
        if r['status'] == 'sent': sent.add(r['recipient'])
print(f'Gönderilen: {len(sent)}')
"
```

---

## 7. Sorun giderme

### "HATA: .env bulunamadı"
`cp .env.example .env` komutunu çalıştırmadınız.

### "HATA: Keychain'de entry yok"
Adım 4'ü yapmadınız. Yeniden:
```
security add-generic-password -a <SMTP_USER> -s <KEYCHAIN_SERVICE> -w
```

### "HATA: Body içinde doldurulmamış placeholder var"
V2 veya V3'te `[X]`, `[Adınız Soyadınız]` gibi köşeli parantezleri doldurmadınız. İlgili `.txt` dosyasını editörle açıp doldurun.

### "SMTPAuthenticationError"
Keychain'deki parola yanlış. Sağlayıcınızda parolanızı kontrol edin, gerekirse Keychain'i sıfırlayın:
```
security delete-generic-password -s <KEYCHAIN_SERVICE>
security add-generic-password -a <SMTP_USER> -s <KEYCHAIN_SERVICE> -w
```

### Mail spam'e düşüyor
- mail-tester.com skoru 8/10'un altında mı? → İçeriği iyileştirin
- DNS check'te SPF/DKIM/DMARC ✓ mı? → Değilse sağlayıcı desteğine yazın
- Çok hızlı mı gönderdiniz? → `--delay 60+` deneyin

### Yanlışlıkla parolayı `.env`'ye yazdım
Sorun değil — script onu yoksayar ve uyarı verir. Yine de `.env`'i açıp `SMTP_PASS=...` satırını silin.

---

## 8. Güvenlik notları

| Koruma | Ne yapar? |
|---|---|
| Keychain depolama | Parola disk'te düz metin değil, macOS şifreli vault'unda |
| `MaskedSecret` sınıfı | Parola yanlışlıkla yazdırılırsa `***` gözükür |
| `SecretStore.scrub` | Hata mesajları log'a yazılırken parola otomatik temizlenir |
| `.gitignore` | `.env`, `send_log.csv`, alıcı listesi git'e gitmez |
| TLS zorunlu | SMTP bağlantısı port 465 üzerinden şifreli |
| smtplib debug kapalı | AUTH satırı stdout'a basılmaz |

**Sizin yapmanız gerekenler:**
1. Parolayı **asla** sohbete, e-postaya, Slack'e yazmayın
2. `.env` dosyasını başkasına **göndermeyin**
3. iCloud Desktop sync açıksa endişelenmeyin — `.env`'de parola yok
4. FileVault aktif olsun

---

## 9. Dosya rehberi

| Dosya | Ne işe yarar? | Git'te mi? |
|---|---|---|
| `send_emails.py` | Ana gönderim scripti | Evet |
| `email_v1_original.txt` | V1 şablonu (tek tip) | Evet (placeholder'lı) |
| `email_v2_revised.txt` | V2 şablonu (revize) | Evet (placeholder'lı) |
| `email_v3_personalized.txt` | V3 şablonu (kişiselleştirilmiş) | Evet (placeholder'lı) |
| `recipients.csv.example` | Alıcı listesi format örneği | Evet |
| `recipients.csv` | Sizin gerçek alıcı listeniz | **Hayır** (gitignore) |
| `.env.example` | Yapılandırma şablonu | Evet |
| `.env` | Sizin yapılandırmanız (parola İÇERMEZ) | **Hayır** (gitignore) |
| `.gitignore` | Hassas dosyaların git'e girmesini engeller | Evet |
| `send_log.csv` | Otomatik üretilir — gönderim geçmişi | **Hayır** (gitignore) |
| `README.md` | Bu dosya | Evet |

---

## Lisans

MIT.

## Yardım

`python3 send_emails.py --help` komutuyla tüm seçenekleri görebilirsiniz.
