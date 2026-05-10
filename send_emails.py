#!/usr/bin/env python3
"""
Toplu kurumsal outreach mail gönderim aracı.

Üç farklı şablon (V1 tek tip, V2 revize, V3 per-company kişiselleştirilmiş)
ile alıcı listesindeki şirketlere ardışık mail gönderir. Drip mod, idempotent
resume, header sanitization, macOS Keychain ile parola izolasyonu içerir.

Kullanım:
    python send_emails.py --check-dns                     # SPF/DKIM/DMARC ön kontrolü
    python send_emails.py --check-keychain                # Keychain entry varlık testi
    python send_emails.py --template v1 --dry-run
    python send_emails.py --template v3 --test you@your-domain.com
    python send_emails.py --template v3 --limit 8 --delay 30

Güvenlik notları:
    • .env dosyasını ASLA git'e commit etmeyin (.gitignore'da olmalı)
    • Parola .env'de DEĞİL macOS Keychain'de tutulur
    • .env izinleri: chmod 600 .env
    • Hesapta 2FA açık olmalı
"""
import argparse
import csv
import os
import re
import smtplib
import socket
import ssl
import subprocess
import sys
import time
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import formataddr, make_msgid
from pathlib import Path


# ============================================================
# Secret protection layer
# ============================================================
class MaskedSecret:
    """Parolayı sarmalar. str/repr asla parolayı göstermez.
    Sadece .reveal() ile çıplak değere erişilir; sadece smtplib AUTH için kullanılır.
    """
    __slots__ = ("_val",)

    def __init__(self, val: str):
        if not isinstance(val, str):
            raise TypeError("MaskedSecret yalnızca str kabul eder")
        self._val = val

    def reveal(self) -> str:
        return self._val

    def __str__(self) -> str:
        return "***"

    def __repr__(self) -> str:
        return "MaskedSecret(***)"

    def __bool__(self) -> bool:
        return bool(self._val)

    def __len__(self) -> int:
        return 0  # uzunluk bile sızdırma


class SecretStore:
    """Bilinen secret'ları toplu tutar. Log/exception scrubber için kullanılır."""
    _secrets: list = []

    @classmethod
    def add(cls, s: "MaskedSecret"):
        cls._secrets.append(s)

    @classmethod
    def scrub(cls, text: str) -> str:
        """Text içinden bilinen tüm secret değerleri ***'a çevirir.
        Çok kısa secret'ları (<8 karakter) yıkamaz — false positive riski.
        """
        if not text:
            return text
        for ms in cls._secrets:
            try:
                val = ms.reveal()
            except Exception:
                continue
            if val and len(val) >= 8:
                text = text.replace(val, "***")
        return text


DEFAULT_KEYCHAIN_SERVICE = "outreach-mailer-smtp"


def get_smtp_password(smtp_user: str, service: str = DEFAULT_KEYCHAIN_SERVICE) -> MaskedSecret:
    """macOS Keychain'den parolayı oku. Subprocess pipe; stdout asla print edilmez."""
    try:
        result = subprocess.run(
            ["security", "find-generic-password",
             "-a", smtp_user, "-s", service, "-w"],
            capture_output=True, text=True, timeout=5
        )
    except FileNotFoundError:
        sys.exit(
            "HATA: 'security' komutu bulunamadı (macOS gerekli).\n"
            "Linux/Windows için Keychain alternatif: pass / Windows Credential Manager."
        )
    except subprocess.TimeoutExpired:
        sys.exit("HATA: Keychain timeout (5sn).")
    if result.returncode != 0:
        sys.exit(
            f"HATA: Keychain'de entry yok (account={smtp_user}, service={service}).\n"
            f"Önce kurulum yapın (kendi terminalinizde, asistana yazmadan):\n"
            f"    security add-generic-password -a {smtp_user} -s {service} -w\n"
            f"Sondaki -w invisible prompt açar; parolayı yazın — ekrana yazılmaz, "
            f"shell history'e girmez."
        )
    pw = result.stdout.rstrip("\n")
    if not pw:
        sys.exit("HATA: Keychain'den boş parola döndü.")
    return MaskedSecret(pw)


def check_keychain(smtp_user: str, service: str = DEFAULT_KEYCHAIN_SERVICE):
    """Keychain'de entry var mı diye SADECE varlık testi.
    Parolayı OKUMAZ — `-w` parametresi yok.
    """
    print(f"[Keychain Check] account={smtp_user}, service={service}\n" + "=" * 60)
    try:
        # -w yok = parola değil sadece metadata döner
        result = subprocess.run(
            ["security", "find-generic-password", "-a", smtp_user, "-s", service],
            capture_output=True, text=True, timeout=5
        )
    except FileNotFoundError:
        print("  ✗ 'security' komutu yok (macOS dışı sistem)")
        return
    except subprocess.TimeoutExpired:
        print("  ✗ Keychain timeout")
        return
    if result.returncode == 0:
        print("  ✓ Keychain entry mevcut. (Parola okunmadı — sadece varlık testi.)")
        print("  Sıradaki adım: python send_emails.py --template v3 --test EMAIL")
    else:
        print("  ✗ Keychain entry YOK. Eklemek için (kendi terminalinizde):")
        print(f"    security add-generic-password -a {smtp_user} -s {service} -w")
        print("    Sondaki -w invisible prompt — parola ekranda görünmez, history'e girmez.")

ROOT = Path(__file__).resolve().parent
RECIPIENTS = ROOT / "recipients.csv"
LOG = ROOT / "send_log.csv"
ENV_FILE = ROOT / ".env"
TEMPLATES = {
    "v1": ROOT / "email_v1_original.txt",
    "v2": ROOT / "email_v2_revised.txt",
    "v3": ROOT / "email_v3_personalized.txt",
}
PLACEHOLDER_PATTERN = re.compile(r"\[[A-ZÇĞİÖŞÜ][^\]]*\]")  # ör: [X], [Adınız Soyadınız]


# ============================================================
# .env loader
# ============================================================
def load_env():
    """Public config (HOST/PORT/USER) okur. SMTP_PASS asla .env'den okunmaz —
    parola Keychain'den gelir.
    """
    if not ENV_FILE.exists():
        sys.exit(
            "HATA: .env bulunamadı. Önce şu komutu çalıştırın:\n"
            "    cp .env.example .env\n"
            "Sonra .env içine SMTP HOST/PORT/USER bilgilerini girin "
            "(parola Keychain'de — .env'ye YAZMAYIN)."
        )
    env = {}
    for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        env[k.strip()] = v.strip().strip('"').strip("'")
    # SMTP_PASS Keychain'den geleceği için zorunlu değil
    required = ["SMTP_HOST", "SMTP_PORT", "SMTP_USER"]
    missing = [k for k in required if not env.get(k)]
    if missing:
        sys.exit(f"HATA: .env içinde eksik değişkenler: {', '.join(missing)}")
    # Eğer kullanıcı yanlışlıkla SMTP_PASS yazmışsa uyar (ama kullanma)
    if env.get("SMTP_PASS"):
        print(
            "[UYARI] .env içinde SMTP_PASS satırı bulundu fakat YOKSAYILDI.\n"
            "        Parola yalnızca macOS Keychain'den okunur. "
            "Lütfen .env'den SMTP_PASS satırını silin (güvenlik).",
            file=sys.stderr,
        )
        env.pop("SMTP_PASS", None)
    return env


# ============================================================
# Template parsing
# ============================================================
def parse_template(path: Path):
    """İlk satır 'Subject: ...' olmalı; sonra boş satır; sonra body."""
    content = path.read_text(encoding="utf-8")
    lines = content.split("\n")
    if not lines[0].lower().startswith("subject:"):
        sys.exit(f"HATA: {path.name} ilk satırı 'Subject: ...' ile başlamalı.")
    subject = lines[0].split(":", 1)[1].strip()
    try:
        empty_idx = lines.index("", 1)
    except ValueError:
        sys.exit(f"HATA: {path.name} subject satırından sonra boş satır olmalı.")
    body = "\n".join(lines[empty_idx + 1:]).rstrip() + "\n"
    return subject, body


def sanitize_header(s: str) -> str:
    """Header injection önleme: \\r ve \\n karakterlerini bosluga çevir."""
    return re.sub(r"[\r\n]+", " ", s).strip()


def render_template(subject: str, body: str, ctx: dict):
    """{{placeholder}} → ctx[placeholder] değişimi."""
    out_subject = subject
    out_body = body
    for key, val in ctx.items():
        token = "{{" + key + "}}"
        # Subject'ta header injection riski var → sanitize
        out_subject = out_subject.replace(token, sanitize_header(str(val)))
        out_body = out_body.replace(token, str(val))
    return out_subject, out_body


def check_unfilled_placeholders(text: str, label: str):
    found = PLACEHOLDER_PATTERN.findall(text)
    if found:
        sys.exit(
            f"HATA: {label} içinde doldurulmamış placeholder var: {', '.join(sorted(set(found)))}\n"
            f"Lütfen template dosyasını düzenleyip gerçek değerleri yazın."
        )


# ============================================================
# V3-specific: birim mapping + donem phrase
# ============================================================
def compute_birim(email: str) -> str:
    """E-posta prefix'inden alıcı birimini çıkar."""
    prefix = email.split("@", 1)[0].lower()
    rules = [
        (r"surdurulebilirlik|sustainability", "Sürdürülebilirlik"),
        (r"\bcsr\b|community", "Kurumsal Sosyal Sorumluluk"),
        (r"iletisim|communications", "Kurumsal İletişim"),
        (r"\bkurumsal\b|corporate", "Kurumsal İlişkiler"),
        (r"turkey|turkiye", "Kurumsal İletişim"),
    ]
    for pattern, label in rules:
        if re.search(pattern, prefix):
            return label
    return "Kurumsal İletişim"  # fallback


def donem_phrase(donem: str) -> str:
    """Donem değerinden gramer açısından doğru bir cümle üret."""
    s = (donem or "").strip()
    low = s.lower()
    if not low or low == "tüm yıl":
        return "Yıl boyunca esnek bir takvimde planlama yapabiliriz."
    return f"Programınızın {s} odağına uygun bir takvim oluşturabiliriz."


# ============================================================
# Recipients
# ============================================================
def load_recipients(template: str):
    if not RECIPIENTS.exists():
        sys.exit(f"HATA: {RECIPIENTS.name} bulunamadı.")
    out = []
    with RECIPIENTS.open(encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            name = (row.get("company_name") or "").strip()
            email = (row.get("email") or "").strip()
            program = (row.get("program") or "").strip()
            donem = (row.get("donem") or "").strip()
            if not name or not email:
                continue
            if template == "v3" and (not program or not donem):
                sys.exit(
                    f"HATA: V3 için her satırın 'program' ve 'donem' kolonu dolu olmalı.\n"
                    f"  Eksik satır: {name} ({email}) — program='{program}' donem='{donem}'"
                )
            out.append({
                "company_name": name,
                "email": email,
                "program": program,
                "donem": donem,
            })
    return out


def build_context(recip: dict, template: str, env: dict = None) -> dict:
    """Template render context'i. NGO_* env değerleri tüm template'lere otomatik enjekte."""
    env = env or {}
    base = {
        "company_name": recip["company_name"],
        "ngo_name": env.get("NGO_NAME", "[NGO_NAME boş]"),
        "ngo_email": env.get("NGO_EMAIL", "[NGO_EMAIL boş]"),
        "ngo_url": env.get("NGO_URL", "[NGO_URL boş]"),
    }
    if template == "v3":
        base.update({
            "email": recip["email"],
            "program": recip["program"],
            "donem": recip["donem"],
            "birim": compute_birim(recip["email"]),
            "donem_sentence": donem_phrase(recip["donem"]),
        })
    return base


# ============================================================
# Logging (idempotent resume)
# ============================================================
def already_sent(template_name: str):
    if not LOG.exists():
        return set()
    sent = set()
    with LOG.open(encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("status") == "sent" and row.get("template") == template_name:
                sent.add(row.get("recipient"))
    return sent


def append_log(template_name: str, recipient: str, status: str, error: str = ""):
    new_file = not LOG.exists()
    with LOG.open("a", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        if new_file:
            w.writerow(["timestamp", "recipient", "template", "status", "error"])
        w.writerow([
            datetime.now(timezone.utc).isoformat(timespec="seconds"),
            recipient, template_name, status, error,
        ])


# ============================================================
# SMTP send
# ============================================================
def build_message(env: dict, to_addr: str, subject: str, body: str):
    msg = EmailMessage()
    from_name = env.get("FROM_NAME") or env["SMTP_USER"]
    msg["From"] = formataddr((sanitize_header(from_name), env["SMTP_USER"]))
    msg["To"] = sanitize_header(to_addr)
    msg["Subject"] = sanitize_header(subject)
    if env.get("REPLY_TO"):
        msg["Reply-To"] = sanitize_header(env["REPLY_TO"])
    msg["Message-ID"] = make_msgid(domain=env["SMTP_USER"].split("@")[-1])
    msg.set_content(body, charset="utf-8")
    return msg


def open_smtp(env: dict):
    """SMTP bağlantısı + AUTH. Parola Keychain'den; MaskedSecret olarak SecretStore'a eklenir."""
    host = env["SMTP_HOST"]
    port = int(env["SMTP_PORT"])
    user = env["SMTP_USER"]
    service = env.get("KEYCHAIN_SERVICE", DEFAULT_KEYCHAIN_SERVICE)
    secret = get_smtp_password(user, service)  # MaskedSecret döner
    SecretStore.add(secret)  # log scrubbing için
    ctx = ssl.create_default_context()
    if port == 465:
        s = smtplib.SMTP_SSL(host, port, context=ctx, timeout=30)
    else:
        s = smtplib.SMTP(host, port, timeout=30)
        s.ehlo()
        s.starttls(context=ctx)
        s.ehlo()
    # smtplib AUTH için reveal — SADECE bu çağrı boyunca, başka yerde kullanılmaz
    s.login(user, secret.reveal())
    return s


# ============================================================
# DNS pre-flight: SPF, DKIM, DMARC checks
# ============================================================
def dns_txt_lookup(name: str):
    """Stdlib ile basit DNS TXT lookup (no external deps)."""
    try:
        # Python stdlib doesn't expose TXT directly; use socket-level workaround:
        # Try `dig` first, fall back to Python's resolver via getaddrinfo trick.
        import subprocess
        result = subprocess.run(
            ["dig", "+short", "TXT", name],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0 and result.stdout.strip():
            return [line.strip().strip('"') for line in result.stdout.strip().split("\n") if line.strip()]
        return []
    except Exception as e:
        return [f"__lookup_error__: {e}"]


def check_dns_for_domain(domain: str):
    """Domain için SPF, DKIM (varsayılan selector), DMARC TXT kayıtlarını kontrol et."""
    print(f"\n[DNS Pre-flight] Domain: {domain}\n" + "=" * 60)

    # SPF — domain'in TXT kayıtlarında v=spf1 başlangıçlı satır olmalı
    print(f"\n1. SPF (domain TXT @ {domain})")
    txts = dns_txt_lookup(domain)
    spf_found = [t for t in txts if "v=spf1" in t.lower()]
    if spf_found:
        print(f"   ✓ SPF bulundu: {spf_found[0][:120]}")
    else:
        print(f"   ✗ SPF YOK — Gmail/Outlook spam'e atar. DNS'te şu kaydı ekleyin:")
        print(f'     {domain}. TXT "v=spf1 include:_spf.google.com ~all"  (Workspace için)')
        print(f"     (Diğer providerlar için kendi SPF dökümanına bakın.)")

    # DMARC — _dmarc.{domain} TXT kaydı olmalı
    print(f"\n2. DMARC (_dmarc.{domain})")
    dmarc_txts = dns_txt_lookup(f"_dmarc.{domain}")
    dmarc_found = [t for t in dmarc_txts if "v=dmarc1" in t.lower()]
    if dmarc_found:
        print(f"   ✓ DMARC bulundu: {dmarc_found[0][:120]}")
    else:
        print(f"   ✗ DMARC YOK — Önerilen başlangıç kaydı:")
        print(f'     _dmarc.{domain}. TXT "v=DMARC1; p=none; rua=mailto:postmaster@{domain}"')

    # DKIM — selector tahmin edilemez ama yaygın olanları dene
    # Hostinger selector'ları eklendi (kullanıcının domain'i Hostinger'da hosted)
    print(f"\n3. DKIM (yaygın selector'lar denenecek)")
    selectors_found = []
    for sel in ["google", "default", "selector1", "k1", "mail",
                "hostingermail-a", "hostingermail-b", "hostingermail-c",
                "zoho", "zmail"]:
        dkim_name = f"{sel}._domainkey.{domain}"
        txts = dns_txt_lookup(dkim_name)
        dkim_match = [t for t in txts if "v=dkim1" in t.lower() or "p=" in t.lower()]
        if dkim_match:
            selectors_found.append(sel)
            print(f"   ✓ DKIM bulundu (selector: {sel})")
            break
    if not selectors_found:
        print(f"   ⚠ Yaygın selector'larda DKIM bulunamadı.")
        print(f"   NOT: DKIM selector provider'a göre özeldir; mail-tester.com daha kesin sonuç verir.")

    # MX — en azından MX kaydı var mı (alıcı dönüş yolu)
    print(f"\n4. MX kaydı")
    try:
        import subprocess
        r = subprocess.run(["dig", "+short", "MX", domain], capture_output=True, text=True, timeout=10)
        if r.returncode == 0 and r.stdout.strip():
            print(f"   ✓ MX: {r.stdout.strip().split(chr(10))[0]}")
        else:
            print(f"   ✗ MX kaydı yok — domain mail kabul edemez.")
    except Exception as e:
        print(f"   ? MX lookup hatası: {e}")

    print("\n" + "=" * 60)
    print("Daha kesin skor için: https://www.mail-tester.com/")
    print("DNS detay görüntüleme: https://mxtoolbox.com/SuperTool.aspx?action=mx%3a" + domain)
    print()


# ============================================================
# Main
# ============================================================
def main():
    p = argparse.ArgumentParser(
        description="Toplu kurumsal outreach mail gönderim aracı",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="GÜVENLİK: SMTP_PASS olarak App Password kullanın. .env'i git'e commit etmeyin."
    )
    p.add_argument("--template", choices=["v1", "v2", "v3"], help="Hangi şablon")
    p.add_argument("--dry-run", action="store_true", help="Hiç gönderme; render'ı yaz")
    p.add_argument("--test", metavar="EMAIL", help="Sadece bu adrese 1 test")
    p.add_argument("--delay", type=int, default=30, help="Mailler arası saniye (default: 30)")
    p.add_argument("--limit", type=int, help="İlk N alıcıya gönder")
    p.add_argument("--no-resume", action="store_true", help="send_log'u yok say")
    p.add_argument("--check-dns", metavar="DOMAIN", nargs="?", const="__from_env__",
                   help="SPF/DKIM/DMARC/MX kontrolü yap (default: .env içindeki SMTP_USER domain'i)")
    p.add_argument("--check-keychain", action="store_true",
                   help="Keychain entry var mı diye kontrol et (parola OKUNMAZ, sadece varlık testi)")
    args = p.parse_args()

    # DNS pre-flight modu — diğer parametreler gerekmez
    if args.check_dns is not None:
        domain = args.check_dns
        if domain == "__from_env__":
            env = load_env()
            domain = env["SMTP_USER"].split("@")[-1]
        check_dns_for_domain(domain)
        return

    # Keychain pre-flight modu — parolayı okumadan varlık testi
    if args.check_keychain:
        env = load_env()
        service = env.get("KEYCHAIN_SERVICE", DEFAULT_KEYCHAIN_SERVICE)
        check_keychain(env["SMTP_USER"], service)
        return

    # Diğer modlar için template zorunlu
    if not args.template:
        p.error("--template gerekli (v1|v2|v3) — veya --check-dns kullanın")

    template_path = TEMPLATES[args.template]
    if not template_path.exists():
        sys.exit(f"HATA: {template_path.name} bulunamadı.")
    subject_tpl, body_tpl = parse_template(template_path)

    if args.dry_run:
        env = {"SMTP_USER": "dryrun@example.com", "FROM_NAME": "Dry Run",
               "SMTP_HOST": "-", "SMTP_PORT": "0", "SMTP_PASS": "-"}
    else:
        env = load_env()

    # Hedef listesi
    if args.test:
        targets = [{"company_name": "Test Alıcısı", "email": args.test,
                    "program": "Test Programı", "donem": "Tüm yıl"}]
    else:
        all_recips = load_recipients(args.template)
        skipped = set() if args.no_resume else already_sent(args.template)
        targets = [r for r in all_recips if r["email"] not in skipped]
        if args.limit:
            targets = targets[: args.limit]
        if skipped and not args.no_resume:
            print(f"[INFO] Daha önce gönderilmiş {len(skipped)} alıcı atlandı.")

    if not targets:
        print("[INFO] Gönderilecek alıcı kalmadı.")
        return

    # Placeholder kontrolü — ilk hedef üzerinden render edip incele
    # Dry-run'da kontrol uyarıya düşer (gönderim olmadığı için zarar yok, render görünmeli)
    sample_ctx = build_context(targets[0], args.template, env)
    sample_subj, sample_body = render_template(subject_tpl, body_tpl, sample_ctx)
    if args.dry_run:
        unfilled_subj = PLACEHOLDER_PATTERN.findall(sample_subj)
        unfilled_body = PLACEHOLDER_PATTERN.findall(sample_body)
        if unfilled_subj or unfilled_body:
            all_unf = sorted(set(unfilled_subj + unfilled_body))
            print(f"[UYARI] Doldurulmamış placeholder: {', '.join(all_unf)}")
            print("[UYARI] Gerçek gönderimde script reddedecek. Şimdi render gösteriliyor.\n")
    else:
        check_unfilled_placeholders(sample_subj, "Subject")
        check_unfilled_placeholders(sample_body, "Body")

    print(f"[INFO] Template: {args.template} | Hedef: {len(targets)} | Delay: {args.delay}s | Sender: {env.get('SMTP_USER', '?')}")

    if args.dry_run:
        for t in targets:
            ctx = build_context(t, args.template, env)
            subj, body = render_template(subject_tpl, body_tpl, ctx)
            print("=" * 70)
            print(f"To: {t['email']}  ({t['company_name']})")
            print(f"Subject: {subj}")
            if args.template == "v3":
                print(f"[V3 ctx] birim={ctx['birim']!r}  program={ctx['program'][:50]!r}")
            print("-" * 70)
            print(body)
        print("=" * 70)
        print(f"[DRY-RUN] {len(targets)} mail render edildi, gönderim yok.")
        return

    s = open_smtp(env)
    sent_count = 0
    fail_count = 0
    try:
        for i, t in enumerate(targets):
            ctx = build_context(t, args.template, env)
            subj, body = render_template(subject_tpl, body_tpl, ctx)
            msg = build_message(env, t["email"], subj, body)
            try:
                s.send_message(msg)
                append_log(args.template, t["email"], "sent")
                sent_count += 1
                print(f"[{i+1}/{len(targets)}] OK   -> {t['email']} ({t['company_name']})")
            except Exception as e:
                # Exception içinde parola sızabilir — scrub
                err_text = SecretStore.scrub(repr(e))
                append_log(args.template, t["email"], "failed", err_text)
                fail_count += 1
                print(f"[{i+1}/{len(targets)}] FAIL -> {t['email']} ({t['company_name']}): {SecretStore.scrub(str(e))}")
            if i < len(targets) - 1 and args.delay > 0:
                time.sleep(args.delay)
    finally:
        try:
            s.quit()
        except Exception:
            pass

    print(f"\n[ÖZET] Başarılı: {sent_count} | Hata: {fail_count} | Log: {LOG.name}")


if __name__ == "__main__":
    main()
