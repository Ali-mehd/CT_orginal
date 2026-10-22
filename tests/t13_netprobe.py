"""netprobe: قاعده‌های نتیجه‌گیری روی «شبکه‌های شبیه‌سازی‌شده». هیچ ترافیک واقعی‌ای زده نمی‌شه."""
import sys, time
sys.path.insert(0, ".")
import netprobe as N

ALL = list(N.CF_ANCHORS) + list(N.OTHER_ANCHORS)
CF = list(N.CF_ANCHORS)


def fake(tcp_ok=None, closed_ports=(), udp=True, quic=True, bad_sni=(), neutral_ok=True, frag_ok=False, flaky_sni=False, asn="AS1", skew=0.0):
    """tcp_ok: مقصدهایی که ۴۴۳ جواب می‌دن (پیش‌فرض همه)؛ closed_ports: پورت‌هایی که روی کلودفلر بسته‌ان"""
    ok = set(ALL if tcp_ok is None else tcp_ok)
    calls = {}

    def tcp(ip, port, timeout=3.0):
        if ip not in ok:
            return None
        if port != 443 and port in closed_ports:
            return None
        return 20.0
    def ntp(ip, timeout=2.5):
        return (time.time() + skew) if udp else None
    def udp_dns(ip, timeout=2.5, name="example.com", qtype=1):
        return [b"\x01\x02\x03\x04"] if udp else None
    def quic_(ip, timeout=2.5):
        return bool(quic and udp)
    def tls(ip, sni, port=443, timeout=4.0, frag=None):
        k = (ip, sni, bool(frag)); calls[k] = calls.get(k, 0) + 1
        if sni == N.NEUTRAL_SNI:
            return True if neutral_ok else False
        if sni in bad_sni:
            if frag:
                return bool(frag_ok)
            if flaky_sni:
                return calls[k] > 1       # بار اول رد می‌شه، بار دوم نه (یعنی ثابت نیست)
            return False
        return True
    N.tcp, N.ntp, N.udp_dns, N.quic, N.tls = tcp, ntp, udp_dns, quic_, tls
    N.asn_info = lambda timeout=2.5: asn
    N.http_date = lambda ip, timeout=4.0: time.time() + skew


def cfg(proto="vless", port=443, **kw):
    return dict(proto=proto, port=port, security="tls", **kw)


# ---- ۱) شبکه‌ی سالم (مودم): هیچ چیز بسته نیست، هیچ جریمه‌ای نیست
fake(); r = N.probe()
assert r["net_ok"] and r["udp"] == "yes" and r["quic"] == "yes" and r["sni_filtered"] == "no", r
assert all(v == "yes" for v in r["ports"].values()), r["ports"]
assert all(N.priority(cfg(port=p), r) == 0 for p in N.PORTS) and not N.hard_skip(cfg("hysteria2"), r)
assert N.want_frag(cfg(), r) is False and N.timeout_scale(r) >= 1.0
print("1) healthy network: nothing penalised, no hard skip OK")

# ---- ۲) نت همراه: کل UDP و چند پورت بسته؛ TCP/443 سالم
fake(closed_ports=(8443, 2053, 2083, 2087, 2096), udp=False, quic=False); r = N.probe()
assert r["ports"][443] == "yes" and r["ports"][8443] == "no" and r["ports"][80] == "yes", r["ports"]
assert r["udp"] == "no" and r["quic"] == "no"
assert N.hard_skip(cfg("hysteria2", 443), r) and N.hard_skip(cfg("tuic", 443), r)
assert not N.hard_skip(cfg("hysteria2", 8443), r), "UDP بسته روی ۵۳/۱۲۳/۴۴۳ یعنی همه‌ی پورت‌های UDP بسته نیست؛ فقط اولویت"
assert N.priority(cfg("hysteria2", 8443), r) > 0 and N.priority(cfg("vless", 8443), r) > 0 and N.priority(cfg("vless", 443), r) == 0
assert not N.hard_skip(cfg("vless", 443), r) and not N.hard_skip(cfg("vless", 8443), r)
print("2) mobile-like: UDP dead -> hysteria2/tuic:443 skipped, closed ports only deprioritised, TCP 443 untouched OK")

# ---- ۳) قطعی اینترنت: هیچ نتیجه‌ای نباید صادر بشه (کنترل شکست خورده)
fake(tcp_ok=[]); r = N.probe()
assert not r["net_ok"] and r["udp"] == "unknown" and r["sni_filtered"] == "unknown" and not r["ports"], r
assert not N.hard_skip(cfg("hysteria2"), r) and N.priority(cfg(port=8443), r) == 0 and N.want_frag(cfg(), r) is None
print("3) outage: everything unknown, nothing skipped or reordered OK")

# ---- ۴) فقط ۲ مقصد کلودفلر زنده: «no» برای پورت‌ها ممنوعه (حداقل ۳ مقصد مستقل)
fake(tcp_ok=CF[:2] + list(N.OTHER_ANCHORS), closed_ports=(8443,), udp=False, quic=False); r = N.probe()
assert r["ports"][8443] == "unknown", r["ports"]
assert N.priority(cfg(port=8443), r) == 0
print("4) only 2 live anchors -> port verdict stays 'unknown' (no conclusion from too little evidence) OK")

# ---- ۵) یک مقصد پورت رو نمی‌ده ولی بقیه می‌دن → باز
class Part:
    pass
fake(); orig_tcp = N.tcp
def tcp_part(ip, port, timeout=3.0):
    if port == 2053 and ip == CF[0]:
        return None
    return orig_tcp(ip, port, timeout)
N.tcp = tcp_part; r = N.probe()
assert r["ports"][2053] == "yes", r["ports"]
print("5) one anchor refusing a port while others accept -> port stays open OK")

# ---- ۶) فیلتر SNI تأییدشده + fragment کار می‌کنه
fake(bad_sni=N.FILTERED_SNI, frag_ok=True); r = N.probe()
assert r["sni_filtered"] == "yes" and r["frag"] == "yes", (r["sni_filtered"], r["frag"], r["ev"])
assert N.want_frag(cfg(), r) is True and N.want_frag(dict(proto="vless", port=443, security="none"), r) is None
fake(bad_sni=N.FILTERED_SNI, frag_ok=False); r = N.probe()
assert r["sni_filtered"] == "yes" and r["frag"] == "no" and N.want_frag(cfg(), r) is None
print("6) SNI filter confirmed twice -> fragment first only if fragment really passes OK")

# ---- ۷) خطای ناپایدار (یک بار رد، یک بار نه) فیلتر حساب نمی‌شه
fake(bad_sni=N.FILTERED_SNI, flaky_sni=True); r = N.probe()
assert r["sni_filtered"] != "yes", r["ev"]
print("7) a one-off SNI failure is not treated as a filter OK")

# ---- ۸) نام عادی هم رد شد → مشکل از خود مقصد/مسیره، نه فیلتر SNI
fake(bad_sni=N.FILTERED_SNI, neutral_ok=False); r = N.probe()
assert r["sni_filtered"] == "unknown", r["ev"]
print("8) neutral name also failing -> no SNI conclusion (control failed) OK")

# ---- ۹) ساعت اشتباه اندازه‌گیری می‌شه و جریمه‌ی سرور نیست
fake(skew=3 * 3600); r = N.probe()
assert N.clock_bad(r) and "ساعت" in N.clock_msg_fa(r)
fake(skew=5); assert not N.clock_bad(N.probe())
print("9) clock skew measured, small skew ignored OK")

# ---- ۱۰) تایم‌اوت فقط بزرگ می‌شه، هیچ‌وقت کوچک‌تر از پیش‌فرض یا بیشتر از ۳ برابر نمی‌شه
assert N.timeout_scale(None) == 1.0
assert 1.0 <= N.timeout_scale({"rtt": {"p90": 30, "loss": 0}}) <= 1.0 + 1e-9
assert N.timeout_scale({"rtt": {"p90": 5000, "loss": 0.9}}) == 3.0
print("10) timeout scale bounded in [1,3] OK")

# ---- ۱۱) ترتیب هیچ‌وقت چیزی رو حذف نمی‌کنه: priority فقط یک عدد ≥۰ و کراندار
fake(closed_ports=(8443,), udp=False, quic=False); r = N.probe()
for p in (443, 8443, 2087, 80, 12345):
    for pr in ("vless", "vmess", "trojan", "hysteria2", "tuic"):
        v = N.priority(cfg(pr, p), r); assert 0 <= v <= 5
print("11) priority is only an order key (0..5), never removal OK")
print("ALL OK")
