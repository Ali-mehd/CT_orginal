"""سنجش تماس با چند سرور STUN، یادگیری تماس به‌تفکیک شبکه، و فیلدهای پنل تشخیص."""
import sys, os, tempfile, json, time, socket, struct, threading
os.environ["CFG_DATA"] = tempfile.mkdtemp(); sys.path.insert(0, ".")
import cfgweb as W, cfgcall as C

# ---- ۱) یک سرور STUN بسته → افت کاذب نسازه
class Fake:
    def __init__(self, dead_host=None, dead_all=False):
        self.dead_host, self.dead_all = dead_host, dead_all
        self.tcp = socket.socket(); self.tcp.bind(("127.0.0.1", 0)); self.tcp.listen(5)
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); self.udp.bind(("127.0.0.1", 0))
        self.port, self.up = self.tcp.getsockname()[1], self.udp.getsockname()[1]; self.stop = False
        threading.Thread(target=self._t, daemon=True).start(); threading.Thread(target=self._u, daemon=True).start()
    def _t(self):
        while not self.stop:
            try: c, _ = self.tcp.accept()
            except OSError: return
            threading.Thread(target=self._c, args=(c,), daemon=True).start()
    def _c(self, c):
        try:
            c.recv(3); c.sendall(b"\x05\x00"); c.recv(10); c.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00" + struct.pack(">H", self.up))
            while c.recv(100): pass
        except OSError: pass
    def _u(self):
        while not self.stop:
            try: d, a = self.udp.recvfrom(2048)
            except OSError: return
            host = d[5:5 + d[4]].decode(); i = 5 + d[4] + 2
            if self.dead_all or host == self.dead_host: continue
            time.sleep(0.02); self.udp.sendto(d[:i] + b"\x01\x01\x00\x00" + d[i + 4:i + 20], a)
    def close(self): self.stop = True; self.tcp.close(); self.udp.close()

def meas(**kw):
    f = Fake(**kw)
    try: return C.assess(C.measure(f.port, count=15, wait=0.8))
    finally: f.close()
a = meas(dead_host="stun.cloudflare.com"); assert a["udp_ok"] and a["loss"] == 0 and a["grade"] in ("excellent", "good"), a
a = meas(dead_host="stun.l.google.com"); assert a["udp_ok"] and a["loss"] == 0, a
a = meas(dead_all=True); assert not a["udp_ok"] and a["grade"] == "unusable", a
print("1) one blocked STUN server is not counted as packet loss; all blocked -> 'no UDP' OK")

# ---- ۲) یادگیری تماس: به‌تفکیک شبکه، نیمه‌عمر، ماندگاری، فایل خراب
def mk(h, proto="vless", net="ws", sec="tls"): return {"host": h, "proto": proto, "network": net, "security": sec}
W.NETID[0] = "a:home"; good = C.assess([20.0] * 20)
for _ in range(4): W.callmem_note(mk("1.1.1.1"), good)
assert W.callmem_prior(mk("9.9.9.9")) and W.callmem_prior(mk("9.9.9.9")) > 4.0, "هر سرور با همین روش، همین پیش‌بینی"
assert W.callmem_prior(mk("9.9.9.9", net="tcp")) is None, "روش دیگه چیزی یاد نگرفته"
W.NETID[0] = "a:mobile"; assert W.callmem_prior(mk("1.1.1.1")) is None, "روی شبکه‌ی دیگه همون تجربه صدق نمی‌کنه"
for _ in range(4): W.callmem_note(mk("2.2.2.2"), C.assess([None] * 20))
assert W.callmem_prior(mk("2.2.2.2")) == 1.0
assert W.call_key(mk("5.5.5.5")) == (1, -1.0), W.call_key(mk("5.5.5.5"))
W.NETID[0] = "a:home"; assert W.call_key(mk("5.5.5.5"))[1] < -4.0 and W.call_key(mk("5.5.5.5")) < W.call_key(dict(mk("6.6.6.6", net="tcp")))
W.NETID[0] = ""; W.callmem_note(mk("1.1.1.1"), good); assert W.callmem_prior(mk("1.1.1.1")) is None, "شبکه‌ی نامعلوم: چیزی ثبت یا استفاده نمی‌شه"
# نیمه‌عمر: تجربه‌ی بسیار قدیمی اثر نمی‌ذاره
W.NETID[0] = "a:home"; e = W.CALLMEM["a"]["a:home"]["vless/ws/tls"]; e[2] -= 30 * 3600
assert W.callmem_prior(mk("1.1.1.1")) is None
# ماندگاری + بدون آدرس + فایل خراب
W.callmem_note(mk("1.1.1.1"), good); W.callmem_save(True); txt = W.CALLMEM_FILE.read_text(encoding="utf-8")
assert "1.1.1.1" not in txt and "vless/ws/tls" in txt
W.CALLMEM["a"] = {}; W._callmem_load(); assert "a:home" in W.CALLMEM["a"]
for bad in ("not json", "[]", '{"a": {"x": {"m": [1, "z", 3]}}}', '{"a": 5}', '{"a": {"x": 7}}'):
    W.CALLMEM_FILE.write_text(bad, encoding="utf-8"); W._callmem_load(); assert isinstance(W.CALLMEM["a"], dict)
W.CALLMEM_FILE.write_text("{}", encoding="utf-8")
W.learn_reset(); assert not W.CALLMEM["a"] and not W.CALLMEM_FILE.exists()
print("2) call learning: per network + per method, half-life, persists without addresses, survives corrupt files, reset wipes it OK")

# ---- ۳) فیلدهای پنل تشخیص در state
W.NETP["shown"] = None; st = W.state(); st = json.loads(st) if isinstance(st, (str, bytes)) else st
assert st["net"] is None and set(st["diag"]) >= {"tested", "ok", "no_reach", "no_traffic", "unsafe"} and "link" in st and "bench" in st and "evolve" in st
W.NETP["shown"] = {"net_ok": True, "t": 1, "ports": {443: "yes", 8443: "no"}, "udp": "no", "quic": "no", "sni_filtered": "unknown", "frag": "unknown", "asn": "AS1"}
W.NETID[0] = "a:0123456789"; v = W.net_view()
assert v["ports"] == {"443": "yes", "8443": "no"} and v["udp"] == "no" and v["id"] == "012345" and v["clock"] == "", v
json.dumps(W.state() if not isinstance(W.state(), (str, bytes)) else {})  # قابل سریال‌سازی
W.NETP["shown"] = {"net_ok": False}; assert W.net_view()["ok"] is False
print("3) state exposes net/diag/link/bench/evolve; JSON-safe; failed probe is shown as failed OK")

# ---- ۴) رابط: بدون ماژول تکامل (اندروید) تب «تکامل» نمایش داده نمی‌شه
src = next(p for p in (W.HERE / "ui.html", W.HERE.parent / "assets" / "web" / "ui.html") if p.exists()).read_text(encoding="utf-8")
assert 'id="sec-evo"' in src and 'id="sec-diag"' in src and 'data-p="adv"' in src and 'id="npon"' in src and 'id="evok"' in src
print("4) UI has the diagnostics tab, network-probe switch and install-patch switch OK")
print("ALL OK")
