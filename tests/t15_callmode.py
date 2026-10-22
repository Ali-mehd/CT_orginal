"""cfgcall: اندازه‌گیری UDP از راه SOCKS5 + برآورد کیفیت، با یک رله‌ی SOCKS5 ساختگی (بدون هیچ ترافیک واقعی)."""
import sys, socket, struct, threading, time, random
sys.path.insert(0, ".")
import cfgcall as C


class FakeSocks:
    """رله‌ی SOCKS5 با UDP ASSOCIATE که به هر پرسش STUN جواب می‌ده؛ رفتارش با پارامترها عوض می‌شه."""
    def __init__(self, delay=lambda: 0.02, drop=0.0, refuse=False, silent=False, garbage=False):
        self.delay, self.drop, self.refuse, self.silent, self.garbage = delay, drop, refuse, silent, garbage
        self.tcp = socket.socket(); self.tcp.bind(("127.0.0.1", 0)); self.tcp.listen(5)
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); self.udp.bind(("127.0.0.1", 0))
        self.port, self.up = self.tcp.getsockname()[1], self.udp.getsockname()[1]
        self.stop = False
        threading.Thread(target=self._tcp, daemon=True).start(); threading.Thread(target=self._udp, daemon=True).start()

    def _tcp(self):
        while not self.stop:
            try: c, _ = self.tcp.accept()
            except OSError: return
            threading.Thread(target=self._ctl, args=(c,), daemon=True).start()

    def _ctl(self, c):
        try:
            c.recv(3); c.sendall(b"\x05\x00"); c.recv(10)
            if self.refuse: c.sendall(b"\x05\x07\x00\x01\0\0\0\0\0\0"); c.close(); return
            c.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00" + struct.pack(">H", self.up))
            while c.recv(100): pass
        except OSError: pass

    def _udp(self):
        while not self.stop:
            try: data, addr = self.udp.recvfrom(2048)
            except OSError: return
            if self.silent or random.random() < self.drop: continue
            i = 4 + 1 + data[4] + 2          # ATYP=3 دامنه
            body = data[i:]
            def reply(body=body, addr=addr, data=data):
                time.sleep(max(0, self.delay()))
                out = b"\x01\x01\x00\x00" + body[4:20] if not self.garbage else b"junk" * 6
                try: self.udp.sendto(data[:i] + out, addr)
                except OSError: pass
            threading.Thread(target=reply, daemon=True).start()

    def close(self):
        self.stop = True; self.tcp.close(); self.udp.close()


def run(count=20, **kw):
    s = FakeSocks(**kw)
    try:
        t0 = time.time(); r = C.measure(s.port, count=count, wait=0.8); dt = time.time() - t0
        return r, dt
    finally: s.close()


# ---- ۱) STUN: فقط جواب موفقِ همان تراکنش پذیرفته می‌شه
req, txn = C.stun_request()
good = b"\x01\x01\x00\x00" + struct.pack(">I", 0x2112A442) + txn
assert C.stun_ok(good, txn) and not C.stun_ok(good, b"x" * 12) and not C.stun_ok(b"\x01\x11" + good[2:], txn)
assert not C.stun_ok(b"", txn) and not C.stun_ok(b"\x00" * 30, txn) and not C.stun_ok(good[:19], txn)
print("1) STUN: only a success reply with the matching transaction counts OK")

# ---- ۲) شبکه‌ی خوب
r, dt = run(delay=lambda: 0.02); a = C.assess(r)
assert a["udp_ok"] and a["loss"] == 0 and 15 < a["p50"] < 80 and a["grade"] in ("excellent", "good") and a["mos"] >= 3.6, a
assert dt < 4, dt
print(f"2) good link: p50={a['p50']}ms jitter={a['jitter']}ms loss={a['loss']}% MOS={a['mos']} -> {a['grade']} ({dt:.1f}s) OK")

# ---- ۳) افت زیاد
random.seed(3); r, _ = run(count=40, drop=0.35); a = C.assess(r)
assert a["udp_ok"] and 15 <= a["loss"] <= 60 and a["grade"] in ("poor", "unusable") and any("افت" in w for w in a["why"]), a
print(f"3) lossy link: loss={a['loss']}% -> {a['grade']} reasons={a['why']} OK")

# ---- ۴) نوسان زیاد
random.seed(4); r, _ = run(count=30, delay=lambda: random.choice([0.01, 0.01, 0.25, 0.4, 0.02])); a = C.assess(r)
assert a["udp_ok"] and a["jitter"] > 80 and a["grade"] in ("poor", "unusable") and any("نوسان" in w for w in a["why"]), a
print(f"4) jittery link: jitter={a['jitter']}ms -> {a['grade']} OK")

# ---- ۵) تونل UDP نمی‌ده: سه حالت (رد ASSOCIATE، سکوت کامل، جواب خراب)
for kw in (dict(refuse=True), dict(silent=True), dict(garbage=True)):
    r, dt = run(count=10, **kw); a = C.assess(r or [])
    assert (r is None or all(x is None for x in r)) and not a["udp_ok"] and a["grade"] == "unusable" and a["mos"] == 1.0, (kw, a)
    assert dt < 6, dt
assert C.measure_via(1) is not None and C.measure_via(1)["grade"] == "unusable", "پورت بسته: استثنا نمی‌ده"
print("5) tunnel without UDP (refused / silent / garbage replies / closed port) -> 'unusable', bounded time, no exception OK")

# ---- ۶) ریاضیات: MOS با تأخیر، افت و نوسان فقط بد می‌شه (یکنواخت)
def Q(p50=40, loss=0, jitter=5, p95=None): return {"udp_ok": True, "p50": p50, "p95": p95 or p50 * 1.3, "loss": loss, "jitter": jitter}
ms = [C.mos(Q(p50=x)) for x in (20, 80, 150, 300, 600, 1200)]
assert all(a >= b for a, b in zip(ms, ms[1:])) and ms[0] > 4.0 and ms[-1] < 3.0, ms
ls = [C.mos(Q(loss=x)) for x in (0, 1, 3, 8, 15, 30)]
assert all(a > b for a, b in zip(ls, ls[1:])) and ls[0] > 4.0 and ls[-1] < 2.7, ls
js = [C.mos(Q(jitter=x)) for x in (0, 10, 40, 100, 300)]
assert all(a >= b for a, b in zip(js, js[1:])), js
assert 1.0 <= min(ms + ls + js) and max(ms + ls + js) <= 4.5
print(f"6) MOS monotone: delay {ms} | loss {ls} OK")

# ---- ۷) سقف درجه: MOS خوب هم افت یا نوسان شدید رو پنهان نمی‌کنه
assert C.grade(Q(loss=16))[0] == "unusable" and C.grade(Q(loss=9))[0] in ("poor", "unusable") and C.grade(Q(jitter=90))[0] in ("poor", "unusable")
assert C.grade(Q())[0] == "excellent" and C.grade(Q(p50=350))[0] in ("fair", "poor", "unusable")
assert not C.call_ok(None) and C.call_ok(C.assess([20.0] * 20)) and not C.call_ok(C.assess([None] * 20))
assert C.quality([])["udp_ok"] is False and C.quality([None, None])["loss"] == 100.0 and C.quality([30.0])["jitter"] == 0.0
print("7) grade caps by loss/jitter/delay; empty / all-lost / single sample handled OK")
print("ALL OK")
