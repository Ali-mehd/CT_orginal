import sys, os, json, tempfile, shutil, zipfile, io, time, hashlib
from pathlib import Path
# تکامل امن: گزارش، وصله با اتاق تست، برگشت، سقف حجم، تنظیم خودکار، محافظ بوت. همه روی یک کپی موقت؛ به برنامه‌ی واقعی دست نمی‌زنه.
os.environ["CFG_DATA"] = tempfile.mkdtemp(); os.environ["CFG_NO_RESTART"] = "1"; sys.path.insert(0, ".")
import evolve as ev
REAL = Path(".").resolve().parent
T = Path(tempfile.mkdtemp())
(T / "app").mkdir(); (T / "tests").mkdir()
for f in (REAL / "app").iterdir():
    if f.is_file() and f.suffix in (".py", ".html", ".txt"):
        shutil.copy2(f, T / "app" / f.name)
for n in ("t11_bad_memory.py", "t12_corrupt_files.py"):  # اتاق تست با دو تست سبک
    shutil.copy2(REAL / "tests" / n, T / "tests" / n)
D = T / "data"; D.mkdir()
ev.init(T, D)
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()

# ---------- گزارش: پاک‌سازی و مهر
ctx = {"recent_log": ["وصل شد به 203.0.113.9:443 با vless://aaaa-bbbb@host.example:443?x=1 و ایمیل a@b.co",
                      "uuid 123e4567-e89b-12d3-a456-426614174000 مسیر C:\\Users\\Ali\\x.txt توکن " + "A" * 40],
       "stats": {"tested": 100, "alive": 12, "reach": 30, "fails": {"no_reach": 50}}, "sources": [{"src": "o/r/main/a.txt", "on": True, "yield": 0.001}]}
rid, text = ev.make_report(ctx)
for bad in ("203.0.113.9", "vless://", "123e4567", "C:\\Users", "a@b.co", "A" * 40):
    assert bad not in text and bad not in json.dumps(ev.open_report(text), ensure_ascii=False), bad
rep = ev.open_report(text)
assert rep["id"] == rid and rep["kind"] == "ctreport" and rep["metrics"]["alive_rate"] == 0.12 and rep["code"], rep["metrics"]
assert rep["ctx"]["sources"][0]["src"] == "o/r/main/a.txt"
try:
    ev.open_report(text.replace("CTREPORT1\n", "CTREPORT1\nAAAA"))
    raise SystemExit("tampered report accepted")
except ev.PatchError:
    pass
print("report ok, id", rid)

def read(p): return (T / p).read_text(encoding="utf-8")
def mk(edits, report_id=None, root=T, **kw):
    return ev.build_patch(root, {k: (v if isinstance(v, bytes) else v.encode("utf-8")) for k, v in edits.items()},
                          report_id or rid, kw.get("title", "آزمایش"), kw.get("notes", "یادداشت"))
def fresh_report():
    return ev.make_report({})[0]

# ---------- وصله‌ی خوب: بررسی، تست، نصب
good = read("app/cfgscan.py") + "\n# patched-by-test\n"
r = ev.inspect_patch(mk({"app/cfgscan.py": good}))
assert r["ok"], r["errors"]
assert r["summary"]["files"][0]["action"] == "replace"
before = sha(T / "app" / "cfgscan.py")
assert ev.apply_patch(mk({"app/cfgscan.py": good, "app/extra_mod.py": "X = 1\n"}), wait=True)
assert ev.JOB["state"] == "done", ev.JOB
assert "patched-by-test" in read("app/cfgscan.py") and (T / "app" / "extra_mod.py").is_file()
st = ev.status(); assert st["applied"][-1]["active"] and not st["applied"][-1]["ok"]
assert (D / "evolve" / "original" / "app" / "cfgscan.py").is_file()
print("good patch installed:", ev.JOB["steps"][-2])

# ---------- هر گزارش فقط یک وصله
r = ev.inspect_patch(mk({"app/cfgscan.py": good + "#2\n"}))
assert not r["ok"], "report id reused"

# ---------- وصله‌های بد باید رد بشن و فایل‌ها دست‌نخورده بمونن
snap = {p.name: sha(p) for p in (T / "app").iterdir() if p.is_file()}
def reject(name, edits, expect=None, rid_=None, run=False):
    rp = rid_ or fresh_report()
    data = mk(edits, rp) if not callable(edits) else edits(rp)
    if run:
        ok = ev.apply_patch(data, wait=True)
        assert ev.JOB["state"] == "failed", (name, ev.JOB)
        msg = ev.JOB["msg"]
    else:
        r = ev.inspect_patch(data)
        assert not r["ok"], name
        msg = " ".join(r["errors"])
    if expect:
        assert expect in msg, (name, msg)
    assert {p.name: sha(p) for p in (T / "app").iterdir() if p.is_file()} == snap, name + ": live files changed!"
    print("rejected:", name)

cur = read("app/cfgscan.py")
reject("syntax error", {"app/cfgscan.py": cur + "\ndef broken(:\n"}, "نوشتاری")
reject("protected evolve.py", {"app/evolve.py": read("app/evolve.py") + "\n#x\n"}, "محافظه")
reject("path traversal", lambda r: (lambda b: b)(ev.build_patch(T, {"app/../../evil.py": b"x=1"}, r, "t")), "مجاز نیست")
reject("outside whitelist", {"launcher/x.go": "package main"}, "مجاز نیست")
reject("stdlib shadow", {"app/json.py": "x=1\n"}, "ماژول‌های خود پایتون")
reject("existing test replaced", {"tests/t11_bad_memory.py": "print(1)\n"}, "تست")
reject("cfgweb without guard", {"app/cfgweb.py": read("app/cfgweb.py").replace("[evolve-guard]", "[x]")}, "محافظ")
reject("unknown report id", {"app/cfgscan.py": cur + "\n#y\n"}, "گزارشی", rid_="deadbeefdead")
# base قدیمی: فایل بعد از ساخت وصله عوض شده
rp = fresh_report(); stale = mk({"app/report.py": read("app/report.py") + "\n#z\n"}, rp)
(T / "app" / "report.py").write_text(read("app/report.py") + "\n#changed\n", encoding="utf-8"); snap["report.py"] = sha(T / "app" / "report.py")
assert not ev.inspect_patch(stale)["ok"] and "فرق داره" in " ".join(ev.inspect_patch(stale)["errors"]); print("rejected: stale base")
# زیپ دستکاری‌شده (مهر فایل نمی‌خونه)
rp = fresh_report(); b = mk({"app/cfgforge.py": read("app/cfgforge.py") + "\n#q\n"}, rp)
zi, zo = zipfile.ZipFile(io.BytesIO(b)), io.BytesIO()
with zipfile.ZipFile(zo, "w") as z:
    for n in zi.namelist():
        z.writestr(n, zi.read(n) + (b"#evil" if n.startswith("files/") else b""))
assert not ev.inspect_patch(zo.getvalue())["ok"]; print("rejected: tampered zip")
assert not ev.inspect_patch(b"not a zip")["ok"] and not ev.inspect_patch(b"")["ok"]
# بمب فشرده‌سازی
bomb = io.BytesIO()
with zipfile.ZipFile(bomb, "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("manifest.json", "{}"); z.writestr("files/app/x.txt", b"0" * 20_000_000)
assert not ev.inspect_patch(bomb.getvalue())["ok"]; print("rejected: zip bomb")
# سقف حجم کد
rp = fresh_report(); big = mk({"app/bigdata.txt": "x" * 2_400_000, "app/bigdata2.txt": "y" * 2_400_000}, rp)
r = ev.inspect_patch(big); assert not r["ok"] and "سقف" in " ".join(r["errors"]); print("rejected: code size cap")

# ---------- وصله‌ای که تست‌ها رو می‌شکنه: نوشتارش درسته ولی اتاق تست رد می‌کنه
breaker = read("app/cfgscan.py") + "\nraise ImportError('boom')\n"
reject("breaks tests (gate)", {"app/cfgscan.py": breaker}, "تست رد شد", run=True)
assert not (D / "evolve" / "stage").exists() or not any((D / "evolve" / "stage").iterdir())

# ---------- برگشت
ok, msg = ev.rollback("last"); assert ok, msg
assert "patched-by-test" not in read("app/cfgscan.py") and not (T / "app" / "extra_mod.py").exists()
assert sha(T / "app" / "cfgscan.py") == before
assert not ev.rollback("last")[0]
print("rollback last ok")
# دو وصله روی هم و برگشت کامل به اصلی
for tag in ("A", "B"):
    rp = fresh_report(); (T / "app" / "report.py").write_text(read("app/report.py").replace("\n#changed\n", "\n"), encoding="utf-8") if tag == "A" else None
    ev.init(T, D)
    cur = read("app/cfgscan.py")
    assert ev.apply_patch(mk({"app/cfgscan.py": cur + f"\n# MARK_{tag}\n"}, rp), wait=True) and ev.JOB["state"] == "done", ev.JOB
ok, msg = ev.rollback("original"); assert ok, msg
assert not any(a["active"] for a in ev.status()["applied"]) and "MARK_A" not in read("app/cfgscan.py") and "MARK_B" not in read("app/cfgscan.py")
print("rollback original ok")

# ---------- هماهنگی با فایل‌های بیرونی: اگه فایل‌ها برگشتن، وصله فعال حساب نمی‌شه
rp = fresh_report(); cur = read("app/cfgscan.py")
assert ev.apply_patch(mk({"app/cfgscan.py": cur + "\n# MARK_C\n"}, rp), wait=True) and ev.JOB["state"] == "done"
assert any(a["active"] for a in ev.status()["applied"])
(T / "app" / "cfgscan.py").write_text(cur, encoding="utf-8")  # مثل بازکردن دوباره‌ی نسخه توسط راه‌انداز
ev.init(T, D); assert not any(a["active"] for a in ev.status()["applied"]); print("external revert detected")
(T / "version.txt").write_text("v2", encoding="utf-8"); ev.init(T, D)   # نسخه‌ی تازه: همه‌چیز پاک
(T / "version.txt").write_text("v2", encoding="utf-8"); ev.init(T, D)
assert not (D / "evolve" / "original").exists() and ev.status()["applied"] == []; print("new app version resets patches")

# ---------- محافظ بوت: وصله‌ی تأییدنشده که سه بار بالا نیاد، خودکار برمی‌گرده
(T / "version.txt").unlink()
ev.init(T, D)
rp = fresh_report(); cur = read("app/cfgscan.py")
assert ev.apply_patch(mk({"app/cfgscan.py": cur + "\n# MARK_D\n"}, rp), wait=True) and ev.JOB["state"] == "done", ev.JOB
os.environ.pop("CFG_NO_RESTART")
import runpy
calls = []
runpy_run = runpy.run_path; runpy.run_path = lambda *a, **k: calls.append(a)  # به‌جای اجرای دوباره‌ی cfgweb فقط ثبت می‌کنیم
try:
    for i in range(3):
        ev.early_guard(T, D); assert "# MARK_D" in read("app/cfgscan.py"), i
    try:
        ev.early_guard(T, D); raise SystemExit("guard did not roll back")
    except SystemExit as e:
        assert e.code == 0
    assert "# MARK_D" not in read("app/cfgscan.py") and calls; print("boot guard rolled back after 3 failed starts")
finally:
    runpy.run_path = runpy_run; os.environ["CFG_NO_RESTART"] = "1"

# ---------- سقف حجم: پشتیبان‌ها و گزارش‌های قدیمی اول پاک می‌شن
ev.init(T, D)
for i in range(6):
    rp = fresh_report(); cur = read("app/cfgscan.py")
    assert ev.apply_patch(mk({"app/cfgscan.py": cur + f"\n# L{i}\n", f"app/pad{i}.txt": "z" * 1500}, rp), wait=True) and ev.JOB["state"] == "done", (i, ev.JOB)
vs = sorted((D / "evolve" / "versions").iterdir()); assert len(vs) <= ev.KEEP, len(vs)
os.makedirs(D / "evolve" / "reports", exist_ok=True)
for i in range(8):
    (D / "evolve" / "reports" / f"r{i}.ctreport").write_bytes(b"x" * 900_000); time.sleep(0.01)
ev.set_cap(5)
assert ev.usage()["evolve"] <= 5_000_000 + 600_000, ev.usage()  # فایل original و state هیچ‌وقت پاک نمی‌شن
assert (D / "evolve" / "original").exists() and (D / "evolve" / "state.json").exists()
print("budget enforced:", ev.usage()["evolve"] // 1000, "KB")

# ---------- تنظیم خودکار: فقط live و workers، نه rate؛ بین ۰٫۶ تا ۱٫۴
base = {"rate": 15, "live": 10, "workers": 40}
assert ev.tune_params(base) == base
for _ in range(14): ev.tune_note(100, 1, None)       # سرور سالم پیدا نمی‌شه
p = ev.tune_params(base); assert p["rate"] == 15 and p["live"] > 10 and ev.status()["tune"]["m"] <= ev.TUNE_MAX, (p, ev.status()["tune"])
hi = ev.status()["tune"]["m"]
for _ in range(60): ev.tune_note(100, 40, 8.0)       # خیلی راحت پیدا می‌شه
lo = ev.status()["tune"]["m"]; p = ev.tune_params(base)
assert lo < hi and lo >= ev.TUNE_MIN and p["live"] < 10 and p["rate"] == 15, (hi, lo, p)
ev.set_autotune(False); assert ev.tune_params(base) == base
print("autotune ok: up to", hi, "down to", lo)
print("ALL OK")
