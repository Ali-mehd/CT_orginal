"""cfgres (کنترل منابع اندروید): عقب‌نشینی فوری، رشد آروم با هیسترزیس، سیگنال نامعلوم محدودیت نمی‌سازه، کف و سقف."""
import sys, importlib.util, os
here = os.path.dirname(os.path.abspath(__file__))
for d in (".", os.path.join(here, "..", "app"), os.path.join(here, "..", "app", "src", "main", "python")):
    if os.path.exists(os.path.join(d, "cfgres.py")): sys.path.insert(0, d); break
else:
    print("cfgres.py در این نسخه نیست (فقط اندروید)؛ تست رد شد"); print("ALL OK"); sys.exit(0)
import cfgres as R

t = [1000.0]; G = R.Governor(clock=lambda: t[0])
P = dict(rate=10.0, live=8, workers=24)
ok_env = dict(ram_total_mb=8000, ram_avail_mb=5000, cores=8, thermal=0, batt_pct=80, batt_temp_c=30, charging=False, power_save=False, screen_on=True)
G.feed(ok_env); assert G.scale() == 1.0 and G.summary() == ""
assert G.apply(P)["live"] == R.BOOT_LIVE, "رم واقعیِ یک پردازه معلوم نیست؛ حدس نمی‌زنیم، از کم شروع می‌کنیم"
G.note_proc_mb(60); G.feed(ok_env); assert G.mem_live == int((5000 - max(400, 0.15 * 8000)) / (60 * R.MARGIN)) and G.apply(P)["live"] == 8
G.note_proc_mb(1500); G.feed(ok_env); assert G.apply(P)["live"] < 8, "پردازه‌ها سنگین شدن ⇒ هم‌زمانی کم می‌شه"
G.note_proc_mb(60); [G.note_proc_mb(60) for _ in range(30)]; G.feed(ok_env)
# ۱) نامعلوم: بدون سنسور دما نصف توان (قابل‌خاموش‌شدن)؛ بدون داده‌ی جاوا (PC) هیچ تغییری
G2 = R.Governor(clock=lambda: t[0]); G2.feed({}); assert G2.scale() == R.NO_THERMAL_CAP, "بدون هیچ سنسور دما: نصف توان (رفتار عمدی)"
G2 = R.Governor(clock=lambda: t[0]); G2.notemp = "full"; G2.feed({}); assert G2.scale() == 1.0 and G2.apply(P)["rate"] == 10.0, "سیگنال نامعلوم با انتخاب کاربر محدودیت نمی‌سازه"
G2 = R.Governor(); assert G2.scale() == 1.0 and G2.apply(P)["rate"] == 10.0, "تا جاوا داده نداده (PC) هیچ تغییری نمی‌ده"
# ۲) داغ‌شدن: فوراً پایین، ولی هیچ‌وقت زیر کف یا صفر
t[0] += 5; G.feed(dict(ok_env, thermal=4)); assert G.s <= R.FLOOR + 1e-9 and "داغ" in G.summary()
q = G.apply(P); assert q["live"] >= 1 and q["rate"] >= 1.5 and q["workers"] >= 4 and G.workers(10) >= 1
# ۳) خنک شد: تا ۴۵ ثانیه رشد نمی‌کنه، بعد پله‌پله (نه یک‌دفعه)
for _ in range(8): t[0] += 5; G.feed(ok_env)
assert G.s <= R.FLOOR + 1e-9, "در دوره‌ی صبر رشد نباید بکنه"
seen = []
for _ in range(40): t[0] += 5; G.feed(ok_env); seen.append(round(G.s, 3))
assert seen[-1] == 1.0 and all(b - a <= R.GROW_STEP + 1e-6 for a, b in zip(seen, seen[1:])), seen
# ۴) باتری کم، صرفه‌جویی، صفحه خاموش، رم کم، onTrimMemory
for env, word in ((dict(ok_env, batt_pct=8), "باتری"), (dict(ok_env, power_save=True), "صرفه"), (dict(ok_env, screen_on=False), "صفحه"),
                  (dict(ok_env, trim=15), "رم می")):
    g = R.Governor(clock=lambda: t[0]); g.feed(ok_env); t[0] += 5; g.feed(env); assert g.s < 0.8 and word in g.summary(), (word, g.s, g.summary())
# ۴b) رم کم: ضریب سرعت عوض نمی‌شه؛ سقف تست هم‌زمان از روی رم واقعیِ هر پردازه پایین میاد (تا ۱)
g = R.Governor(clock=lambda: t[0]); g.note_proc_mb(60); g.feed(dict(ok_env, ram_avail_mb=500)); assert g.mem_live == 1 and g.apply(P)["live"] == 1
# ۵) شارژ باتری کم رو محدودیت نمی‌کنه
g = R.Governor(clock=lambda: t[0]); g.feed(dict(ok_env, batt_pct=8, charging=True)); assert g.s == 1.0
# ۶) داده‌ی قدیمی (سرویس مرده) نادیده گرفته می‌شه
g = R.Governor(clock=lambda: t[0]); g.feed(dict(ok_env, thermal=4)); t[0] += R.STALE + 1; assert g.scale() == 1.0 and g.apply(P)["rate"] == 10.0 and g.summary() == ""
# ۷) ورودی خراب هیچ‌وقت خطا نمی‌ده
for bad in (None, [], "x", {"thermal": "abc", "ram_total_mb": float("nan"), "batt_temp_c": 1e99}): R.Governor().feed(bad)
# ۸) بدون هیچ سنسور دما: نصف توان (و به کاربر گفته می‌شه)؛ انتخاب کاربر «full» محدودیت رو برمی‌داره
nt = dict(ram_total_mb=8000, ram_avail_mb=5000, cores=8, batt_pct=80, charging=False, power_save=False, screen_on=True)
g = R.Governor(clock=lambda: t[0]); g.feed(nt); assert g.s <= R.NO_THERMAL_CAP + 1e-9 and g.temp_blind() and "نصف توان" in g.report_fa()
g = R.Governor(clock=lambda: t[0]); g.notemp = "full"; g.feed(nt); assert g.s == 1.0
g = R.Governor(clock=lambda: t[0]); g.feed(ok_env); assert not g.temp_blind() and g.sensors()["دمای باتری"] and g.report_fa().startswith("اندازه‌گیری می‌شه")
assert R.Governor().report_fa() == "هنوز داده‌ای از گوشی نرسیده."
print("cfgres governor OK"); print("ALL OK")
