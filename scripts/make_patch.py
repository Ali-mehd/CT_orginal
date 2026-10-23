#!/usr/bin/env python3
"""ساخت فایل وصله (.ctpatch) از روی یک گزارش کاربر. (ابزار نویسنده؛ داخل برنامه‌ی کاربر نمی‌ره.)

  python3 scripts/make_patch.py --report گزارش.ctreport --title "عنوان کوتاه" --notes "توضیح ساده" \
      --out خروجی.ctpatch  app/cfgscan.py=/مسیر/فایل-تازه.py  [app/ui.html=...]

فایل‌هایی که توی مخزن هست «جایگزینی» حساب می‌شن؛ نسخه‌ی مخزن باید با نسخه‌ای که کاربر داره (طبق گزارش) یکی باشه."""
import argparse, hashlib, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))
import evolve  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--repo", default=str(Path(__file__).resolve().parent.parent))
ap.add_argument("--report", required=True)
ap.add_argument("--title", required=True)
ap.add_argument("--notes", default="")
ap.add_argument("--out", required=True)
ap.add_argument("--force", action="store_true", help="با وجود اختلاف نسخه ادامه بده")
ap.add_argument("edits", nargs="+", help="مسیر-داخل-برنامه=مسیر-فایل-تازه")
a = ap.parse_args()
rep = evolve.open_report(Path(a.report).read_text(encoding="utf-8"))
theirs = {f["path"]: f["sha256"] for f in rep["code"]}
edits = {}
for e in a.edits:
    dst, _, src = e.partition("=")
    edits[dst] = Path(src).read_bytes()
bad = [p for p in edits if (Path(a.repo) / p).is_file() and theirs.get(p) != hashlib.sha256((Path(a.repo) / p).read_bytes()).hexdigest()]
if bad and not a.force:
    sys.exit("این فایل‌ها توی مخزن با نسخه‌ی کاربر فرق دارن (وصله روی کاربر نمی‌شینه): " + ", ".join(bad))
data = evolve.build_patch(a.repo, edits, rep["id"], a.title, a.notes, rep["app"]["ver"])
Path(a.out).write_bytes(data)
print("OK", a.out, len(data), "bytes; report", rep["id"])
