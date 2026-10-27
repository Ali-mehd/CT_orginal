"""حذف کامل: اسکریپت امن و کامل؛ محیطِ اتاق تستِ وصله پاک‌سازی‌شده؛ لانچر پوشه‌ی tests رو هم تازه می‌کنه."""
import sys, os, tempfile, re
os.environ["CFG_DATA"] = tempfile.mkdtemp(); sys.path.insert(0, ".")
import cfgweb as W, evolve as E

root = r"C:\Users\jahan\AppData\Local\ConfigTool"
txt = W.build_uninstall_cmd(root, r"C:\Users\jahan\Downloads\ConfigTool.exe")
assert txt and txt.startswith("@echo off") and "chcp 65001" in txt
assert f'rmdir /s /q "{root}"' in txt and "for /L %%i in (1,1,15)" in txt          # چند بار تلاش
assert "StartsWith('" + root + "\\'" in txt and "CommandLine.Contains('" + root + "')" in txt   # پردازه‌های قفل‌کننده (xray، WebView2) بسته می‌شن
assert 'del /f /q "C:\\Users\\jahan\\Downloads\\ConfigTool.exe"' in txt              # خودِ فایل اجرایی
assert "ctgate*" in txt and txt.rstrip().endswith('del "%~f0"')                      # پوشه‌های موقت اتاق تست + خودحذفی
# امنیت: مسیرِ مشکوک ← None؛ exe داخل پوشه‌ی برنامه/سیستم/غیر exe حذف نمی‌شه
assert W.build_uninstall_cmd(r"C:\x & calc\ConfigTool") is None and W.build_uninstall_cmd("C:\\") is None
assert W.build_uninstall_cmd(root, root + r"\app\x.exe").count("del /f /q") == 0
assert W.build_uninstall_cmd(root, r"C:\Windows\System32\cmd.exe").count("del /f /q") == 0
assert W.build_uninstall_cmd(root, r"C:\Users\a\Downloads\notes.txt").count("del /f /q") == 0
assert W.build_uninstall_cmd(root, r"C:\Users\a\a&b.exe").count("del /f /q") == 0
assert W.build_uninstall_cmd(root).count("del /f /q") == 0
print("1) uninstall script: retries, kills locking processes, removes exe + temp rooms, self-deletes, refuses unsafe paths OK")

# محیط اتاق تست: توکن و پروکسی کاربر نمی‌رسه
os.environ.update(MY_SECRET_TOKEN="x", HTTPS_PROXY="http://evil:1", GITHUB_TOKEN="g")
env = E._gate_env("/tmp/ct_room")
assert "MY_SECRET_TOKEN" not in env and "HTTPS_PROXY" not in env and "GITHUB_TOKEN" not in env
assert env["CFG_DATA"] == "/tmp/ct_room" and env["PYTHONNOUSERSITE"] == "1" and env["TEMP"] == "/tmp/ct_room"
print("2) evolve test room gets a scrubbed environment (no secrets/proxy from the user's shell) OK")

# لانچر: پوشه‌ی tests هم همگام و مسیر exe به هسته می‌رسه
go = open("../launcher/main.go", encoding="utf-8").read()
assert '"app", "tests"}' in go and '"CFG_EXE="+exe' in go
print("3) launcher refreshes tests/ on update and passes its exe path to the core OK")
print("ALL OK")
