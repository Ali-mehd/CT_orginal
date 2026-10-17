package main

import (
	"archive/zip"
	"bytes"
	_ "embed"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

//go:embed payload.zip
var payload []byte

// نسخه‌ی بسته؛ موقع بیلد با -ldflags "-X main.ver=..." پر می‌شه. اگه عوض بشه، فایل‌ها دوباره باز می‌شن.
var ver = "dev"

const pyExe = "pythonw.exe"

var logPath string

// logf: ردپای کوتاه برای عیب‌یابی (زمان و اتفاق؛ هیچ آدرس سرور یا رمزی نیست).
func logf(format string, args ...any) {
	if logPath == "" {
		return
	}
	if st, err := os.Stat(logPath); err == nil && st.Size() > 200_000 {
		os.Remove(logPath)
	}
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s %s\n", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprintf(format, args...))
}

var dirs = []string{"python", "xray", "singbox", "app"} // پوشه‌ی data (تنظیمات و سرورهای ذخیره‌شده) دست نمی‌خوره

func isFile(p string) bool { st, err := os.Stat(p); return err == nil && !st.IsDir() }

func unpack(root string) error {
	zr, err := zip.NewReader(bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return err
	}
	for _, d := range dirs {
		if err := os.RemoveAll(filepath.Join(root, d)); err != nil {
			return fmt.Errorf("برنامه هنوز در حال اجراست یا فایل‌هاش قفله. اول ConfigTool رو کامل ببند (از دکمه‌ی خروج)، بعد دوباره اجرا کن.\n(%v)", err)
		}
	}
	absRoot, _ := filepath.Abs(root)
	for _, f := range zr.File {
		target := filepath.Join(absRoot, filepath.FromSlash(f.Name))
		if target != absRoot && !strings.HasPrefix(target, absRoot+string(os.PathSeparator)) {
			return fmt.Errorf("فایل نامعتبر در بسته: %s", f.Name)
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		mode := os.FileMode(0o644)
		if f.Mode()&0o111 != 0 {
			mode = 0o755
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
		if err != nil {
			rc.Close()
			return err
		}
		_, err = io.Copy(out, rc)
		rc.Close()
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func startCore(root, py string) (*app, error) {
	dataDir := filepath.Join(root, "data")
	os.MkdirAll(dataDir, 0o755)
	urlFile := filepath.Join(dataDir, "url.txt")
	os.Remove(urlFile)
	exe, _ := os.Executable()
	cmd := exec.Command(py, "-X", "utf8", filepath.Join(root, "app", "cfgweb.py"))
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "PYTHONUTF8=1", "CFG_EXE_DIR="+filepath.Dir(exe), "CFG_EMBEDDED=1", "CFG_DATA="+dataDir)
	hide(cmd)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	a := &app{cmd: cmd, dataDir: dataDir, exited: make(chan struct{})}
	go func() { cmd.Wait(); close(a.exited) }()
	u, gone, err := waitURL(urlFile, a.exited, 40*time.Second)
	if err != nil {
		killCore(a)
		return nil, err
	}
	a.setURL(u)
	a.orphan = gone
	return a, nil
}

func install(root, vf string) error {
	os.Remove(vf)
	if err := unpack(root); err != nil {
		return err
	}
	return os.WriteFile(vf, []byte(ver), 0o644)
}

func main() {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		base = os.TempDir()
	}
	root := filepath.Join(base, "ConfigTool")
	os.MkdirAll(root, 0o755)
	logPath = filepath.Join(root, "launcher.log")
	if alreadyRunning() {
		if showExisting() { // نسخه‌ی دیگه‌ای باز است (شاید در پس‌زمینه)؛ همان پنجره را نشان بده
			logf("another instance: window shown")
			return
		}
		logf("another instance holds the lock but has no window; continuing")
	}
	logf("start ver=%s", ver)
	py := filepath.Join(root, "python", pyExe)
	vf := filepath.Join(root, "version.txt")
	cur, err := os.ReadFile(vf)
	if err != nil || strings.TrimSpace(string(cur)) != ver || !isFile(py) {
		logf("extracting payload")
		if err := install(root, vf); err != nil {
			logf("extract failed: %v", err)
			msg("باز کردن فایل‌های برنامه ناموفق بود:\n" + err.Error() + "\n\nگزارش: " + logPath)
			os.Exit(1)
		}
	}
	a, err := startCore(root, py)
	if err != nil { // یک بار خودترمیمی: فایل‌ها (شاید نیمه‌حذف‌شده) را دوباره باز کن
		logf("core failed: %v; re-extracting once", err)
		if ierr := install(root, vf); ierr == nil {
			a, err = startCore(root, py)
		} else {
			logf("re-extract failed: %v", ierr)
		}
	}
	if err != nil {
		logf("giving up: %v", err)
		msg(err.Error() + "\n\nگزارش برای عیب‌یابی: " + logPath)
		os.Exit(1)
	}
	logf("core ready orphan=%v", a.orphan)
	if !runGUI(a) {
		logf("fallback: opened in browser")
		return // پنجره‌ی داخلی ساخته نشد؛ در مرورگر باز شد و برنامه ادامه می‌ده
	}
	if !a.orphan {
		select {
		case <-a.exited:
		default:
			a.requestQuit()
			select {
			case <-a.exited:
			case <-time.After(8 * time.Second):
				logf("core did not exit in time; killing")
				killCore(a)
			}
		}
	}
	logf("exit")
}
