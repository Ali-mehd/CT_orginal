package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// app: پردازه‌ی پایتون (هسته) و آدرس محلی‌ای که پنجره باید نشونش بده.
type app struct {
	cmd      *exec.Cmd
	dataDir  string
	url      string
	base     string
	token    string
	exited   chan struct{}
	orphan   bool // به نسخه‌ی در حال اجرای قبلی وصل شدیم (خود این پردازه‌ی پایتون بلافاصله تمام شد)
	mu       sync.Mutex
	quitting bool
}

func (a *app) setURL(u string) {
	a.url = u
	if i := strings.Index(u, "/?t="); i > 0 {
		a.base, a.token = u[:i], u[i+4:]
	}
}

func (a *app) isQuitting() bool { a.mu.Lock(); defer a.mu.Unlock(); return a.quitting }
func (a *app) setQuitting()     { a.mu.Lock(); a.quitting = true; a.mu.Unlock() }

func (a *app) call(method, path string, timeout time.Duration) ([]byte, error) {
	if a.base == "" {
		return nil, errors.New("no url")
	}
	var body io.Reader
	if method == "POST" {
		body = strings.NewReader("{}")
	}
	req, err := http.NewRequest(method, a.base+path+"?t="+a.token, body)
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{Timeout: timeout}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return b, errors.New(resp.Status)
	}
	return b, nil
}

// requestQuit: همان کاری که دکمه‌ی «خروج» داخل برنامه می‌کند (قطع اتصال، بازگردانی پروکسی، بستن).
func (a *app) requestQuit() {
	a.setQuitting()
	a.call("POST", "/api/quit", 5*time.Second)
}

// stage: وضعیت فعلی برنامه (connected / running / idle ...)؛ اگر نشد خالی.
func (a *app) stage() string {
	b, err := a.call("GET", "/api/state", 1500*time.Millisecond)
	if err != nil {
		return ""
	}
	var s struct {
		Stage string `json:"stage"`
	}
	json.Unmarshal(b, &s)
	return s.Stage
}

// waitURL: منتظر می‌ماند پایتون آدرس را در فایل بنویسد.
func waitURL(path string, exited <-chan struct{}, limit time.Duration) (string, bool, error) {
	end := time.Now().Add(limit)
	gone := false
	for time.Now().Before(end) {
		if b, err := os.ReadFile(path); err == nil && strings.Contains(string(b), "/?t=") {
			return strings.TrimSpace(string(b)), gone, nil
		}
		select {
		case <-exited:
			gone = true
			// یک شانس دیگر: شاید فایل درست همزمان با خروج نوشته شده
			time.Sleep(300 * time.Millisecond)
			if b, err := os.ReadFile(path); err == nil && strings.Contains(string(b), "/?t=") {
				return strings.TrimSpace(string(b)), true, nil
			}
			return "", true, errors.New("هسته‌ی برنامه بسته شد پیش از اینکه آماده بشه")
		case <-time.After(150 * time.Millisecond):
		}
	}
	return "", false, errors.New("هسته‌ی برنامه در زمان مناسب آماده نشد")
}
