//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"time"
	"unsafe"

	"github.com/jchv/go-webview2"
	"golang.org/x/sys/windows"
)

const windowTitle = "ابزار اتصال"

var (
	user32            = windows.NewLazySystemDLL("user32.dll")
	pFindWindowW      = user32.NewProc("FindWindowW")
	pShowWindow       = user32.NewProc("ShowWindow")
	pSetForeground    = user32.NewProc("SetForegroundWindow")
	pSetWindowLongPtr = user32.NewProc("SetWindowLongPtrW")
	pCallWindowProc   = user32.NewProc("CallWindowProcW")
	pMessageBox       = user32.NewProc("MessageBoxW")
	pGetSystemMetrics = user32.NewProc("GetSystemMetrics")
	pGetDpiForSystem  = user32.NewProc("GetDpiForSystem")
	mutexHandle       windows.Handle

	shell32          = windows.NewLazySystemDLL("shell32.dll")
	pShellNotifyIcon = shell32.NewProc("Shell_NotifyIconW")
	pGetModuleHandle = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetModuleHandleW")
	pLoadImage       = user32.NewProc("LoadImageW")
	pCreatePopupMenu = user32.NewProc("CreatePopupMenu")
	pAppendMenu      = user32.NewProc("AppendMenuW")
	pTrackPopupMenu  = user32.NewProc("TrackPopupMenu")
	pDestroyMenu     = user32.NewProc("DestroyMenu")
	pGetCursorPos    = user32.NewProc("GetCursorPos")
	pPostMessage     = user32.NewProc("PostMessageW")
	pRegisterMsg     = user32.NewProc("RegisterWindowMessageW")
)

const wmTray = 0x8001 // پیام آیکون نوار اعلان (WM_APP+1)

// notifyIconData: چیدمان NOTIFYICONDATAW ویندوز (۶۴ بیتی).
type notifyIconData struct {
	CbSize           uint32
	HWnd             uintptr
	UID              uint32
	UFlags           uint32
	UCallbackMessage uint32
	HIcon            uintptr
	SzTip            [128]uint16
	DwState          uint32
	DwStateMask      uint32
	SzInfo           [256]uint16
	UVersion         uint32
	SzInfoTitle      [64]uint16
	DwInfoFlags      uint32
	GuidItem         windows.GUID
	HBalloonIcon     uintptr
}

// tray: آیکون کنار ساعت. وقتی وصله قرمزه، وقتی وصل نیست همون رنگ همیشگی.
type tray struct {
	hwnd        uintptr
	normal, red uintptr
	active      bool
	added       bool
}

func loadIcon(id uintptr) uintptr {
	inst, _, _ := pGetModuleHandle.Call(0)
	cx, _, _ := pGetSystemMetrics.Call(49)                  // SM_CXSMICON
	cy, _, _ := pGetSystemMetrics.Call(50)                  // SM_CYSMICON
	h, _, _ := pLoadImage.Call(inst, id, 1, cx, cy, 0x8000) // IMAGE_ICON, LR_SHARED
	return h
}

func (t *tray) data() *notifyIconData {
	d := &notifyIconData{HWnd: t.hwnd, UID: 1, UFlags: 0x7, UCallbackMessage: wmTray, HIcon: t.normal} // MESSAGE|ICON|TIP
	tip := windowTitle + " — بدون اتصال"
	if t.active {
		d.HIcon = t.red
		tip = windowTitle + " — متصل"
	}
	u, _ := windows.UTF16FromString(tip)
	copy(d.SzTip[:127], u)
	d.CbSize = uint32(unsafe.Sizeof(*d))
	return d
}

func (t *tray) add() {
	pShellNotifyIcon.Call(0, uintptr(unsafe.Pointer(t.data()))) // NIM_ADD
	t.added = true
}

func (t *tray) set(active bool) {
	if !t.added || t.active == active {
		return
	}
	t.active = active
	pShellNotifyIcon.Call(1, uintptr(unsafe.Pointer(t.data()))) // NIM_MODIFY
}

func (t *tray) remove() {
	if t.added {
		pShellNotifyIcon.Call(2, uintptr(unsafe.Pointer(t.data()))) // NIM_DELETE
		t.added = false
	}
}

// menu: منوی راست‌کلیک؛ ۱ = باز کردن، ۲ = بستن کامل، ۰ = هیچ.
func (t *tray) menu() int {
	m, _, _ := pCreatePopupMenu.Call()
	if m == 0 {
		return 0
	}
	defer pDestroyMenu.Call(m)
	open, _ := windows.UTF16PtrFromString("باز کردن")
	quit, _ := windows.UTF16PtrFromString("بستن کامل")
	pAppendMenu.Call(m, 0, 1, ptr(open))
	pAppendMenu.Call(m, 0, 2, ptr(quit))
	var pt struct{ X, Y int32 }
	pGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	pSetForeground.Call(t.hwnd)                                                                      // بدون این، منو با کلیک بیرون بسته نمی‌شود
	cmd, _, _ := pTrackPopupMenu.Call(m, 0x100|0x2|0x20, uintptr(pt.X), uintptr(pt.Y), 0, t.hwnd, 0) // RETURNCMD|RIGHTBUTTON|BOTTOMALIGN
	pPostMessage.Call(t.hwnd, 0, 0, 0)
	return int(cmd)
}

func ptr(p *uint16) uintptr { return uintptr(unsafe.Pointer(p)) }

// alreadyRunning: فقط یک نسخه‌ی برنامه باز باشد.
func alreadyRunning() bool {
	name, _ := windows.UTF16PtrFromString("Local\\ConfigToolLauncher")
	h, err := windows.CreateMutex(nil, false, name)
	mutexHandle = h
	return err == windows.ERROR_ALREADY_EXISTS
}

// showExisting: پنجره‌ی نسخه‌ی در حال اجرا (حتی اگر در پس‌زمینه پنهان است) را نشان می‌دهد.
func showExisting() bool {
	t, _ := windows.UTF16PtrFromString(windowTitle)
	hwnd, _, _ := pFindWindowW.Call(0, ptr(t))
	if hwnd == 0 {
		return false
	}
	pShowWindow.Call(hwnd, 9) // SW_RESTORE
	pShowWindow.Call(hwnd, 5) // SW_SHOW
	pSetForeground.Call(hwnd)
	return true
}

func dpiScale() float64 {
	if pGetDpiForSystem.Find() != nil {
		return 1
	}
	d, _, _ := pGetDpiForSystem.Call()
	if d == 0 {
		return 1
	}
	return float64(d) / 96
}

// askClose: پرسش قبل از بسته‌شدن؛ "bg" پس‌زمینه، "quit" بستن کامل، "stay" برگشت.
func askClose(hwnd uintptr, a *app) string {
	now := "الان اتصالی برقرار نیست."
	switch a.stage() {
	case "connected":
		now = "الان به اینترنت وصلی."
	case "running":
		now = "جستجو در حال انجامه."
	}
	text := now + "\nمی‌خوای برنامه در پس‌زمینه به کارش ادامه بده؟\n\n" +
		"بله = ادامه در پس‌زمینه (برای دیدن دوباره‌ی پنجره، روی آیکون کنار ساعت کلیک کن)\n" +
		"خیر = بستن کامل و قطع اتصال\nانصراف = برگشت به برنامه"
	t, _ := windows.UTF16PtrFromString(text)
	c, _ := windows.UTF16PtrFromString(windowTitle)
	// YESNOCANCEL | ICONQUESTION | SETFOREGROUND | RTLREADING ؛ ۶ بله، ۷ خیر، ۲ انصراف
	r, _, _ := pMessageBox.Call(hwnd, ptr(t), ptr(c), 0x3|0x20|0x10000|0x100000)
	switch r {
	case 7:
		return "quit"
	case 2:
		return "stay"
	}
	return "bg" // هر چیز غیرمنتظره: اتصال نمونه قطع نشه
}

// runGUI: پنجره‌ی مستقل با WebView2. false یعنی ساخته نشد و در مرورگر باز شد.
func runGUI(a *app) bool {
	sc := dpiScale()
	w, h := int(470*sc), int(900*sc)
	if sh, _, _ := pGetSystemMetrics.Call(1); sh > 0 { // SM_CYSCREEN
		if max := int(sh) - int(90*sc); max > 400 && h > max {
			h = max
		}
	}
	wv := webview2.NewWithOptions(webview2.WebViewOptions{
		DataPath:  filepath.Join(a.dataDir, "webview"),
		AutoFocus: true,
		WindowOptions: webview2.WindowOptions{
			Title: windowTitle, Width: uint(w), Height: uint(h), IconId: 1, Center: true,
		},
	})
	if wv == nil {
		exec.Command("rundll32", "url.dll,FileProtocolHandler", a.url).Start()
		msg("اجزای WebView2 ویندوز پیدا نشد؛ برنامه در مرورگر باز شد. برای خروج کامل از دکمه‌ی «خروج» داخل برنامه استفاده کن.")
		return false
	}
	defer wv.Destroy()
	hwnd := uintptr(wv.Window())
	hideWin := func() { pShowWindow.Call(hwnd, 0) } // SW_HIDE
	showWin := func() {
		pShowWindow.Call(hwnd, 9) // SW_RESTORE
		pShowWindow.Call(hwnd, 5) // SW_SHOW
		pSetForeground.Call(hwnd)
	}
	wv.Bind("goHide", func() { wv.Dispatch(hideWin) })
	tr := &tray{hwnd: hwnd, normal: loadIcon(1), red: loadIcon(2)}
	quitFlow := func() {
		hideWin()
		logf("quit requested")
		go a.requestQuit()
		// تضمین بسته‌شدن کامل: اگه هسته تا ۱۰ ثانیه نبست، قطعی ببند و خارج شو (پردازه‌ی بی‌پنجره نمونه)
		time.AfterFunc(10*time.Second, func() {
			logf("quit timeout: killing core and exiting")
			killCore(a)
			tr.remove()
			os.Exit(0)
		})
		if a.orphan {
			go func() { time.Sleep(3 * time.Second); wv.Dispatch(wv.Terminate) }()
		}
	}
	taskbarCreated, _, _ := pRegisterMsg.Call(ptr(func() *uint16 { p, _ := windows.UTF16PtrFromString("TaskbarCreated"); return p }()))

	var orig uintptr
	cb := windows.NewCallback(func(h, m, wp, lp uintptr) uintptr {
		if m == 0x0010 { // WM_CLOSE: ضربدر، Alt+F4 یا بستن از نوار وظیفه
			switch askClose(h, a) {
			case "quit":
				quitFlow()
			case "bg":
				hideWin()
			}
			return 0 // خودمان تصمیم گرفتیم؛ بستن پیش‌فرض انجام نشود
		}
		if m == wmTray {
			switch lp & 0xFFFF {
			case 0x0202, 0x0203: // کلیک چپ (یا دوبار کلیک): نشان‌دادن پنجره
				showWin()
			case 0x0205: // کلیک راست: منو
				switch tr.menu() {
				case 1:
					showWin()
				case 2:
					quitFlow()
				}
			}
			return 0
		}
		if taskbarCreated != 0 && m == taskbarCreated { // explorer دوباره بالا آمده: آیکون را دوباره بگذار
			tr.added = false
			tr.add()
			return 0
		}
		r, _, _ := pCallWindowProc.Call(orig, h, m, wp, lp)
		return r
	})
	orig, _, _ = pSetWindowLongPtr.Call(hwnd, ^uintptr(3), cb) // GWLP_WNDPROC = -4

	if !a.orphan {
		go func() {
			<-a.exited
			if !a.isQuitting() && a.cmd.ProcessState != nil && a.cmd.ProcessState.ExitCode() != 0 {
				msg("هسته‌ی برنامه ناگهانی بسته شد.")
			}
			wv.Dispatch(wv.Terminate)
		}()
	}
	tr.add()
	defer tr.remove()
	stop := make(chan struct{})
	defer close(stop)
	go func() { // رنگ آیکون: قرمز وقتی وصله
		for {
			select {
			case <-stop:
				return
			case <-time.After(2 * time.Second):
			}
			act := a.stage() == "connected"
			wv.Dispatch(func() { tr.set(act) })
		}
	}()
	wv.Navigate(a.url)
	wv.Run()
	return true
}
