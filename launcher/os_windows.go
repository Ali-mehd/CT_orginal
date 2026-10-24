//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

func msg(text string) {
	t, _ := syscall.UTF16PtrFromString(text)
	c, _ := syscall.UTF16PtrFromString("Config Tool")
	syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW").Call(0, uintptr(unsafe.Pointer(t)), uintptr(unsafe.Pointer(c)), 0x10)
}

func hide(c *exec.Cmd) {
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
}

// killCore: هسته و پردازه‌های فرزندش (xray و ...) را قطعی می‌بندد.
func killCore(a *app) {
	if a == nil || a.cmd == nil || a.cmd.Process == nil {
		return
	}
	c := exec.Command("taskkill", "/PID", strconv.Itoa(a.cmd.Process.Pid), "/T", "/F")
	hide(c)
	c.Run()
	a.cmd.Process.Kill()
}

// ── یک «کار» (Job Object) ویندوز: هسته و همه‌ی فرزندانش (xray و ...) توش می‌رن.
// با بسته‌شدن لانچر (حتی با End Task از تسک‌منیجر) ویندوز همه‌ی اون‌ها رو هم می‌بنده؛
// پس xray یتیم نمی‌مونه و فایل‌ها قفل نمی‌شن.
var (
	kernel32    = syscall.NewLazyDLL("kernel32.dll")
	pCreateJob  = kernel32.NewProc("CreateJobObjectW")
	pSetInfoJob = kernel32.NewProc("SetInformationJobObject")
	pAssignJob  = kernel32.NewProc("AssignProcessToJobObject")
	jobHandle   uintptr
)

type jobBasicLimit struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type jobExtLimit struct {
	Basic                 jobBasicLimit
	IO                    [6]uint64
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

const (
	jobKillOnClose  = 0x2000
	jobInfoExtended = 9
)

func setJobFlags(flags uint32) bool {
	if jobHandle == 0 {
		return false
	}
	var info jobExtLimit
	info.Basic.LimitFlags = flags
	r, _, _ := pSetInfoJob.Call(jobHandle, jobInfoExtended, uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info))
	return r != 0
}

// bindToJob: پردازه‌ی تازه‌شروع‌شده را (و هر چی بعداً می‌سازه) به کار «بستن همراه لانچر» می‌بنده.
func bindToJob(c *exec.Cmd) {
	if c == nil || c.Process == nil {
		return
	}
	if jobHandle == 0 {
		h, _, _ := pCreateJob.Call(0, 0)
		if h == 0 {
			return
		}
		jobHandle = h
		if !setJobFlags(jobKillOnClose) {
			jobHandle = 0
			return
		}
	}
	ph, err := syscall.OpenProcess(0x0100|0x0001, false, uint32(c.Process.Pid)) // PROCESS_SET_QUOTA | PROCESS_TERMINATE
	if err != nil {
		return
	}
	defer syscall.CloseHandle(ph)
	pAssignJob.Call(jobHandle, uintptr(ph)) // اگه نشد (مثلاً لانچر خودش توی کار قفل‌شده‌ایه) فقط همون راه قبلی (خروج/kill) می‌مونه
}

// releaseJob: لانچر قراره بره ولی هسته باید زنده بمونه (مثلاً وقتی در مرورگر باز شد)؛ دیگه با بسته‌شدن لانچر نمی‌میره.
func releaseJob() { setJobFlags(0) }

// killStale: پردازه‌های یتیم‌مونده از دفعه‌ی قبل (xray/pythonw داخل پوشه‌ی برنامه) رو می‌بنده تا فایل‌ها آزاد بشن.
// فقط پردازه‌هایی که فایل اجراییشون داخل همین پوشه‌ست؛ هیچ xray دیگه‌ای روی سیستم دست نمی‌خوره.
func killStale(root string) {
	r := strings.ReplaceAll(root, "'", "''")
	ps := fmt.Sprintf("Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and $_.ProcessId -ne %d -and $_.ExecutablePath.StartsWith('%s\\', [StringComparison]::OrdinalIgnoreCase) } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }", os.Getpid(), r)
	c := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", ps)
	hide(c)
	c.Run()
	time.Sleep(800 * time.Millisecond)
}
