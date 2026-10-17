//go:build windows

package main

import (
	"os/exec"
	"strconv"
	"syscall"
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
