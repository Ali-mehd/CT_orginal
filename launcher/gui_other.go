//go:build !windows

package main

import (
	"os"
	"strconv"
	"time"
)

func alreadyRunning() bool { return false }
func showExisting() bool   { return false }

// runGUI (فقط برای تست روی لینوکس): بعد از CT_TEST_WAIT ثانیه مثل ضربدر + «بستن کامل» رفتار می‌کند.
func runGUI(a *app) bool {
	n, _ := strconv.Atoi(os.Getenv("CT_TEST_WAIT"))
	select {
	case <-a.exited:
	case <-time.After(time.Duration(n) * time.Second):
		println("stage=" + a.stage())
		a.requestQuit()
		select {
		case <-a.exited:
		case <-time.After(10 * time.Second):
		}
	}
	return true
}
