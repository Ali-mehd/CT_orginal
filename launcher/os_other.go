//go:build !windows

package main

import (
	"fmt"
	"os"
	"os/exec"
)

func msg(text string) { fmt.Fprintln(os.Stderr, text) }

func hide(c *exec.Cmd) {}

func killCore(a *app) {
	if a != nil && a.cmd != nil && a.cmd.Process != nil {
		a.cmd.Process.Kill()
	}
}
