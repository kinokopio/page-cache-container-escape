//go:build linux

package main

import (
	"bytes"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type crashMethod string

const (
	crashCgroupKill crashMethod = "cgroup-kill"
	crashSigint     crashMethod = "sigint"
	crashSigkill    crashMethod = "sigkill"
	crashKillAll    crashMethod = "kill-all"
	crashOOM        crashMethod = "oom"
)

type crashOptions struct {
	PID        int
	Timeout    time.Duration
	ProcRoot   string
	CgroupRoot string
}

type crashTriggerReport struct {
	CgroupKillOK     bool
	CgroupKillDetail string
	SIGINTLikelyOK   bool
	SIGINTDetail     string
}

func defaultCrashMethods() []crashMethod {
	return []crashMethod{crashCgroupKill, crashSigint, crashSigkill, crashKillAll}
}

func crashContainer(opts crashOptions) error {
	methods := defaultCrashMethods()
	for i, m := range methods {
		if i > 0 {
			fmt.Printf("    [*] Trying next crash method: %s\n", m)
		}
		err := triggerCrash(m, opts)
		if err == nil {
			return nil
		}
		fmt.Printf("    [-] %s: %v\n", m, err)
	}
	return fmt.Errorf("all crash methods failed")
}

func triggerCrash(m crashMethod, opts crashOptions) error {
	switch m {
	case crashCgroupKill:
		return triggerCgroupKill(opts)
	case crashSigint:
		return triggerSignal(opts, syscall.SIGINT, crashSigint)
	case crashSigkill:
		return triggerSignal(opts, syscall.SIGKILL, crashSigkill)
	case crashKillAll:
		return triggerKillAll(opts)
	case crashOOM:
		return triggerOOM(opts)
	default:
		return fmt.Errorf("unknown crash method: %s", m)
	}
}

// --- cgroup.kill ---

func triggerCgroupKill(opts crashOptions) error {
	killFile, ok := unifiedCgroupKillPath(opts.ProcRoot, opts.CgroupRoot, opts.PID)
	if !ok {
		return fmt.Errorf("cgroup v2 kill file not found")
	}
	if err := os.WriteFile(killFile, []byte("1"), 0644); err != nil {
		return fmt.Errorf("write %s: %w", killFile, err)
	}
	fmt.Printf("    [*] %s: wrote to %s\n", crashCgroupKill, killFile)
	return waitForProcExit(opts.ProcRoot, opts.PID, opts.Timeout)
}

func unifiedCgroupKillPath(procRoot, cgroupRoot string, pid int) (string, bool) {
	if procRoot == "" {
		procRoot = "/proc"
	}
	if cgroupRoot == "" {
		cgroupRoot = "/sys/fs/cgroup"
	}
	cgData, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return "", false
	}
	rel := unifiedCgroupPath(cgData)
	if rel == "" {
		return "", false
	}
	return filepath.Join(cgroupRoot, rel, "cgroup.kill"), true
}

func unifiedCgroupPath(data []byte) string {
	for _, line := range bytes.Split(data, []byte("\n")) {
		if bytes.HasPrefix(line, []byte("0::")) {
			return string(bytes.TrimPrefix(line, []byte("0::")))
		}
	}
	return ""
}

// --- signals ---

func triggerSignal(opts crashOptions, sig syscall.Signal, method crashMethod) error {
	pid := opts.PID
	if pid <= 0 {
		pid = 1
	}
	if err := syscall.Kill(pid, sig); err != nil {
		return fmt.Errorf("signal pid %d with %s: %w", pid, method, err)
	}
	fmt.Printf("    [*] %s: sent %s to pid %d\n", method, signalName(sig), pid)
	return waitForProcExit(opts.ProcRoot, pid, opts.Timeout)
}

func signalName(sig syscall.Signal) string {
	switch sig {
	case syscall.SIGINT:
		return "SIGINT"
	case syscall.SIGKILL:
		return "SIGKILL"
	default:
		return fmt.Sprintf("signal(%d)", sig)
	}
}

// --- kill-all ---

func triggerKillAll(opts crashOptions) error {
	procRoot := opts.ProcRoot
	if procRoot == "" {
		procRoot = "/proc"
	}
	pid := opts.PID
	if pid <= 0 {
		pid = 1
	}
	selfPID := os.Getpid()

	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return fmt.Errorf("read %s: %w", procRoot, err)
	}

	killed := 0
	for _, entry := range entries {
		p, ok := parseProcPID(entry.Name())
		if !ok || p == selfPID || p == pid {
			continue
		}
		if err := syscall.Kill(p, syscall.SIGKILL); err != nil {
			continue
		}
		killed++
	}
	if killed == 0 {
		return fmt.Errorf("no process killed")
	}
	fmt.Printf("    [*] %s: killed %d processes (excluding pid %d and self)\n", crashKillAll, killed, pid)
	return waitForProcExit(procRoot, pid, opts.Timeout)
}

func parseProcPID(name string) (int, bool) {
	if name == "" || strings.Trim(name, "0123456789") != "" {
		return 0, false
	}
	p, err := strconv.Atoi(name)
	return p, err == nil && p > 0
}

func inspectCrashTrigger(opts crashOptions) crashTriggerReport {
	pid := opts.PID
	if pid <= 0 {
		pid = 1
	}
	report := crashTriggerReport{}
	if killFile, ok := unifiedCgroupKillPath(opts.ProcRoot, opts.CgroupRoot, pid); ok {
		if err := canWriteFile(killFile); err == nil {
			report.CgroupKillOK = true
			report.CgroupKillDetail = killFile
		} else {
			report.CgroupKillDetail = fmt.Sprintf("%s (%v)", killFile, err)
		}
	} else {
		report.CgroupKillDetail = "cgroup.kill not found"
	}

	ok, detail := pidHandlesSignal(opts.ProcRoot, pid, syscall.SIGINT)
	report.SIGINTLikelyOK = ok
	report.SIGINTDetail = detail
	return report
}

func canWriteFile(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	return f.Close()
}

func pidHandlesSignal(procRoot string, pid int, sig syscall.Signal) (bool, string) {
	if procRoot == "" {
		procRoot = "/proc"
	}
	statusPath := filepath.Join(procRoot, strconv.Itoa(pid), "status")
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return false, fmt.Sprintf("read %s: %v", statusPath, err)
	}
	ignored, _ := signalMaskField(data, "SigIgn")
	caught, _ := signalMaskField(data, "SigCgt")
	bit := uint64(1) << uint(sig-1)
	switch {
	case ignored&bit != 0:
		return false, fmt.Sprintf("%s is ignored by pid %d", signalName(sig), pid)
	case caught&bit != 0:
		return true, fmt.Sprintf("%s is caught by pid %d (clean shutdown likely)", signalName(sig), pid)
	default:
		return false, fmt.Sprintf("%s is not caught by pid %d", signalName(sig), pid)
	}
}

func signalMaskField(status []byte, field string) (uint64, bool) {
	prefix := []byte(field + ":")
	for _, line := range bytes.Split(status, []byte("\n")) {
		if !bytes.HasPrefix(line, prefix) {
			continue
		}
		parts := strings.Fields(string(line))
		if len(parts) < 2 {
			return 0, false
		}
		value, err := strconv.ParseUint(parts[1], 16, 64)
		return value, err == nil
	}
	return 0, false
}

// --- oom ---

const (
	oomTargetScore = 1000
	oomSelfScore   = -1000
	oomChunkBytes  = 16 << 20 // 16 MiB
	oomMaxFallback = 512 << 20
)

func triggerOOM(opts crashOptions) error {
	procRoot := opts.ProcRoot
	if procRoot == "" {
		procRoot = "/proc"
	}
	cgroupRoot := opts.CgroupRoot
	if cgroupRoot == "" {
		cgroupRoot = "/sys/fs/cgroup"
	}
	pid := opts.PID
	if pid <= 0 {
		pid = 1
	}

	if err := writeOOMScoreAdj(procRoot, pid, oomTargetScore); err != nil {
		return fmt.Errorf("set target oom_score_adj: %w", err)
	}
	if err := writeOOMScoreAdj(procRoot, os.Getpid(), oomSelfScore); err != nil {
		return fmt.Errorf("set self oom_score_adj: %w", err)
	}

	maxBytes, err := oomMemoryLimit(procRoot, cgroupRoot, pid)
	if err != nil {
		return fmt.Errorf("determine memory limit: %w", err)
	}
	fmt.Printf("    [*] %s: target pid %d oom_score_adj=%d, memory limit %d bytes\n", crashOOM, pid, oomTargetScore, maxBytes)

	var held [][]byte
	var allocated uint64
	for allocated < maxBytes {
		size := uint64(oomChunkBytes)
		if remaining := maxBytes - allocated; remaining < size {
			size = remaining
		}
		if size > uint64(math.MaxInt) {
			break
		}
		chunk := make([]byte, int(size))
		touchPages(chunk)
		held = append(held, chunk)
		allocated += size
	}
	return fmt.Errorf("exhausted OOM allocation limit without container exit")
}

func oomMemoryLimit(procRoot, cgroupRoot string, pid int) (uint64, error) {
	rel := ""
	cgData, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "cgroup"))
	if err == nil {
		rel = unifiedCgroupPath(cgData)
	}
	if rel != "" {
		maxPath := filepath.Join(cgroupRoot, rel, "memory.max")
		content, err := os.ReadFile(maxPath)
		if err == nil {
			value := strings.TrimSpace(string(content))
			if value != "" && value != "max" {
				limit, err := strconv.ParseUint(value, 10, 64)
				if err == nil {
					return limit + uint64(oomChunkBytes), nil
				}
			}
		}
	}
	return oomMaxFallback, nil
}

func writeOOMScoreAdj(procRoot string, pid int, score int) error {
	path := filepath.Join(procRoot, strconv.Itoa(pid), "oom_score_adj")
	return os.WriteFile(path, []byte(strconv.Itoa(score)), 0644)
}

func touchPages(buf []byte) {
	const pageSize = 4096
	for i := 0; i < len(buf); i += pageSize {
		buf[i] = 1
	}
	if len(buf) > 0 {
		buf[len(buf)-1] = 1
	}
}

// --- shared ---

func waitForProcExit(procRoot string, pid int, timeout time.Duration) error {
	if procRoot == "" {
		procRoot = "/proc"
	}
	procPath := filepath.Join(procRoot, strconv.Itoa(pid))
	var deadline time.Time
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	for {
		if _, err := os.Stat(procPath); os.IsNotExist(err) {
			return nil
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for pid %d to exit", pid)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
