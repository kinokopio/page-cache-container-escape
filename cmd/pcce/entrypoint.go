//go:build linux

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// procArgv0 reads /proc/<pid>/cmdline and returns argv[0], empty string on error.
func procArgv0(pid int) string {
	cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	return string(bytes.SplitN(cmdline, []byte{0}, 2)[0])
}

func resolveEntrypoint(pid int) (string, []string, error) {
	return resolveEntrypointPath(pid, procArgv0(pid), filepath.EvalSymlinks)
}

func resolveEntrypointPath(pid int, argv0 string, eval func(string) (string, error)) (string, []string, error) {
	var warnings []string
	if argv0 == "" {
		warnings = append(warnings, fmt.Sprintf("could not read /proc/%d/cmdline; resolving /proc/%d/exe", pid, pid))
		return resolveProcExe(pid, warnings, eval)
	}
	if filepath.IsAbs(argv0) {
		if resolved, err := eval(argv0); err == nil {
			return resolved, warnings, nil
		} else {
			warnings = append(warnings, fmt.Sprintf("could not resolve entrypoint %q: %v; resolving /proc/%d/exe", argv0, err, pid))
			return resolveProcExe(pid, warnings, eval)
		}
	}
	warnings = append(warnings, fmt.Sprintf("entrypoint argv0 %q is not absolute; using /proc/%d/exe", argv0, pid))
	return resolveProcExe(pid, warnings, eval)
}

func resolveProcExe(pid int, warnings []string, eval func(string) (string, error)) (string, []string, error) {
	exePath := fmt.Sprintf("/proc/%d/exe", pid)
	resolved, err := eval(exePath)
	if err != nil {
		return "", warnings, fmt.Errorf("resolve %s: %w", exePath, err)
	}
	return resolved, warnings, nil
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
