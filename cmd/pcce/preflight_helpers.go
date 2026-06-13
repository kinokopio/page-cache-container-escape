//go:build linux

package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"syscall"
)

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
