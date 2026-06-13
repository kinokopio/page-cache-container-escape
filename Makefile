GO           ?= go
GOOS         ?= linux
GOARCH       ?= amd64

ifdef CROSS_PREFIX
CC := $(CROSS_PREFIX)gcc
LD := $(CROSS_PREFIX)ld
else
ifeq ($(origin CC),default)
CC := $(shell command -v x86_64-linux-gnu-gcc 2>/dev/null || command -v gcc)
endif
ifeq ($(origin LD),default)
LD := $(shell command -v x86_64-linux-gnu-ld 2>/dev/null || command -v ld)
endif
endif

CMD_DIR      := ./cmd/pcce
INJECTOR_BIN := cmd/pcce/injector-amd64.bin
PCCE_BIN     := pcce
GO_BUILD_FLAGS ?= -trimpath -buildvcs=false
GO_LDFLAGS     ?= -s -w

.PHONY: all pcce pcce-debug verify check-artifacts clean

all: $(INJECTOR_BIN) $(PCCE_BIN)

$(INJECTOR_BIN): injector.c
	mkdir -p $(dir $@)
	$(CC) -c -O2 -fPIC -nostdlib -fno-stack-protector -fno-asynchronous-unwind-tables -o injector.o injector.c
	$(LD) -N -shared -nostdlib -e _start -o $@ injector.o
	rm -f injector.o

$(PCCE_BIN): $(INJECTOR_BIN)
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build $(GO_BUILD_FLAGS) -ldflags='$(GO_LDFLAGS)' -o $@ $(CMD_DIR)

pcce-debug: $(INJECTOR_BIN)
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build -o $(PCCE_BIN) $(CMD_DIR)

verify: | check-artifacts
	@echo "[+] All artifact checks passed"

check-artifacts:
	@if [ ! -f $(INJECTOR_BIN) ]; then echo "[-] $(INJECTOR_BIN) not found; run 'make' first or provide a cross-compiled binary"; exit 1; fi
	@echo "[*] Verifying $(INJECTOR_BIN)..."
	@MARKER="PAGE_CACHE_INJECTOR_PAYLOAD_MARKER_V01"; \
	OFF=$$(strings -t d $(INJECTOR_BIN) | grep "$$MARKER" | awk '{print $$1}'); \
	if [ -z "$$OFF" ]; then echo "[-] FAIL: marker not found"; exit 1; fi; \
	echo "    Marker offset: $$OFF"; \
	SIZE=$$(wc -c < $(INJECTOR_BIN) | tr -d ' '); \
	echo "    Binary size:   $$SIZE"; \
	LEN_OFF=$$((OFF + $${#MARKER})); \
	LEN_VAL=$$(od -An -tu8 -j$$LEN_OFF -N8 $(INJECTOR_BIN) | tr -d ' '); \
	if [ "$$LEN_VAL" != "0" ]; then echo "[-] FAIL: payload len = $$LEN_VAL (expected 0)"; exit 1; fi; \
	echo "    Payload len:   0 (ok)"; \
	if command -v readelf >/dev/null 2>&1; then \
		LOADS=$$(readelf -l $(INJECTOR_BIN) 2>/dev/null | grep -c LOAD); \
		echo "    LOAD segments: $$LOADS"; \
		if [ "$$LOADS" -ne 1 ]; then echo "[-] WARN: expected 1 LOAD segment, got $$LOADS"; fi; \
	else \
		echo "    (readelf not available, skipping ELF segment check)"; \
	fi; \
	if command -v file >/dev/null 2>&1; then \
		printf "    ELF type:      "; file -b $(INJECTOR_BIN); \
	fi
	@if [ ! -f $(PCCE_BIN) ]; then echo "[!] $(PCCE_BIN) not found; skipping pcce check"; else \
		echo "[*] Verifying $(PCCE_BIN)..."; \
		if command -v file >/dev/null 2>&1; then \
			printf "    Binary type:   "; file -b $(PCCE_BIN); \
		fi; \
	fi
	@echo "[+] Artifact checks complete"

clean:
	rm -f injector.o $(INJECTOR_BIN) $(PCCE_BIN)
