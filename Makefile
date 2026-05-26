VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
PKG := ./cmd/yass
DIST := dist

PLATFORMS := \
	linux/amd64 \
	linux/arm64 \
	darwin/amd64 \
	darwin/arm64 \
	windows/amd64 \
	windows/arm64

.PHONY: all build test vet clean release checksums

all: build

build:
	go build -trimpath -ldflags="$(LDFLAGS)" -o yass$(if $(filter windows,$(GOOS)),.exe,) $(PKG)

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -rf $(DIST) yass yass.exe

# Cross-compile to dist/yass-<os>-<arch>[.exe]. Each platform builds in its own
# subshell so a failure on one doesn't poison the others.
release: clean
	mkdir -p $(DIST)
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		ext=$$( [ $$os = windows ] && echo .exe || echo ); \
		out=$(DIST)/yass-$$os-$$arch$$ext; \
		echo "==> $$out"; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 \
			go build -trimpath -ldflags="$(LDFLAGS)" -o $$out $(PKG) || exit 1; \
	done
	$(MAKE) checksums

checksums:
	cd $(DIST) && sha256sum yass-* > SHA256SUMS
