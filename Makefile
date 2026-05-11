GO ?= go
GOCACHE ?= $(CURDIR)/.gocache
CGO_ENABLED ?= 0
WIN_GOARCH ?= amd64
GOFLAGS ?=
LDFLAGS ?=

export GOCACHE
export CGO_ENABLED

AS_BIN := as-server
TGS_BIN := tgs-server
V_BIN := v-server

AS_WIN_BIN := as-server.exe
TGS_WIN_BIN := tgs-server.exe
V_WIN_BIN := v-server.exe

.PHONY: all build linux windows as tgs v as-win tgs-win v-win clean help

all: build

build: linux windows

linux: as tgs v

windows: as-win tgs-win v-win

as:
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(AS_BIN) ./as_server/cmd

tgs:
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(TGS_BIN) ./tgs_server/cmd

v:
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(V_BIN) ./verify_server/cmd

as-win:
	GOOS=windows GOARCH=$(WIN_GOARCH) $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(AS_WIN_BIN) ./as_server/cmd

tgs-win:
	GOOS=windows GOARCH=$(WIN_GOARCH) $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(TGS_WIN_BIN) ./tgs_server/cmd

v-win:
	GOOS=windows GOARCH=$(WIN_GOARCH) $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(V_WIN_BIN) ./verify_server/cmd

clean:
	rm -rf $(AS_BIN) $(TGS_BIN) $(V_BIN) $(AS_WIN_BIN) $(TGS_WIN_BIN) $(V_WIN_BIN) bin .gocache

help:
	@echo "Targets:"
	@echo "  make          Build Linux/current-platform and Windows servers in project root"
	@echo "  make linux    Build AS, TGS, and V servers for the current platform"
	@echo "  make windows  Build AS, TGS, and V servers for Windows/$(WIN_GOARCH)"
	@echo "  make as       Build AS server"
	@echo "  make tgs      Build TGS server"
	@echo "  make v        Build V server"
	@echo "  make clean    Remove build outputs and local Go build cache"
