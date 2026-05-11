GO ?= go
GOCACHE ?= $(CURDIR)/.gocache
CGO_ENABLED ?= 0
LINUX_GOARCH ?= amd64
WIN_GOARCH ?= amd64
GOFLAGS ?=
LDFLAGS ?=

export GOCACHE
export CGO_ENABLED

AS_LINUX_BIN := as-server-linux
TGS_LINUX_BIN := tgs-server-linux
V_LINUX_BIN := v-server-linux

AS_WIN_BIN := as-server-win.exe
TGS_WIN_BIN := tgs-server-win.exe
V_WIN_BIN := v-server-win.exe

.PHONY: all build linux windows as tgs v as-linux tgs-linux v-linux as-win tgs-win v-win clean help

all: build

build: linux windows

linux: as-linux tgs-linux v-linux

windows: as-win tgs-win v-win

as: as-linux

tgs: tgs-linux

v: v-linux

as-linux:
	GOOS=linux GOARCH=$(LINUX_GOARCH) $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(AS_LINUX_BIN) ./as_server/cmd

tgs-linux:
	GOOS=linux GOARCH=$(LINUX_GOARCH) $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(TGS_LINUX_BIN) ./tgs_server/cmd

v-linux:
	GOOS=linux GOARCH=$(LINUX_GOARCH) $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(V_LINUX_BIN) ./verify_server/cmd

as-win:
	GOOS=windows GOARCH=$(WIN_GOARCH) $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(AS_WIN_BIN) ./as_server/cmd

tgs-win:
	GOOS=windows GOARCH=$(WIN_GOARCH) $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(TGS_WIN_BIN) ./tgs_server/cmd

v-win:
	GOOS=windows GOARCH=$(WIN_GOARCH) $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(V_WIN_BIN) ./verify_server/cmd

clean:
	rm -rf $(AS_LINUX_BIN) $(TGS_LINUX_BIN) $(V_LINUX_BIN) $(AS_WIN_BIN) $(TGS_WIN_BIN) $(V_WIN_BIN) as-server tgs-server v-server as-server.exe tgs-server.exe v-server.exe bin .gocache

help:
	@echo "Targets:"
	@echo "  make          Build Linux and Windows servers in project root"
	@echo "  make linux    Build AS, TGS, and V servers for Linux/$(LINUX_GOARCH)"
	@echo "  make windows  Build AS, TGS, and V servers for Windows/$(WIN_GOARCH)"
	@echo "  make as       Build AS server for Linux/$(LINUX_GOARCH)"
	@echo "  make tgs      Build TGS server for Linux/$(LINUX_GOARCH)"
	@echo "  make v        Build V server for Linux/$(LINUX_GOARCH)"
	@echo "  make clean    Remove build outputs and local Go build cache"
