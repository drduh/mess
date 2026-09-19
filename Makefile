# https://github.com/drduh/mess/blob/main/Makefile
ROOT         = mess

ARG          =
PKG          = ./...
SRC          = cmd/$(ROOT)/main.go

GOCMD       ?= go
GOLINT      ?= golangci-lint
GOLINTARG    =
GOSEC       ?= gosec
GOSTATIC    ?= staticcheck

BINARY_NAME := $(ROOT)
VERSION     := $(shell date +%Y.%m.%d)
PLATFORM    := arm64-darwin
RELEASE_DIR := release
TARGET      := $(RELEASE_DIR)/$(BINARY_NAME)-$(VERSION)-$(PLATFORM)

.PHONY: build run prep clean

all: fmt run

prep:
	@mkdir -p $(RELEASE_DIR)

build: prep
	@GOOS=darwin GOARCH=arm64 $(GOCMD) build -o $(TARGET) $(SRC)

version: ARG += -version
run version: build
	@./$(TARGET) $(ARG) \
		-dir /var/log/mess \
		-pattern "mess-v1-*.log" \
		-serve 127.0.0.1:8080

clean:
	rm -f $(RELEASE_DIR)/$(BINARY_NAME)-*

WARN         = tput setaf 3 ; printf "%s\n" "${1}" ; tput sgr0
RUN_IF_FOUND = if command -v $(1) >/dev/null 2>&1 ; \
	then $(1) $(2) ; else \
	$(call WARN,skipping '$@': '$(1)' not found); fi

lint-verbose: GOLINTARG = --verbose

lint lint-verbose:
	@printf "linting ... "
	@$(call RUN_IF_FOUND,$(GOLINT),run $(GOLINTARG) $(PKG))

sec:
	@$(call RUN_IF_FOUND,$(GOSEC),$(PKG))

static:
	@$(call RUN_IF_FOUND,$(GOSTATIC),$(PKG))

fmt:
	@$(GOCMD) fmt $(PKG)
