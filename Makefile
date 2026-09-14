# https://github.com/drduh/mess/blob/main/Makefile

BINARY_NAME := mess
VERSION     := $(shell date +%Y.%m.%d)
PLATFORM    := arm64-darwin
RELEASE_DIR := release
TARGET      := $(RELEASE_DIR)/$(BINARY_NAME)-$(VERSION)-$(PLATFORM)

.PHONY: build run prep clean

all: run

prep:
	@mkdir -p $(RELEASE_DIR)

build: prep
	@GOOS=darwin GOARCH=arm64 go build -o $(TARGET) cmd/mess/main.go

run: build
	@./$(TARGET) -dir /var/log/mess -pattern "mess-v1-*.log" -serve 127.0.0.1:8000

clean:
	rm -f $(RELEASE_DIR)/$(BINARY_NAME)-*
