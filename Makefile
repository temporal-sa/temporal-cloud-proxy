BINARY_NAME := tclp
CMD_DIR := ./cmd
OUTPUT_DIR := .
OUTPUT_PATH := $(OUTPUT_DIR)/$(BINARY_NAME)

.PHONY: all build clean

all: build

build:
	go build -o $(OUTPUT_PATH) $(CMD_DIR)

clean:
	rm -f $(OUTPUT_PATH)