# Makefile for UK Nuclear Simulation Platform

# Compiler and flags
CC = gcc
# -Wall: Enable common warnings
# -Wextra: Enable extra warnings
# -g: Include debugging information
# -Isrc: Tell compiler to look for headers (#include "...") in the src/ directory
# -std=c11: Use the C11 standard (optional, but good practice)
CFLAGS = -Wall -Wextra -g -Isrc -std=c11
# Linker flags: -pthread is needed for nuclearControl using pthreads
LDFLAGS = -pthread

# Source directory
SRC_DIR = src
# Build directory (where executables will go)
BUILD_DIR = build
# Logs directory
LOG_DIR = logs

# Source files residing in SRC_DIR
UTILS_SRC = $(SRC_DIR)/utils.c
CONTROL_SRC = $(SRC_DIR)/nuclearControl.c
SILO_SRC = $(SRC_DIR)/missileSilo.c
SUB_SRC = $(SRC_DIR)/submarine.c
RADAR_SRC = $(SRC_DIR)/radar.c
SAT_SRC = $(SRC_DIR)/satellite.c # Corrected spelling

# Executable targets in BUILD_DIR
CONTROL_EXE = $(BUILD_DIR)/nuclearControl
SILO_EXE = $(BUILD_DIR)/missileSilo
SUB_EXE = $(BUILD_DIR)/submarine
RADAR_EXE = $(BUILD_DIR)/radar
SAT_EXE = $(BUILD_DIR)/satellite

TARGETS = $(CONTROL_EXE) $(SILO_EXE) $(SUB_EXE) $(RADAR_EXE) $(SAT_EXE)

# Default target: build all executables
all: $(TARGETS)

# Rule to create build and logs directories
# This target runs first if the directories don't exist
# The pipe symbol | indicates an order-only prerequisite
$(BUILD_DIR):
	@echo "Creating build directory: $(BUILD_DIR)"
	@mkdir -p $(BUILD_DIR)

$(LOG_DIR):
	@echo "Creating log directory: $(LOG_DIR)"
	@mkdir -p $(LOG_DIR)

# Specify that executables depend on the directories existing
$(TARGETS): | $(BUILD_DIR) $(LOG_DIR)

# Rule to build nuclearControl (depends on its source, utils source, and headers)
# Links with pthreads via LDFLAGS
$(CONTROL_EXE): $(CONTROL_SRC) $(UTILS_SRC) $(SRC_DIR)/common.h $(SRC_DIR)/utils.h
	$(CC) $(CFLAGS) $(CONTROL_SRC) $(UTILS_SRC) -o $@ $(LDFLAGS)

# Rule to build missileSilo
$(SILO_EXE): $(SILO_SRC) $(UTILS_SRC) $(SRC_DIR)/common.h $(SRC_DIR)/utils.h
	$(CC) $(CFLAGS) $(SILO_SRC) $(UTILS_SRC) -o $@

# Rule to build submarine
$(SUB_EXE): $(SUB_SRC) $(UTILS_SRC) $(SRC_DIR)/common.h $(SRC_DIR)/utils.h
	$(CC) $(CFLAGS) $(SUB_SRC) $(UTILS_SRC) -o $@

# Rule to build radar
$(RADAR_EXE): $(RADAR_SRC) $(UTILS_SRC) $(SRC_DIR)/common.h $(SRC_DIR)/utils.h
	$(CC) $(CFLAGS) $(RADAR_SRC) $(UTILS_SRC) -o $@

# Rule to build satellite
$(SAT_EXE): $(SAT_SRC) $(UTILS_SRC) $(SRC_DIR)/common.h $(SRC_DIR)/utils.h
	$(CC) $(CFLAGS) $(SAT_SRC) $(UTILS_SRC) -o $@

# Clean up build directory and log files (optional: remove log files)
clean:
	@echo "Cleaning build directory..."
	@rm -rf $(BUILD_DIR)
	@# Optional: uncomment below to also remove logs on clean
	@# echo "Cleaning log directory..."
	@# rm -rf $(LOG_DIR)/*
	@echo "Clean finished."

# Phony targets (targets that don't represent files)
.PHONY: all clean

