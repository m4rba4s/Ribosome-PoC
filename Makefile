# Makefile for Ribosome-PoC and Aegis Telemetry
# This automates the build and test process for a full Linux host/VM.

.PHONY: all build clean test_detection run_poc test_stegano help

help:
	@echo "Ribosome-PoC & Aegis Telemetry Build System"
	@echo "==========================================="
	@echo "make build          - Compile the Rust in-memory exec PoC"
	@echo "make run_poc        - Run the PoC (translates payload to memfd)"
	@echo "make test_detection - Run the YARA memory scanner against /proc"
	@echo "make install_ebpf   - Load the Aegis eBPF telemetry module (requires sudo)"
	@echo "make clean          - Remove Rust build artifacts"

build:
	@echo "[+] Building Ribosome-PoC (Zero-Dep Syscall implementation)..."
	cd ribosome-poc && cargo build --release
	@echo "[+] Build complete. Binary at: ribosome-poc/target/release/ribosome-poc"

run_poc: build
	@echo "[+] Executing PoC (Biomimicry in memory)..."
	@./ribosome-poc/target/release/ribosome-poc

test_detection:
	@echo "[+] Running YARA Heuristic Scanner on /proc/*/exe..."
	@sudo python3 yara_scanner.py

install_ebpf:
	@echo "[+] Compiling and loading Aegis BPF Telemetry (Requires LLVM/BCC)..."
	@if [ "$$(id -u)" -ne 0 ]; then echo "[-] Please run this target with sudo: sudo make install_ebpf"; exit 1; fi
	@python3 aegis_loader.py

clean:
	@echo "[+] Cleaning build artifacts..."
	cd ribosome-poc && cargo clean
	rm -f dummy_memfd dummy_memfd.py rust_payload out.txt
