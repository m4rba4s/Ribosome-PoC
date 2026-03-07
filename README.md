# Ribosome-PoC: Biomimetic In-Memory Execution
**Status**: Proof of Concept (Educational / Red Team Laboratory)

This repository contains a Rust-based Proof of Concept that emulates the biological process of RNA splicing and Ribosome translation to achieve fileless, in-memory execution on Linux.

## Technical Details
Traditional EDR and Antivirus tools historically revolve around the filesystem. This architecture pushes payload execution strictly into volatile memory ("Cytoplasm") using legitimate syscalls (`memfd_create` and `execveat`).

* **Zero-Trust Memory Degradation**: Payloads are securely wiped from RAM (`secure_zero()`) using non-optimizable memory writes immediately after being loaded into the anonymous file descriptor to foil forensic memory dumping. 
* **Zero External Dependencies**: The Rust codebase uses custom inline assembly shims to directly invoke raw Linux syscalls, meaning it requires no external crates (`libc` or `nix`) and minimizes the compilation footprint.

## Contents
* `ribosome-poc/` - The Rust source code for the loader ("The Ribosome").
* `aegis_loader.py` - Blue Team skeleton for an eBPF sensor to catch the `memfd_create -> execveat` transition point.
* `yara_scanner.py` - Blue Team heuristic `/proc` scanner.
* `Makefile` - Build and test automation.

## Usage
*This tool is exclusively for authorized laboratory testing and purple-team threat emulation scenarios.*

```bash
make build
make run_poc
```

### Blue Team Tests
```bash
sudo make install_ebpf
# or
sudo make test_detection
```

## Disclaimer
The code is provided for reference and educational purposes only. Do not use this in environments without explicit authorization.
