# Walkthrough: Biologically-Inspired Evasion & Telemetry (Ribosome-PoC)

This document serves as the final report and execution guide for the `Ribosome-PoC` project. We successfully developed a cross-domain laboratory demonstrating state-of-the-art offensive evasion (Red Team) and deep kernel telemetry (Blue Team).

## Concept: Biomimicry in Cyberspace
The project models advanced malware after cellular biology:
- **DNA (The Attacker Server):** Holds the malicious generic blueprint.
- **tRNA (DNS TXT Records):** Carrier molecules that transport encoded fragments of the payload across the network, sidestepping traditional Firewalls/DPI.
- **Spliceosome (Memory Assembler):** Reconstructs the encoded chunks into a coherent binary within RAM.
- **Membrane (memfd & fcntl):** Creates an anonymous, sealed memory region (`memfd_create` + `F_ADD_SEALS`) to protect the payload from EDR/AV tampering.
- **Ribosome (execveat):** Translates the inert memory region into an active, executing process without ever touching the hard drive.
- **Immune System (Aegis eBPF):** Ring-0 kernel probes that detect the specific anomalous sequence of `memfd_create` followed by `execveat`.

---

## 🔴 Playbook V1: The Attack (Red Team)

### Step 1: Payload Preparation
We use `payload_packer.py` to convert a raw ELF binary into a chunked, Base64-encoded BIND DNS zone file.
```bash
# Example: Packing a 1MB reverse shell
./payload_packer.py -i reverse_shell.bin -d malicious.local -c 200 > payload.zone

# Output:
# 0 IN TXT "VGhpcyBpcyBiYXNlNjQ..."
# ...
# N IN TXT "EOF"
```

### Step 2: Implant Execution
The victim runs the `ribosome-poc` implant. 
1. **Evasion Check:** It first runs `ptrace(PTRACE_TRACEME)` and uses `rdtsc` to verify it isn't being debugged or sandboxed by automated analysis tools.
2. **Network Fetch:** It queries `0.malicious.local TXT`, `1.malicious.local TXT` over raw UDP Port 53, reassembling the Base64 chunks in memory.
3. **Execution Masking:** The payload is written to a `memfd`, sealed (`F_SEAL_WRITE`), and executed via `execveat`. Strings like `kworker/u4:2\0` and domain names are XOR-obfuscated at compile time to defeat `strings` analysis.

---

## 🔵 Playbook V2: The Defense (Blue Team)

Traditional AV fails because there is no file hash, and no file is ever opened via standard `open()`/`execve()` pathways. We built **Aegis**, an eBPF Telemetry module.

### Step 1: Kernel Compilation & Loading
Aegis uses the BPF Compiler Collection (BCC) to inject C code directly into the Linux Kernel.
```bash
sudo python3 aegis_loader.py
# Output:
# [*] Compiling Aegis eBPF Telemetry Core...
# [+] Compilation successful! Aegis probes loaded into Ring-0.
# [*] Monitoring for Ribosome-PoC (memfd_create -> execveat)...
```

### Step 2: Anomaly Detection
When the Ribosome implant attempts to fire, Aegis intercepts the system calls in real-time.
1. `sys_enter_memfd_create`: Aegis logs the PID and the requested anonymous file name into a BPF Hash Map.
2. `sys_enter_execveat`: Aegis intercepts the execution attempt. If the calling PID is in the Hash Map, it triggers a Level 1 Anomaly.

```text
[!!!] LEVEL 1 ANOMALY DETECTED [!!!]
      Rule:  In-Memory Execution (memfd_create -> execveat)
      PID:   44892 (ribosome-poc)
      File:  kworker/u4:2
      Act:   Aegis logged the attempt. (Enforcement mode OFF)
```

## Conclusion
The `Ribosome-PoC` demonstrates that while advanced steganography and memory-only execution can bypass entirely standard user-space and network defenses, deep kernel telemetry via eBPF provides an asymmetrical advantage to the defender, capable of pinpointing the absolute lowest-level physics of the operating system.
