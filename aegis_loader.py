#!/usr/bin/env python3
import time
import sys

try:
    from bcc import BPF
except ImportError:
    print("[-] Error: BCC (BPF Compiler Collection) is not installed.")
    print("    Install it via: sudo apt-get install bpfcc-tools python3-bpfcc")
    sys.exit(1)

import os
import ctypes

# Struct matching the C definition in aegis_kernel.c
class AlertData(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("comm", ctypes.c_char * 16),
        ("trigger", ctypes.c_char * 32),
        ("alert_id", ctypes.c_uint32)
    ]

def print_event(cpu, data, size):
    # Cast the generic byte array to our structured AlertData
    event = ctypes.cast(data, ctypes.POINTER(AlertData)).contents
    comm = event.comm.decode('utf-8', 'replace')
    trigger = event.trigger.decode('utf-8', 'replace')
    
    if event.alert_id == 1:
        print(f"\n[!!!] LEVEL 1 ANOMALY DETECTED [!!!]")
        print(f"      Rule:  In-Memory Execution (memfd_create -> execveat)")
        print(f"      PID:   {event.pid} ({comm})")
        print(f"      File:  {trigger}")
        print(f"      Act:   Aegis logged the attempt. (Enforcement mode OFF)\n")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] FATAL: eBPF requires root privileges. Run with sudo.")
        sys.exit(1)

    print("[*] Compiling Aegis eBPF Telemetry Core...")
    kernel_file = "aegis_kernel.c"
    if not os.path.exists(kernel_file):
        print(f"[-] FATAL: Kernel source {kernel_file} not found.")
        sys.exit(1)
        
    try:
        with open(kernel_file, 'r') as f:
            ebpf_c_code = f.read()
            
        b = BPF(text=ebpf_c_code)
    except Exception as e:
        print(f"[-] BPF Compilation Failed: {e}")
        sys.exit(1)

    print("[+] Compilation successful! Aegis probes loaded into Ring-0.")
    print("[*] Monitoring for Ribosome-PoC (memfd_create -> execveat)...")
    print("[*] Press Ctrl+C to unload modules and exit.\n")

    b["events"].open_perf_buffer(print_event)

    try:
        while True:
            b.perf_buffer_poll()
            time.sleep(0.1)
    except KeyboardInterrupt:
        print("\n[*] Unloading Aegis eBPF Module. Shield Down.")
        sys.exit(0)
