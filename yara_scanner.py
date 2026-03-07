#!/usr/bin/env python3
import os
import sys
import re

# Простейший эмулятор YARA-сканера для /proc/
# Реализует логику из Документа 4 (Detection Engineering)
# Правило: ProcExe_MemfdReference

def scan_proc_exe():
    print("[*] Starting YARA heuristic scan on /proc/*/exe...")
    suspicious_pids = []
    
    # Регулярка для '/memfd:name (deleted)'
    # В Linux symlink в /proc/[pid]/exe для memfd выглядит именно так
    memfd_pattern = re.compile(r'^/memfd:.* \(deleted\)$')
    
    try:
        pids = [int(pid) for pid in os.listdir('/proc') if pid.isdigit()]
    except OSError as e:
        print(f"[-] Failed to read /proc: {e}")
        return

    for pid in pids:
        exe_path = f"/proc/{pid}/exe"
        try:
            # Читаем куда указывает symlink
            target = os.readlink(exe_path)
            
            if memfd_pattern.match(target):
                # Читаем /proc/[pid]/comm для имени процесса
                comm = "unknown"
                try:
                    with open(f"/proc/{pid}/comm", "r") as f:
                        comm = f.read().strip()
                except OSError:
                    pass
                
                print(f"[!] SCANNED ANOMALY [T1620]: PID {pid} ({comm}) is executing from memfd: {target}")
                suspicious_pids.append((pid, comm, target))
                
        except OSError:
            # Нормально (нет прав чтения exe чужого процесса или процесс умер)
            continue
            
    print(f"[*] Scan complete. Found {len(suspicious_pids)} suspicious processes.")
    return suspicious_pids

def check_whitelist(pid, comm):
    # Упрощенный whitelist из Документа 4 (PulseAudio, JIT, etc не должны вызывать execve, но на всякий)
    WHITELIST = ["pulseaudio", "pipewire", "Chrome", "java", "node"]
    for wl in WHITELIST:
        if wl.lower() in comm.lower():
            return True
    return False

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] Warning: Running without root. You will only scan your own processes.")
        
    findings = scan_proc_exe()
    
    if findings:
        print("\n[+] Triage Action Required:")
        for pid, comm, target in findings:
            if check_whitelist(pid, comm):
                print(f"  -> PID {pid} ({comm}): WHITELISTED (False Positive highly likely)")
            else:
                print(f"  -> PID {pid} ({comm}): CRITICAL ALERT! Potential Bio-Mimicry (Ribosome Translation)")
