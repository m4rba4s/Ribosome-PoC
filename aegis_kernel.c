#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/dcache.h>

// BPF Map to track memfd_create calls -> { pid : memfd_name }
BPF_HASH(memfd_pids, u32, char[32]);

// Ring buffer to alert user-space python script
BPF_PERF_OUTPUT(events);

struct alert_data {
    u32 pid;
    char comm[16];
    char trigger[32];
    u32 alert_id;
};

// ----------------------------------------------------
// Probe 1: sys_enter_memfd_create
// Catch the moment a process requests an anonymous memory file
// ----------------------------------------------------
TRACEPOINT_PROBE(syscalls, sys_enter_memfd_create) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    char name[32] = {};
    
    // Read the requested name for the memfd (e.g., "kworker/u4:2")
    bpf_probe_read_user_str(&name, sizeof(name), args->uname);
    
    memfd_pids.update(&pid, &name);
    return 0;
}

// ----------------------------------------------------
// Probe 2: sys_enter_execveat
// Catch file execution. If the calling PID recently created a memfd,
// and is now calling execveat, it's a high-confidence signal for Ribosome-PoC
// ----------------------------------------------------
TRACEPOINT_PROBE(syscalls, sys_enter_execveat) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // Check if the caller PID exists in our tracking map
    char *memfd_name = memfd_pids.lookup(&pid);
    if (memfd_name) {
        // High confidence fileless execution via memfd
        struct alert_data data = {};
        data.pid = pid;
        data.alert_id = 1; // 1 = DETECT_IN_MEMORY_EXEC
        
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        bpf_probe_read_kernel_str(&data.trigger, sizeof(data.trigger), memfd_name);
        
        events.perf_submit(args, &data, sizeof(data));
        
        // Remove the entry after alerting to prevent duplicate spam
        memfd_pids.delete(&pid);
    }
    
    return 0;
}

// ----------------------------------------------------
// Probe 3: sys_exit_exit_group (Process Death)
// Housekeeping: remove the PID from the map if it dies cleanly
// ----------------------------------------------------
TRACEPOINT_PROBE(syscalls, sys_enter_exit_group) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    memfd_pids.delete(&pid);
    return 0;
}
