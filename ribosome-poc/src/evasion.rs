use crate::syscalls::{raw_ptrace, PTRACE_TRACEME};
use core::fmt;

#[derive(Debug)]
pub enum EvasionError {
    DebuggerDetected,
    SandboxDetected(u64),
    HypervisorDetected,
}

impl fmt::Display for EvasionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EvasionError::DebuggerDetected => write!(f, "Debugger attached (ptrace failed)"),
            EvasionError::SandboxDetected(delta) => {
                write!(f, "Sandbox/Hypervisor detected (rdtsc delta = {})", delta)
            }
            EvasionError::HypervisorDetected => write!(f, "Hypervisor bit set in CPUID"),
        }
    }
}

impl std::error::Error for EvasionError {}

/// Runs elite evasion checks to ensure a pristine execution environment.
pub struct Evasion;

impl Evasion {
    /// Attempts to PTRACE_TRACEME. If a debugger is already attached, this syscall will fail.
    pub fn anti_debug() -> Result<(), EvasionError> {
        let ret = unsafe {
            raw_ptrace(
                PTRACE_TRACEME,
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        if ret < 0 {
            return Err(EvasionError::DebuggerDetected);
        }
        Ok(())
    }

    /// Measures the CPU cycles taken to execute an empty sequence.
    /// Hypervisors and sandboxes that intercept instructions or implement emulation
    /// will cause significant overhead.
    pub fn anti_sandbox() -> Result<(), EvasionError> {
        let start: u64;
        let end: u64;

        unsafe {
            core::arch::asm!(
                "rdtsc",
                "shl rdx, 32",
                "or rax, rdx",
                out("rax") start,
                out("rdx") _,
                out("rcx") _,
                options(nostack)
            );

            // A tiny sequence of NOPs to measure
            core::arch::asm!("nop", "nop", "nop", "nop");

            core::arch::asm!(
                "rdtscp", // Serialize and read
                "shl rdx, 32",
                "or rax, rdx",
                out("rax") end,
                out("rdx") _,
                out("rcx") _,
                options(nostack)
            );
        }

        let delta = end - start;

        // Threshold tuning: native hardware normally executes this in under 100-200 cycles.
        // Virtual environments might push it significantly higher (e.g., 500-2000+).
        if delta > 1000 {
            return Err(EvasionError::SandboxDetected(delta));
        }

        Ok(())
    }

    /// Checks the CPUID hypervisor present bit.
    pub fn anti_vm_cpuid() -> Result<(), EvasionError> {
        let rcx: u32;
        unsafe {
            let result = core::arch::x86_64::__cpuid(1);
            rcx = result.ecx;
        }
        // The 31st bit of ECX is the hypervisor present bit
        if (rcx & (1 << 31)) != 0 {
            return Err(EvasionError::HypervisorDetected);
        }
        Ok(())
    }

    /// Run all environment safety checks.
    pub fn verify_environment() -> Result<(), EvasionError> {
        Self::anti_debug()?;
        Self::anti_vm_cpuid()?;
        Self::anti_sandbox()?;
        Ok(())
    }
}
