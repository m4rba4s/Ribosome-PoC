// Raw Linux syscall numbers (x86_64)
pub const SYS_MEMFD_CREATE: i64 = 319;
pub const SYS_WRITE: i64 = 1;
pub const SYS_LSEEK: i64 = 8;
pub const SYS_EXECVEAT: i64 = 322;
pub const SYS_CLOSE: i64 = 3;
pub const SYS_PTRACE: i64 = 101;
pub const SYS_FCNTL: i64 = 72;

pub const MFD_CLOEXEC: u32 = 1;
pub const MFD_ALLOW_SEALING: u32 = 2;

// FCNTL seals
pub const F_ADD_SEALS: u64 = 1033;
pub const F_SEAL_SEAL: u64 = 0x0001;
pub const F_SEAL_SHRINK: u64 = 0x0002;
pub const F_SEAL_GROW: u64 = 0x0004;
pub const F_SEAL_WRITE: u64 = 0x0008;

// PTRACE
pub const PTRACE_TRACEME: u64 = 0;

pub const AT_EMPTY_PATH: i32 = 0x1000;
pub const SEEK_SET: i32 = 0;

/// Thin inline wrappers — each maps to exactly one syscall.
/// Error returns are raw negated errno values.

#[inline]
pub unsafe fn raw_memfd_create(name: *const u8, flags: u32) -> i64 {
    let ret: i64;
    core::arch::asm!(
        "syscall",
        inlateout("rax") SYS_MEMFD_CREATE => ret,
        in("rdi") name,
        in("rsi") flags as u64,
        out("rcx") _, out("r11") _,
        options(nostack)
    );
    ret
}

#[inline]
pub unsafe fn raw_write(fd: i32, buf: *const u8, count: usize) -> i64 {
    let ret: i64;
    core::arch::asm!(
        "syscall",
        inlateout("rax") SYS_WRITE => ret,
        in("rdi") fd as u64,
        in("rsi") buf,
        in("rdx") count,
        out("rcx") _, out("r11") _,
        options(nostack)
    );
    ret
}

#[inline]
pub unsafe fn raw_lseek(fd: i32, offset: i64, whence: i32) -> i64 {
    let ret: i64;
    core::arch::asm!(
        "syscall",
        inlateout("rax") SYS_LSEEK => ret,
        in("rdi") fd as u64,
        in("rsi") offset as u64,
        in("rdx") whence as u64,
        out("rcx") _, out("r11") _,
        options(nostack)
    );
    ret
}

/// Executes the file referred to by `fd` using the AT_EMPTY_PATH flag.
/// On success the process image is replaced — this function does not return.
#[inline]
pub unsafe fn raw_execveat(
    fd: i32,
    argv: *const *const u8,
    envp: *const *const u8,
) -> i64 {
    let ret: i64;
    let empty: u8 = 0; // empty pathname ""
    core::arch::asm!(
        "syscall",
        inlateout("rax") SYS_EXECVEAT => ret,
        in("rdi") fd as u64,
        in("rsi") &empty as *const u8,
        in("rdx") argv,
        in("r10") envp,
        in("r8")  AT_EMPTY_PATH as u64,
        out("rcx") _, out("r11") _,
        options(nostack)
    );
    ret
}

#[inline]
pub unsafe fn raw_close(fd: i32) -> i64 {
    let ret: i64;
    core::arch::asm!(
        "syscall",
        inlateout("rax") SYS_CLOSE => ret,
        in("rdi") fd as u64,
        out("rcx") _, out("r11") _,
        options(nostack)
    );
    ret
}

/// Guaranteed memset that the compiler cannot elide.
/// Replacement for `zeroize` crate.
#[inline(never)]
pub fn secure_zero(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // volatile write prevents optimisation
        unsafe { core::ptr::write_volatile(b, 0) };
    }
}

#[inline]
pub unsafe fn raw_ptrace(request: u64, pid: u64, addr: *mut u8, data: *mut u8) -> i64 {
    let ret: i64;
    core::arch::asm!(
        "syscall",
        inlateout("rax") SYS_PTRACE => ret,
        in("rdi") request,
        in("rsi") pid,
        in("rdx") addr,
        in("r10") data,
        out("rcx") _, out("r11") _,
        options(nostack)
    );
    ret
}

#[inline]
pub unsafe fn raw_fcntl(fd: i32, cmd: u64, arg: u64) -> i64 {
    let ret: i64;
    core::arch::asm!(
        "syscall",
        inlateout("rax") SYS_FCNTL => ret,
        in("rdi") fd as u64,
        in("rsi") cmd,
        in("rdx") arg,
        out("rcx") _, out("r11") _,
        options(nostack)
    );
    ret
}
