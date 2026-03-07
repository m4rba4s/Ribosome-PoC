extern crate libc;

use libc::{c_void, c_char, syscall, SYS_memfd_create, SYS_write, SYS_lseek, SYS_execve, SEEK_SET};
use std::ffi::CString;

fn main() {
    let name = CString::new("test_payload").unwrap();
    let fd = unsafe { syscall(SYS_memfd_create, name.as_ptr(), 0) };
    if fd < 0 {
        eprintln!("Failed to memfd_create");
        return;
    }

    let script = b"#!/bin/sh\necho 'Hello from Ribosome-PoC'\n";
    let w = unsafe { syscall(SYS_write, fd, script.as_ptr() as *const c_void, script.len()) };
    if w < 0 {
        eprintln!("Failed to write");
        return;
    }

    let _ = unsafe { syscall(SYS_lseek, fd, 0, SEEK_SET) };

    let path = CString::new(format!("/proc/self/fd/{}", fd)).unwrap();
    let arg0 = CString::new("test_payload").unwrap();
    let argv = [arg0.as_ptr(), std::ptr::null()];
    
    // We use execve instead of execveat because SYS_execveat constant isn't in older libc
    unsafe { syscall(SYS_execve, path.as_ptr(), argv.as_ptr(), std::ptr::null::<*const c_char>()) };
    
    eprintln!("Exec failed");
}
