use crate::syscalls::{raw_memfd_create, raw_write, raw_lseek, secure_zero, MFD_CLOEXEC, SEEK_SET};
use core::fmt;

#[derive(Debug)]
pub enum MembraneError {
    CreateFailed(i64),   // raw negative errno
    WriteFailed(i64),
    IncompleteWrite,
    SeekFailed(i64),
}

impl fmt::Display for MembraneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MembraneError::CreateFailed(e)  => write!(f, "memfd_create failed: errno={}", -e),
            MembraneError::WriteFailed(e)   => write!(f, "write failed: errno={}", -e),
            MembraneError::IncompleteWrite  => write!(f, "write: partial write (disk/RAM full?)"),
            MembraneError::SeekFailed(e)    => write!(f, "lseek failed: errno={}", -e),
        }
    }
}

impl std::error::Error for MembraneError {}

pub struct Membrane;

impl Membrane {
    /// Creates an MFD_CLOEXEC anonymous file, writes `data` into it,
    /// zeroes `data` unconditionally, then rewinds to offset 0.
    /// Returns a raw file descriptor (caller owns it).
    pub fn create_and_fill(name: &[u8], data: &mut Vec<u8>) -> Result<i32, MembraneError> {
        // --- Phase 1: create ---
        let fd = unsafe { raw_memfd_create(name.as_ptr(), MFD_CLOEXEC) };
        if fd < 0 {
            return Err(MembraneError::CreateFailed(fd));
        }
        let fd = fd as i32;

        // --- Phase 2: write (capture result BEFORE zeroize) ---
        let n = unsafe { raw_write(fd, data.as_ptr(), data.len()) };

        // --- SECURITY INVARIANT: always zeroize, even on write error ---
        secure_zero(data);

        if n < 0 {
            return Err(MembraneError::WriteFailed(n));
        }
        if n as usize != data.len() {
            // data is already zeroed; length mismatch is a hard error
            return Err(MembraneError::IncompleteWrite);
        }

        // --- Phase 3: rewind to 0 so execveat can read ELF/script from start ---
        let seek_ret = unsafe { raw_lseek(fd, 0, SEEK_SET) };
        if seek_ret < 0 {
            return Err(MembraneError::SeekFailed(seek_ret));
        }

        Ok(fd)
    }
}
