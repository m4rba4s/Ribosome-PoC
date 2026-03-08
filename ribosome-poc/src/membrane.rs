use crate::syscalls::{
    raw_memfd_create, raw_write, raw_lseek, secure_zero, raw_fcntl,
    MFD_CLOEXEC, MFD_ALLOW_SEALING, SEEK_SET,
    F_ADD_SEALS, F_SEAL_SEAL, F_SEAL_SHRINK, F_SEAL_GROW, F_SEAL_WRITE
};
use core::fmt;

#[derive(Debug)]
pub enum MembraneError {
    CreateFailed(i64),   // raw negative errno
    WriteFailed(i64),
    IncompleteWrite,
    SeekFailed(i64),
    SealFailed(i64),
}

impl fmt::Display for MembraneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MembraneError::CreateFailed(e)  => write!(f, "memfd_create failed: errno={}", -e),
            MembraneError::WriteFailed(e)   => write!(f, "write failed: errno={}", -e),
            MembraneError::IncompleteWrite  => write!(f, "write: partial write (disk/RAM full?)"),
            MembraneError::SeekFailed(e)    => write!(f, "lseek failed: errno={}", -e),
            MembraneError::SealFailed(e)    => write!(f, "fcntl(F_ADD_SEALS) failed: errno={}", -e),
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
        // --- Phase 1: create with sealing allowed ---
        let flags = MFD_CLOEXEC | MFD_ALLOW_SEALING;
        let fd = unsafe { raw_memfd_create(name.as_ptr(), flags) };
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

        // --- Phase 3A: Seal the file descriptor to prevent modification by external tools ---
        let seals = F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE;
        let seal_ret = unsafe { raw_fcntl(fd, F_ADD_SEALS, seals) };
        if seal_ret < 0 {
            return Err(MembraneError::SealFailed(seal_ret));
        }

        // --- Phase 3B: rewind to 0 so execveat can read ELF/script from start ---
        let seek_ret = unsafe { raw_lseek(fd, 0, SEEK_SET) };
        if seek_ret < 0 {
            return Err(MembraneError::SeekFailed(seek_ret));
        }

        Ok(fd)
    }
}
