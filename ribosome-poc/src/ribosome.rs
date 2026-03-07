use crate::syscalls::raw_execveat;
use core::fmt;

#[derive(Debug)]
pub enum TranslateError {
    ExecFailed(i64), // raw negative errno
}

impl fmt::Display for TranslateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TranslateError::ExecFailed(e) => write!(f, "execveat failed: errno={}", -e),
        }
    }
}

impl std::error::Error for TranslateError {}

pub struct Ribosome;

impl Ribosome {
    /// Executes the script/binary held in `fd` via execveat(AT_EMPTY_PATH).
    /// On success this never returns — the calling process is replaced.
    pub fn translate(fd: i32) -> Result<std::convert::Infallible, TranslateError> {
        // argv[0] = program name (NUL-terminated), argv[1] = NULL sentinel
        let arg0: &[u8] = b"payload\0";
        let argv: [*const u8; 2] = [arg0.as_ptr(), core::ptr::null()];

        // Minimal env: just a null-terminated list with one entry (empty)
        let envp: [*const u8; 1] = [core::ptr::null()];

        let ret = unsafe { raw_execveat(fd, argv.as_ptr(), envp.as_ptr()) };

        // POSIX invariant: execveat does not return on success.
        // If we reach here, the syscall failed.
        Err(TranslateError::ExecFailed(ret))
    }
}
