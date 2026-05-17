use crate::fragments::Fragment;
use core::fmt;

#[derive(Debug)]
pub enum SpliceError {
    DuplicateSequenceId(u16),
    MissingSequenceId { expected: u16, found: u16 },
    EmptyFragment(u16),
    EmptyPayload,
}

impl fmt::Display for SpliceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpliceError::DuplicateSequenceId(id) => {
                write!(f, "duplicate sequence_id={} in fragment list", id)
            }
            SpliceError::MissingSequenceId { expected, found } => {
                write!(
                    f,
                    "missing sequence_id={} before sequence_id={}",
                    expected, found
                )
            }
            SpliceError::EmptyFragment(id) => {
                write!(f, "empty data in sequence_id={}", id)
            }
            SpliceError::EmptyPayload => write!(f, "no payload fragments were provided"),
        }
    }
}

impl std::error::Error for SpliceError {}

#[derive(Debug)]
pub struct AssembledPayload {
    pub data: Vec<u8>,
    pub fragment_count: usize,
}

use crate::concurrency::RingBuffer;
use crate::logger::{BitLogger, LogEvent};

pub struct Splicer;

impl Splicer {
    /// Consumes fragments from the RingBuffer using Lock-Free polling.
    /// Expects fragments to arrive in order (for now) or buffers them internally if needed.
    pub fn assemble_concurrent(
        rx: &RingBuffer<Fragment, 4096>,
        expected_fragments: usize,
    ) -> Result<AssembledPayload, SpliceError> {
        if expected_fragments == 0 {
            return Err(SpliceError::EmptyPayload);
        }

        let mut assembled = Vec::new();
        let mut expected_id = 0u16;
        let mut count = 0;

        // Busy-wait loop (Lock-Free consumer)
        while count < expected_fragments {
            if let Some(frag) = rx.pop() {
                if frag.sequence_id != expected_id {
                    return Err(SpliceError::MissingSequenceId {
                        expected: expected_id,
                        found: frag.sequence_id,
                    });
                }
                if frag.data.is_empty() {
                    return Err(SpliceError::EmptyFragment(frag.sequence_id));
                }

                // Send to Logger asynchronously (assuming Logger is fast enough or has its own buffer)
                BitLogger::log_event(LogEvent::SpliceFragment {
                    seq: frag.sequence_id,
                    data: frag.data.clone(),
                });

                assembled.extend_from_slice(&frag.data);
                expected_id = expected_id.wrapping_add(1);
                count += 1;
            } else {
                // Yield to prevent total CPU starvation if producer is slow,
                // but keep it aggressive as per Red Team standards.
                core::hint::spin_loop();
            }
        }

        Ok(AssembledPayload {
            data: assembled,
            fragment_count: count,
        })
    }
}
