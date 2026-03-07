use crate::fragments::Fragment;
use core::fmt;

#[derive(Debug)]
pub enum SpliceError {
    DuplicateSequenceId(u8),
}

impl fmt::Display for SpliceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpliceError::DuplicateSequenceId(id) => {
                write!(f, "duplicate sequence_id={} in fragment list", id)
            }
        }
    }
}

impl std::error::Error for SpliceError {}

pub struct AssembledPayload {
    pub data: Vec<u8>,
    pub fragment_count: usize,
}

pub struct Splicer;

impl Splicer {
    /// Sort by sequence_id, validate uniqueness, concatenate.
    pub fn assemble(fragments: &mut [Fragment]) -> Result<AssembledPayload, SpliceError> {
        fragments.sort_by_key(|f| f.sequence_id);

        let mut assembled = Vec::new();
        let mut prev_id: Option<u8> = None;

        for frag in fragments.iter() {
            if prev_id == Some(frag.sequence_id) {
                return Err(SpliceError::DuplicateSequenceId(frag.sequence_id));
            }
            prev_id = Some(frag.sequence_id);
            assembled.extend_from_slice(&frag.data);
        }

        Ok(AssembledPayload {
            data: assembled,
            fragment_count: fragments.len(),
        })
    }
}
