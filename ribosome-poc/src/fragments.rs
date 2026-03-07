/// Fragment: a numbered chunk of payload data.
pub struct Fragment {
    pub sequence_id: u8,
    pub data: Vec<u8>,
}

/// Anything that can yield a Fragment.
pub trait FragmentSource {
    fn fetch(&self) -> Fragment;
}

/// Hardcoded in-memory source — zero I/O, zero deps.
pub struct InMemorySource {
    pub id: u8,
    pub payload: &'static [u8],
}

impl FragmentSource for InMemorySource {
    fn fetch(&self) -> Fragment {
        Fragment {
            sequence_id: self.id,
            data: self.payload.to_vec(),
        }
    }
}
