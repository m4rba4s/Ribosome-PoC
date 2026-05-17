use crate::splicer::AssembledPayload;
use core::fmt;

const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadManifest {
    pub version: u16,
    pub fragment_count: usize,
    pub total_len: usize,
    pub checksum64: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ManifestError {
    VersionMismatch { expected: u16, found: u16 },
    FragmentCountMismatch { expected: usize, found: usize },
    LengthMismatch { expected: usize, found: usize },
    ChecksumMismatch { expected: u64, found: u64 },
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ManifestError::VersionMismatch { expected, found } => {
                write!(
                    f,
                    "manifest version mismatch: expected {}, found {}",
                    expected, found
                )
            }
            ManifestError::FragmentCountMismatch { expected, found } => {
                write!(
                    f,
                    "fragment count mismatch: expected {}, found {}",
                    expected, found
                )
            }
            ManifestError::LengthMismatch { expected, found } => {
                write!(
                    f,
                    "payload length mismatch: expected {}, found {}",
                    expected, found
                )
            }
            ManifestError::ChecksumMismatch { expected, found } => {
                write!(
                    f,
                    "payload checksum mismatch: expected 0x{expected:016x}, found 0x{found:016x}"
                )
            }
        }
    }
}

impl std::error::Error for ManifestError {}

impl PayloadManifest {
    pub const fn new(
        version: u16,
        fragment_count: usize,
        total_len: usize,
        checksum64: u64,
    ) -> Self {
        Self {
            version,
            fragment_count,
            total_len,
            checksum64,
        }
    }

    pub fn verify(
        &self,
        expected_version: u16,
        payload: &AssembledPayload,
    ) -> Result<(), ManifestError> {
        if self.version != expected_version {
            return Err(ManifestError::VersionMismatch {
                expected: expected_version,
                found: self.version,
            });
        }
        if self.fragment_count != payload.fragment_count {
            return Err(ManifestError::FragmentCountMismatch {
                expected: self.fragment_count,
                found: payload.fragment_count,
            });
        }
        if self.total_len != payload.data.len() {
            return Err(ManifestError::LengthMismatch {
                expected: self.total_len,
                found: payload.data.len(),
            });
        }

        let found = checksum64(&payload.data);
        if self.checksum64 != found {
            return Err(ManifestError::ChecksumMismatch {
                expected: self.checksum64,
                found,
            });
        }

        Ok(())
    }
}

/// Non-cryptographic corruption guard. This is deliberately small and auditable;
/// do not treat it as a trust boundary for hostile networks.
pub fn checksum64(data: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET_BASIS;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

pub fn manifest_for_payload(version: u16, payload: &AssembledPayload) -> PayloadManifest {
    PayloadManifest::new(
        version,
        payload.fragment_count,
        payload.data.len(),
        checksum64(&payload.data),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(data: &[u8], fragment_count: usize) -> AssembledPayload {
        AssembledPayload {
            data: data.to_vec(),
            fragment_count,
        }
    }

    #[test]
    fn verifies_matching_manifest() {
        let payload = payload(b"hello world", 2);
        let manifest = manifest_for_payload(1, &payload);

        assert!(manifest.verify(1, &payload).is_ok());
    }

    #[test]
    fn rejects_length_mismatch() {
        let payload = payload(b"hello world", 2);
        let manifest = PayloadManifest::new(1, 2, 12, checksum64(&payload.data));

        let err = manifest.verify(1, &payload).expect_err("length mismatch");

        match err {
            ManifestError::LengthMismatch { expected, found } => {
                assert_eq!(expected, 12);
                assert_eq!(found, 11);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn rejects_checksum_mismatch() {
        let payload = payload(b"hello world", 2);
        let manifest = PayloadManifest::new(1, 2, payload.data.len(), 0);

        let err = manifest.verify(1, &payload).expect_err("checksum mismatch");

        match err {
            ManifestError::ChecksumMismatch { expected, found } => {
                assert_eq!(expected, 0);
                assert_ne!(found, 0);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
