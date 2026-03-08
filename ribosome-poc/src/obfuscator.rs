/// A simple, zero-dependency XOR obfuscator for strings and byte arrays.
/// In a full `no_std` environment without proc-macros, compile-time evaluation
/// of strings is tricky. We'll use a const array approach to store the XORed
/// bytes and decrypt them on the fly during execution.

pub struct ObfuscatedString<const N: usize> {
    data: [u8; N],
    key: u8,
}

impl<const N: usize> ObfuscatedString<N> {
    /// Creates a new obfuscated string at compile time
    pub const fn new(cleartext: &[u8; N], key: u8) -> Self {
        let mut data = [0u8; N];
        let mut i = 0;
        while i < N {
            data[i] = cleartext[i] ^ key;
            i += 1;
        }
        Self { data, key }
    }

    /// Decrypts the string at runtime into a new Vec
    #[inline(never)] // Prevent compiler from leaking the cleartext by aggressive optimization
    pub fn decrypt(&self) -> Vec<u8> {
        let mut clear = Vec::with_capacity(N);
        for &b in &self.data {
            clear.push(b ^ self.key);
        }
        clear
    }
}

/// Helper macro to generate an ObfuscatedString const.
/// Format: `obf!(b"my_string", 0x42)`
#[macro_export]
macro_rules! obf {
    ($bytes:expr, $key:expr) => {
        $crate::obfuscator::ObfuscatedString::new($bytes, $key)
    };
}
