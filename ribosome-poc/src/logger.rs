use core::fmt;
use std::io::{self, Write};

/// An aggressive bit-level tracer that parses and hex-dumps incoming bytes.
/// This runs in its own thread to avoid blocking the fast path of the Splicer.
pub struct BitLogger;

impl BitLogger {
    pub fn log_event(event: LogEvent) {
        let mut stderr = io::stderr();

        match event {
            LogEvent::FetchFragment { seq, len } => {
                let _ = writeln!(
                    stderr,
                    "\x1b[36m[Core 0] FETCHER: Acquired fragment seq={}, len={} bytes\x1b[0m",
                    seq, len
                );
            }
            LogEvent::SpliceFragment { seq, data } => {
                let _ = writeln!(
                    stderr,
                    "\x1b[33m[Core 1] SPLICER: Processing seq={}\x1b[0m",
                    seq
                );
                Self::hexdump_bits(&mut stderr, &data);
            }
            LogEvent::MembraneCreated { fd } => {
                let _ = writeln!(
                    stderr,
                    "\x1b[35m[Core 1] MEMBRANE: memfd created at fd={}\x1b[0m",
                    fd
                );
            }
            LogEvent::ExecutionReady => {
                let _ = writeln!(stderr, "\x1b[31;1m[Core 1] RIBOSOME: Full assembly verified. Triggering execveat...\x1b[0m");
            }
            LogEvent::EvasionPassed => {
                let _ = writeln!(stderr, "\x1b[32m[Core 1] EVASION: Hypervisor/Debugger checks passed. Clean environment.\x1b[0m");
            }
        }
    }

    /// Prints a classic hex dump alongside binary (bit-level) representation
    fn hexdump_bits(w: &mut std::io::Stderr, data: &[u8]) {
        for (i, chunk) in data.chunks(8).enumerate() {
            let offset = i * 8;
            let mut hex_str = String::with_capacity(24);
            let mut bit_str = String::with_capacity(72);
            let mut ascii_str = String::with_capacity(8);

            for &b in chunk {
                hex_str.push_str(&format!("{:02x} ", b));
                bit_str.push_str(&format!("{:08b} ", b));
                if b >= 32 && b <= 126 {
                    ascii_str.push(b as char);
                } else {
                    ascii_str.push('.');
                }
            }

            // Pad the last line if it's less than 8 bytes
            while hex_str.len() < 24 {
                hex_str.push(' ');
            }
            while bit_str.len() < 72 {
                bit_str.push(' ');
            }

            let _ = writeln!(
                w,
                "  | 0x{:04x} | {} | {} | {} |",
                offset, hex_str, bit_str, ascii_str
            );
        }
    }
}

pub enum LogEvent {
    FetchFragment { seq: u16, len: usize },
    SpliceFragment { seq: u16, data: Vec<u8> },
    MembraneCreated { fd: i32 },
    ExecutionReady,
    EvasionPassed,
}
