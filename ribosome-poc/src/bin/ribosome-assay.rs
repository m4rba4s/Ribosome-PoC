use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::process;

const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;

#[derive(Debug)]
struct Manifest {
    version: u16,
    fragment_count: usize,
    total_len: usize,
    checksum64: u64,
}

#[derive(Debug)]
struct ZoneAudit {
    manifest: Manifest,
    eof_seq: Option<u16>,
    max_seq: u16,
    receiver_compatible: bool,
}

fn main() {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let result = match args.first().map(String::as_str) {
        None | Some("help") | Some("--help") | Some("-h") => {
            print_usage();
            Ok(())
        }
        Some("pathway") => {
            print_pathway();
            Ok(())
        }
        Some("fingerprint") => fingerprint_command(&args[1..]),
        Some("serum") => serum_command(&args[1..]),
        Some("phenotype") => phenotype_command(&args[1..]),
        Some(other) => Err(format!("unknown command: {other}")),
    };

    if let Err(e) = result {
        eprintln!("[!] {e}");
        process::exit(1);
    }
}

fn fingerprint_command(args: &[String]) -> Result<(), String> {
    let path = args.first().ok_or_else(|| {
        "usage: ribosome-assay fingerprint <payload-file> [fragment-count]".to_string()
    })?;
    let fragment_count = match args.get(1) {
        Some(raw) => parse_usize(raw, "fragment-count")?,
        None => 1,
    };

    let data = fs::read(path).map_err(|e| format!("failed to read {path}: {e}"))?;
    let manifest = manifest_for(fragment_count, &data);
    println!("molecular_fingerprint={path}");
    print_manifest(&manifest);
    Ok(())
}

fn serum_command(args: &[String]) -> Result<(), String> {
    let path = args
        .first()
        .ok_or_else(|| "usage: ribosome-assay serum <bind-zone-file>".to_string())?;
    let text = fs::read_to_string(path).map_err(|e| format!("failed to read {path}: {e}"))?;
    let audit = audit_zone(&text)?;

    eprintln!("[+] serum prepared from genetic library: {path}");
    print_env(&audit.manifest);
    Ok(())
}

fn phenotype_command(args: &[String]) -> Result<(), String> {
    let path = args
        .first()
        .ok_or_else(|| "usage: ribosome-assay phenotype <bind-zone-file>".to_string())?;
    let text = fs::read_to_string(path).map_err(|e| format!("failed to read {path}: {e}"))?;
    let audit = audit_zone(&text)?;

    eprintln!("[+] phenotype assay complete: {path}");
    if let Some(seq) = audit.eof_seq {
        eprintln!("[+] terminator codon found at sequence {seq}");
    } else {
        eprintln!("[!] terminator codon not found; receiver will stop only on timeout/error");
    }
    if audit.receiver_compatible {
        eprintln!("[+] ribosome compatibility: ok");
    } else {
        eprintln!(
            "[!] ribosome compatibility: genome uses sequence {}, current receiver limit is 255",
            audit.max_seq
        );
    }

    print_manifest(&audit.manifest);
    print_env(&audit.manifest);
    Ok(())
}

fn audit_zone(text: &str) -> Result<ZoneAudit, String> {
    let mut fragments = BTreeMap::<u16, Vec<u8>>::new();
    let mut eof_seq = None;

    for (line_no, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('$') {
            continue;
        }

        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 4 || !fields.iter().any(|field| *field == "TXT") {
            continue;
        }

        let seq = fields[0]
            .parse::<u16>()
            .map_err(|_| format!("line {}: sequence id must be a number", line_no + 1))?;

        let txt = extract_txt(line)
            .ok_or_else(|| format!("line {}: TXT record has no quoted data", line_no + 1))?;
        if txt == "EOF" {
            eof_seq = Some(seq);
            continue;
        }

        let data = decode_b64(&txt).map_err(|e| format!("line {}: {e}", line_no + 1))?;
        if data.is_empty() {
            return Err(format!("line {}: decoded fragment is empty", line_no + 1));
        }
        if fragments.insert(seq, data).is_some() {
            return Err(format!("line {}: duplicate sequence id {seq}", line_no + 1));
        }
    }

    if fragments.is_empty() {
        return Err("zone contains no payload fragments".to_string());
    }

    let mut expected = 0u16;
    let mut assembled = Vec::new();
    for (seq, data) in fragments.iter() {
        if *seq != expected {
            return Err(format!("missing sequence id {expected} before {seq}"));
        }
        assembled.extend_from_slice(data);
        expected += 1;
    }

    Ok(ZoneAudit {
        manifest: manifest_for(fragments.len(), &assembled),
        eof_seq,
        max_seq: *fragments.keys().last().unwrap_or(&0),
        receiver_compatible: fragments.keys().all(|seq| *seq <= u8::MAX as u16),
    })
}

fn extract_txt(line: &str) -> Option<String> {
    let mut out = String::new();
    let mut in_quote = false;
    let mut saw_quote = false;

    for ch in line.chars() {
        match ch {
            '"' => {
                in_quote = !in_quote;
                saw_quote = true;
            }
            _ if in_quote => out.push(ch),
            _ => {}
        }
    }

    saw_quote.then_some(out)
}

fn decode_b64(input: &str) -> Result<Vec<u8>, String> {
    let clean = input
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .collect::<Vec<_>>();
    if clean.len() % 4 != 0 {
        return Err("base64 length is not a multiple of 4".to_string());
    }

    let mut out = Vec::with_capacity((clean.len() / 4) * 3);
    for chunk in clean.chunks(4) {
        let a = b64_value(chunk[0])?;
        let b = b64_value(chunk[1])?;
        let c = if chunk[2] == b'=' {
            None
        } else {
            Some(b64_value(chunk[2])?)
        };
        let d = if chunk[3] == b'=' {
            None
        } else {
            Some(b64_value(chunk[3])?)
        };

        out.push((a << 2) | (b >> 4));
        if let Some(c) = c {
            out.push(((b & 0x0f) << 4) | (c >> 2));
            if let Some(d) = d {
                out.push(((c & 0x03) << 6) | d);
            }
        } else if d.is_some() {
            return Err("invalid base64 padding".to_string());
        }
    }

    Ok(out)
}

fn b64_value(byte: u8) -> Result<u8, String> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        b'=' => Err("unexpected base64 padding".to_string()),
        other => Err(format!("invalid base64 byte 0x{other:02x}")),
    }
}

fn manifest_for(fragment_count: usize, data: &[u8]) -> Manifest {
    Manifest {
        version: 1,
        fragment_count,
        total_len: data.len(),
        checksum64: checksum64(data),
    }
}

fn checksum64(data: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET_BASIS;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

fn parse_usize(raw: &str, label: &str) -> Result<usize, String> {
    raw.parse::<usize>()
        .map_err(|_| format!("{label} must be a positive integer"))
}

fn print_manifest(manifest: &Manifest) {
    println!("version={}", manifest.version);
    println!("fragments={}", manifest.fragment_count);
    println!("len={}", manifest.total_len);
    println!("checksum64=0x{:016x}", manifest.checksum64);
}

fn print_env(manifest: &Manifest) {
    println!();
    println!("RIBOSOME_EXPECTED_FRAGMENTS={}", manifest.fragment_count);
    println!("RIBOSOME_EXPECTED_LEN={}", manifest.total_len);
    println!(
        "RIBOSOME_EXPECTED_CHECKSUM64=0x{:016x}",
        manifest.checksum64
    );
}

fn print_pathway() {
    println!("Ribosome biochemical pathway");
    println!();
    println!("  DNA library: payload file or BIND TXT zone");
    println!("          |");
    println!("          v");
    println!("  tRNA carriers: sequence id + base64 fragment");
    println!("          |");
    println!("          v");
    println!("  spliceosome: ordering, continuity, duplicate rejection");
    println!("          |");
    println!("          v");
    println!("  assay serum: version + fragment count + length + checksum64");
    println!("          |");
    println!("          v");
    println!("  membrane vesicle: memfd_create + sealing");
    println!("          |");
    println!("          v");
    println!("  translation event: execveat(AT_EMPTY_PATH)");
    println!();
    println!("Compatibility note:");
    println!("  The current harness receiver uses an 8-bit sequence id.");
    println!("  ribosome-assay can still phenotype larger zone files and will report");
    println!("  whether a zone is compatible with that receiver.");
}

fn print_usage() {
    println!("usage:");
    println!("  ribosome-assay pathway");
    println!("  ribosome-assay fingerprint <payload-file> [fragment-count]");
    println!("  ribosome-assay serum <bind-zone-file>");
    println!("  ribosome-assay phenotype <bind-zone-file>");
    println!();
    println!("The assay instrument performs offline lab measurements only.");
    println!("It does not use the network and never triggers translation.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_base64() {
        assert_eq!(decode_b64("aGVsbG8=").expect("decode"), b"hello");
    }

    #[test]
    fn extracts_multi_string_txt() {
        let txt = extract_txt(r#"0 IN TXT "aGVs" "bG8=""#).expect("txt");
        assert_eq!(txt, "aGVsbG8=");
    }

    #[test]
    fn audits_zone_manifest() {
        let zone = r#"
$ORIGIN payload.test.local.
0 IN TXT "aGVs"
1 IN TXT "bG8="
2 IN TXT "EOF"
"#;

        let audit = audit_zone(zone).expect("audit");

        assert_eq!(audit.manifest.fragment_count, 2);
        assert_eq!(audit.manifest.total_len, 5);
        assert_eq!(audit.eof_seq, Some(2));
        assert!(audit.receiver_compatible);
    }

    #[test]
    fn audits_large_zone_but_marks_receiver_incompatible() {
        let mut zone = String::from("$ORIGIN payload.test.local.\n");
        for seq in 0..=256 {
            zone.push_str(&format!("{seq} IN TXT \"YQ==\"\n"));
        }
        zone.push_str("257 IN TXT \"EOF\"\n");

        let audit = audit_zone(&zone).expect("audit");

        assert_eq!(audit.manifest.fragment_count, 257);
        assert_eq!(audit.manifest.total_len, 257);
        assert_eq!(audit.max_seq, 256);
        assert!(!audit.receiver_compatible);
    }
}
