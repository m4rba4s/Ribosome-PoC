# Ribosome PoC

Ribosome PoC is a Linux/x86_64 purple-team research harness for studying a
fragmented payload pipeline:

1. collect numbered fragments,
2. splice them into a contiguous payload,
3. verify the assembled payload against an explicit manifest,
4. optionally place the verified bytes in an anonymous `memfd`,
5. optionally transfer control with `execveat(AT_EMPTY_PATH)`.

The default path is intentionally non-destructive: it uses built-in lab
fragments, performs no network activity, and does not execute assembled bytes.

## Safety Model

This repository is for authorized lab research only.

- `cargo run` and `cargo run -- --audit` do not use the network and do not
  execute a payload.
- `--fetch` requires explicit operator consent through
  `RIBOSOME_LAB_NETWORK=1` and verifies the result against manifest
  environment variables.
- `--execute` requires the same network consent, a matching manifest, and an
  additional execution acknowledgement:
  `RIBOSOME_LAB_EXEC=I_ACCEPT_LAB_RISK`.
- The environment diagnostics are isolated behind `--diagnose-env`; they are
  not part of the default flow because timing checks are noisy and hurt
  reproducibility.

Do not run this against systems, networks, or payloads you do not own or have
explicit permission to test.

## Build And Test

```sh
cargo fmt --check
cargo check
cargo test
cargo run -- --audit
```

Expected audit output includes a generated manifest for the built-in lab
fragments and ends with:

```text
[+] Audit mode complete. No network or exec path was used.
```

## Modes

```text
ribosome-poc [--audit|--fetch|--execute|--diagnose-env]
```

`--audit`

Assembles built-in lab fragments, computes a manifest, verifies it, then exits.
This is the default mode.

`--fetch`

Fetches DNS TXT fragments from the configured lab source, assembles them, and
verifies the assembled payload against an operator-supplied manifest. It does
not execute the payload.

Required environment:

```sh
RIBOSOME_LAB_NETWORK=1
RIBOSOME_EXPECTED_FRAGMENTS=<count>
RIBOSOME_EXPECTED_LEN=<bytes>
RIBOSOME_EXPECTED_CHECKSUM64=<decimal-or-0xhex>
```

`--execute`

Runs the same fetch and manifest verification path, then uses the `memfd` and
`execveat` stage only after a second explicit acknowledgement:

```sh
RIBOSOME_LAB_EXEC=I_ACCEPT_LAB_RISK
```

`--diagnose-env`

Runs the explicit anti-debug/timing diagnostics and exits.

## Design Notes

The project keeps the core mechanism small on purpose:

- `fragments.rs` defines the fragment data model.
- `splicer.rs` sorts fragments and rejects empty payloads, missing sequence
  IDs, duplicate sequence IDs, and empty fragment data.
- `manifest.rs` checks manifest version, fragment count, payload length, and a
  small checksum.
- `network_t_rna.rs` implements the minimal DNS TXT transport used by the lab
  mode.
- `membrane.rs` owns `memfd_create`, write, seal, rewind, zeroization, and fd
  cleanup on error.
- `ribosome.rs` contains the `execveat(AT_EMPTY_PATH)` transfer.
- `evasion.rs` is kept as an explicit diagnostic module, not a default gate.

The current `checksum64` is a compact corruption guard, not a cryptographic
trust boundary. If this research moves beyond a closed lab, replace it with a
well-reviewed signature scheme from a maintained Rust crate instead of adding
custom cryptography.

## Defensive Observables

For blue-team validation in an authorized lab, monitor for:

- DNS TXT lookups to the configured lab domain,
- `memfd_create`,
- `fcntl(F_ADD_SEALS)`,
- `execveat` with `AT_EMPTY_PATH`,
- anomalous anonymous executable mappings.

Those observables should be documented in the lab report before any execution
mode is used.

## Publication Checklist

- Keep the default mode as `--audit`.
- Do not publish live payloads or operational infrastructure.
- Publish detection notes with any demonstration.
- Run `cargo fmt --check`, `cargo check`, and `cargo test`.
- Choose an explicit license before public release.
