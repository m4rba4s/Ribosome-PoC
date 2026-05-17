# Ribosome-PoC: Biomimetic Translation Lab

**Status:** authorized purple-team research instrument.

Ribosome-PoC models a payload lifecycle as cellular biochemistry: genetic
material is fragmented into carrier molecules, reassembled by a spliceosome,
validated by an assay serum, moved into a membrane vesicle, and observed at the
translation boundary.

This is not just a loader. The project is a paired red/blue laboratory:

- `ribosome-poc` is the experimental cell.
- `ribosome-assay` is the offline assay instrument.
- `Aegis` is the immune telemetry layer.
- `packed.zone` is a DNA library for local laboratory measurement.

## Demonstration Pathway

```bash
make build
make test
make pathway
make phenotype
make serum
make run_poc
```

The default harness path is an audit cycle. It proves assembly and manifest
verification without network transport or translation.

## Assay Instrument

`ribosome-assay` is the scientific control plane. It never uses the network and
never triggers translation.

```bash
cd ribosome-poc
cargo run --bin ribosome-assay -- pathway
cargo run --bin ribosome-assay -- phenotype ../packed.zone
cargo run --bin ribosome-assay -- serum ../packed.zone
```

Commands:

- `pathway`: prints the biochemical I/O pathway.
- `fingerprint <payload-file> [fragment-count]`: prints a molecular manifest
  for a local artifact.
- `phenotype <bind-zone-file>`: audits a DNA library: fragment continuity,
  decoded genome length, terminator codon, checksum, and current ribosome
  compatibility.
- `serum <bind-zone-file>`: emits the manifest variables expected by the
  controlled harness.

## Experimental Cell

```bash
cd ribosome-poc
cargo run -- --audit
```

The harness keeps the translation boundary explicit. Network transport and
translation require operator-provided serum values and lab acknowledgement.
That makes the experiment repeatable in front of other researchers without
turning the demo into guesswork.

## Repository Anatomy

- `ribosome-poc/`: Rust source for the experimental cell and assay instrument.
- `payload_packer.py`: local DNA-library generator for BIND TXT records.
- `aegis_loader.py` and `aegis_kernel.c`: immune telemetry for the
  `memfd_create -> execveat` transition.
- `yara_scanner.py`: `/proc` phenotype scanner for memfd-backed executables.
- `packed.zone`: local laboratory DNA library.
- `Makefile`: repeatable demonstration entrypoints.

## Scientific Claims

The project demonstrates:

- biomimetic fragmentation and reassembly,
- manifest-gated translation,
- anonymous membrane staging through `memfd_create`,
- explicit translation boundary through `execveat(AT_EMPTY_PATH)`,
- blue-team observability at the syscall and `/proc` layers,
- offline phenotype measurement before running the cell.

## Validation

```bash
cd ribosome-poc
cargo fmt --check
cargo check
cargo test
cargo run --bin ribosome-assay -- pathway
cargo run -- --audit
```

Use only in environments where you have explicit authorization.
