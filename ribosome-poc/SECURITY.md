# Security Policy

## Scope

This project is a purple-team research harness for authorized laboratory use.
It must not be used against systems, networks, or payloads without explicit
permission.

## Reporting

If you find a safety issue, bypass of the consent gates, unsafe default
behavior, or a bug that causes unintended execution, open a private report with
the repository owner before publishing details.

Include:

- affected commit,
- operating system and architecture,
- command used,
- expected behavior,
- observed behavior,
- whether network or execution consent variables were set.

## Safety Invariants

The following properties are intentional and should be preserved:

- default mode performs no network activity,
- default mode does not execute assembled bytes,
- network fetch requires `RIBOSOME_LAB_NETWORK=1`,
- execution requires a matching manifest and
  `RIBOSOME_LAB_EXEC=I_ACCEPT_LAB_RISK`,
- environment diagnostics are opt-in through `--diagnose-env`.

Changes that weaken those properties should be treated as security-sensitive.
