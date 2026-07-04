# Ports of bootwarden

The same **core check** — locate EFI firmware volumes (`_FVH` + header
checksum), detect the Secure Boot key variables (PK / KEK / db / dbx) stored as
UTF-16LE names, and count unsigned PE/TE executable modules — ported across
languages so you can drop bootwarden into any stack or ship a single static
binary. Every port is **passive/offline**: it analyses a firmware dump you
already have and never touches the network or a device. All ports emit the same
JSON shape (`tool`, `verdict`, `firmware_volumes`, `secureboot_vars`,
`modules`, `findings`) and the same PASS/FAIL exit code.

| Language | Path | Run | Test |
|---|---|---|---|
| Python (reference) | `../bootwarden/` | `bootwarden scan firmware.bin` | `pytest -q` |
| JavaScript / Node | `javascript/` | `node ports/javascript/index.js firmware.bin` | `node --test` |
| Go | `go/` | `cd ports/go && go run . firmware.bin` | `go test ./...` |
| Rust | `rust/` | `cd ports/rust && cargo run -- firmware.bin` | `cargo test` |
| Shell (POSIX) | `shell/` | `bash ports/shell/bootwarden.sh firmware.bin` | `bash ports/shell/test.sh` |

The Go and Rust ports are **built and tested on GitHub runners** (see
`.github/workflows/ports.yml`); the Go/Rust toolchains are not assumed to be
present locally. The JavaScript and Shell ports run anywhere Node / a POSIX
shell is available and are covered by the same CI workflow.

Contributions of additional ports (Ruby, C#, Bun, Deno, WASM) are welcome — see
../CONTRIBUTING.md.
