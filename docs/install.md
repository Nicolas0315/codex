## Installing & building

### System requirements

| Requirement                 | Details                                                         |
| --------------------------- | --------------------------------------------------------------- |
| Operating systems           | macOS 12+, Ubuntu 20.04+/Debian 10+, or Windows 11 **via WSL2** |
| Git (optional, recommended) | 2.23+ for built-in PR helpers                                   |
| RAM                         | 4-GB minimum (8-GB recommended)                                 |

### DotSlash

The GitHub Release also contains a [DotSlash](https://dotslash-cli.com/) file for the Codex CLI named `codex`. Using a DotSlash file makes it possible to make a lightweight commit to source control to ensure all contributors use the same version of an executable, regardless of what platform they use for development.

### Build from source

```bash
# Clone the repository and navigate to the root of the Cargo workspace.
git clone https://github.com/openai/codex.git
cd codex/codex-rs

# Install the Rust toolchain, if necessary.
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
rustup component add rustfmt
rustup component add clippy
# Install helper tools used by the workspace justfile:
cargo install --locked just
# DotSlash fetches pinned development tools such as buildifier on first use.
cargo install --locked dotslash
# Install nextest for the `just test` helper.
cargo install --locked cargo-nextest

# Build Codex.
cargo build

# Launch the TUI with a sample prompt.
cargo run --bin codex -- "explain this codebase to me"

# After making changes, use the root justfile helpers (they default to codex-rs):
just fmt
just fix -p <crate-you-touched>

# Run the relevant tests (project-specific is fastest), for example:
just test -p codex-tui
# `just test` runs the test suite via nextest:
just test
# Avoid `--all-features` for routine local runs because it increases build
# time and `target/` disk usage by compiling additional feature combinations.
```

## Tracing / verbose logging

Codex is written in Rust, so it honors the `RUST_LOG` environment variable to configure its logging behavior.

The TUI records diagnostics in bounded local stores by default. Set `log_dir` explicitly to enable a plaintext TUI log for a run:

```bash
codex -c log_dir=./.codex-log
tail -F ./.codex-log/codex-tui.log
```

The non-interactive mode (`codex exec`) defaults to `RUST_LOG=error`, but messages are printed inline, so there is no need to monitor a separate file.

`RUST_LOG` does not affect the bounded local stores. To turn those down, set `CODEX_SQLITE_LOG`:

```bash
CODEX_SQLITE_LOG=warn    # keep WARN/ERROR diagnostics, drop the TRACE volume
CODEX_SQLITE_LOG=off     # record nothing
```

Leaving it unset keeps the default, which records everything except a short list of high-volume targets. Three things to know:

- It takes `level` and `target=level` directives separated by commas — a subset of what `RUST_LOG` accepts. Per-span field filters such as `[span{field=value}]` are not supported and cause the whole value to be ignored.
- A bare level is required. `CODEX_SQLITE_LOG=codex_core=debug` names a target but no default, which disables every target you did not name.
- The high-volume targets are clamped, so `CODEX_SQLITE_LOG=trace` does not restore them. Two of them span a subtree and can be lifted by naming a longer target, for example `CODEX_SQLITE_LOG=trace,hyper_util::client=debug`. The rest emit under the clamped name itself, so they cannot be raised at all.

Turning this down trades detail for history. The default records every TRACE event, and each partition keeps only its most recent rows, so a busy session can evict its own warnings and errors within seconds. Expect less per-event detail in `/feedback` and crash reports, and a longer window of the levels that usually matter. Unset it when you need full TRACE detail for a specific reproduction.

On macOS, applications launched from Finder do not inherit shell environment variables. Use `launchctl setenv CODEX_SQLITE_LOG warn` if you start Codex from outside a terminal.

See the Rust documentation on [`RUST_LOG`](https://docs.rs/env_logger/latest/env_logger/#enabling-logging) for more information on the configuration options.
