# whogoesthere

Linux persistence enumeration. Inspired by Patrick Wardle's macOS
[KnockKnock](https://objective-see.org/products/knockknock.html), but
re-thought from the ground up for Linux's very different persistence
surface (systemd, cron, init, dotfiles, udev — not LaunchAgents and kexts).

Surveys the high-value persistence vectors on a host and lists what's
installed at each one, with **package-ownership attribution** so that
distro-shipped entries are distinguishable from drops that no package owns.
The `UNTRACKED` flag on a finding is the primary malware signal.

## What it checks (v1)

| Checker     | What it surveys |
|-------------|-----------------|
| `systemd`   | `.service`, `.timer`, `.path`, `.socket` units in system, global-user, and per-user unit dirs. One finding per `Exec*` directive; trigger details and what the unit activates for non-service types. |
| `cron`      | `/etc/crontab`, `/etc/cron.d/`, `/etc/cron.{hourly,daily,weekly,monthly}/`, `/etc/anacrontab`, per-user crontabs (both Debian and RHEL spool layouts), `at` jobs. `@reboot` highlighted. |
| `init`      | SysV: `/etc/init.d/` scripts with rc-runlevel cross-reference, `/etc/rc.local`, `/etc/inittab`. |
| `shell`     | System rc files (`/etc/profile`, `/etc/profile.d/*`, `/etc/bash.bashrc`, `/etc/bashrc`, `/etc/zsh/*`) and per-user dotfiles (`.bashrc`, `.zshrc`, `.profile`, etc.) for every real user on the system. |
| `autostart` | XDG `.desktop` autostart entries: `/etc/xdg/autostart/` system-wide and `~/.config/autostart/` per user. Hidden/disabled flags surfaced. |
| `udev`      | `RUN+=` and `IMPORT{program}=` directives across `/etc/udev/rules.d/`, `/run/udev/rules.d/`, `/lib/udev/rules.d/`, `/usr/lib/udev/rules.d/`. |
| `modules`   | `/etc/modules` (Debian legacy), `modules-load.d/*.conf`, and `modprobe.d/*.conf` — with special focus on `install <module> <command>` directives, which run arbitrary commands. |
| `ld_so`     | `/etc/ld.so.preload` and `LD_PRELOAD` in `/etc/environment`. |
| `ssh`       | Per-user `~/.ssh/authorized_keys` (one finding per key, with `forced_command` surfaced when `command="..."` is set), per-user `~/.ssh/rc` and system `/etc/ssh/sshrc` login scripts, `ForceCommand` and `AuthorizedKeysCommand` in `/etc/ssh/sshd_config` and `sshd_config.d/*.conf` (with `Match` block context as metadata). |

## Usage

```sh
# All checkers, human-readable
cargo run --release

# JSON output
cargo run --release -- --format json

# List available checker names
cargo run --release -- --list-checkers

# Just one checker (repeatable)
cargo run --release -- --checker systemd --checker cron

# Only entries no package owns — the malware-triage signal
cargo run --release -- --untracked-only
```

## Reading the output

Each finding looks like:

```
[systemd] systemd service ExecStart= (system)
  source:  /etc/systemd/system/display-manager.service
  target:  /usr/bin/gdm
  scope:   system
  package: UNTRACKED
  description: GNOME Display Manager
  directive: ExecStart
  location: system
```

- `source` — the config file that defines the persistence
- `target` — what runs (binary path, command, schedule, listen address, etc.)
- `scope` — system-wide or scoped to a specific user
- `package` — `Owned { package: "..." }`, `UNTRACKED`, or `Unknown`
- `metadata` — checker-specific extras

**`UNTRACKED` is the signal.** A persistence entry that no package owns is
either user-edited (dotfiles), admin-installed (custom units, display-manager
selection), or malware. Filter for it and triage:

```sh
cargo run --release -- --untracked-only
cargo run --release -- --untracked-only --format json
```

## Performance

A full run on Fedora 44 (1353 findings across all nine checkers) takes
~0.7s. Package-ownership attribution is the hot path; it's done once at
startup by ingesting the entire `rpm` / `dpkg` / `pacman` file index into
a hash map, then served as O(1) lookups against each finding's source path.

## Building a single static binary

```sh
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
# binary: target/x86_64-unknown-linux-musl/release/whogoesthere
```

The release profile is configured with LTO + single codegen unit + symbol
stripping, so the binary is tight (~3–5 MB) and self-contained.

## Development

The tree currently passes every lint configuration below. They're
ordered roughly by strictness — `fmt --check` and the default
`-Dwarnings` clippy are the bare minimum for CI; the rest are useful
one-shot audits when adding code.

```sh
# Formatting
cargo fmt --all -- --check

# Default clippy, warnings as errors. `-Adeprecated` keeps churn
# from upstream API deprecations out of the failure signal.
cargo clippy --all-targets --all-features -- -Dwarnings -Adeprecated

# Stricter, opt-in lint groups (warnings, not errors — review before fixing)
cargo clippy --all-targets --all-features -- -Wclippy::pedantic
cargo clippy --all-targets --all-features -- -Wclippy::nursery
cargo clippy --all-targets --all-features -- -Wclippy::cargo

# "No silent panics" sweep — flags every .unwrap()/.expect()/dbg!/todo!/unimplemented!
cargo clippy --all-targets --all-features -- \
    -Wclippy::unwrap_used -Wclippy::expect_used \
    -Wclippy::dbg_macro -Wclippy::todo -Wclippy::unimplemented

# Release-mode check (occasionally catches lints that fire only under
# release codegen assumptions)
cargo clippy --release --all-targets --all-features -- -Dwarnings -Adeprecated
```

## Status

v1 is feature-complete for the nine checkers above. Tested on Fedora 44.
Debian/Ubuntu validation pending. See [TODO.md](TODO.md) for the follow-up
backlog: distro coverage, baseline+diff mode, and the remaining v2 vector
list (PAM, D-Bus, dynamic linker, display manager, dispatcher scripts,
package-manager hooks).

## Why the name?

`whogoesthere` is the sentry's challenge — same idea as KnockKnock (who's
at the door?) but it's its own tool with its own scope, not a port. The
name also avoids collisions with the existing macOS KnockKnock binary if
both ever sit on the same machine.
