# whogoesthere

[![CI](https://github.com/mikemadden42/whogoesthere/actions/workflows/ci.yml/badge.svg)](https://github.com/mikemadden42/whogoesthere/actions/workflows/ci.yml)

Linux persistence enumeration. Inspired by Patrick Wardle's macOS
[KnockKnock](https://objective-see.org/products/knockknock.html), but
re-thought from the ground up for Linux's very different persistence
surface (systemd, cron, init, dotfiles, udev — not LaunchAgents and kexts).

Surveys the high-value persistence vectors on a host and lists what's
installed at each one, with **package-ownership attribution** so that
distro-shipped entries are distinguishable from drops that no package owns.
The `UNTRACKED` flag on a finding is the primary malware signal; the
`--diff` mode is the operationally useful complement — what's *new* since
the last snapshot.

## What it checks

| Checker     | What it surveys |
|-------------|-----------------|
| `systemd`   | `.service`, `.timer`, `.path`, `.socket` units in system, global-user, and per-user unit dirs. One finding per `Exec*` directive; trigger details and what the unit activates for non-service types. |
| `cron`      | `/etc/crontab`, `/etc/cron.d/`, `/etc/cron.{hourly,daily,weekly,monthly}/`, `/etc/anacrontab`, per-user crontabs (both Debian and RHEL spool layouts), `at` jobs. `@reboot` highlighted. |
| `init`      | SysV: `/etc/init.d/` scripts with rc-runlevel cross-reference, `/etc/rc.local`, `/etc/inittab`. |
| `shell`     | System rc files (`/etc/profile`, `/etc/profile.d/*`, `/etc/bash.bashrc`, `/etc/bashrc`, `/etc/zsh/*`) and per-user dotfiles (`.bashrc`, `.zshrc`, `.profile`, etc.) for every real user on the system. |
| `autostart` | XDG `.desktop` autostart entries: `/etc/xdg/autostart/` system-wide and `~/.config/autostart/` per user. Hidden/disabled flags surfaced. |
| `udev`      | `RUN+=` and `IMPORT{program}=` directives across `/etc/udev/rules.d/`, `/run/udev/rules.d/`, `/lib/udev/rules.d/`, `/usr/lib/udev/rules.d/`. |
| `modules`   | `/etc/modules` (Debian legacy), `modules-load.d/*.conf`, and `modprobe.d/*.conf` — with special focus on `install <module> <command>` directives, which run arbitrary commands. |
| `ld_so`     | `/etc/ld.so.preload`, `LD_PRELOAD` in `/etc/environment`, and the per-directory search-path config — `/etc/ld.so.conf` plus `/etc/ld.so.conf.d/*.conf`. Each search-path entry and `include` directive emits a finding so an UNTRACKED `.conf` in `ld.so.conf.d/` adding an attacker-controlled directory (T1574.006-class library hijacking) is independently surfaced. |
| `ssh`       | Per-user `~/.ssh/authorized_keys` (one finding per key, with `forced_command` surfaced when `command="..."` is set), per-user `~/.ssh/rc` and system `/etc/ssh/sshrc` login scripts, `ForceCommand` and `AuthorizedKeysCommand` in `/etc/ssh/sshd_config` and `sshd_config.d/*.conf` (with `Match` block context as metadata). |
| `pam`       | One finding per non-comment line in `/etc/pam.d/*` — type (auth/account/password/session, plus leading-dash variants), control (including bracketed `[key=value ...]` form), module path, and module args surfaced as metadata. PAM runs at every authentication (console, GUI, sudo, su, cron, screen unlock) so module injection here is one of the broadest persistence vectors on Linux. |
| `dbus`      | D-Bus auto-activation registrations under `/usr/share/dbus-1/services/`, `/etc/dbus-1/services/`, the matching `system-services/` dirs, and per-user `~/.local/share/dbus-1/services/`. One finding per `.service` file: target is `Exec=` (or `(activates systemd unit) <name>` when only `SystemdService=` is set), with `bus_name`, `bus` (session/system), `run_as`, and `systemd_service` surfaced as metadata. Auto-activation triggers on the first D-Bus client request for the bus name (T1543.002-class). |
| `network_manager` | NetworkManager dispatcher scripts under `/etc/NetworkManager/dispatcher.d/` plus the phase sub-dirs (`pre-up.d/`, `pre-down.d/`, `no-wait.d/`). One finding per script with `size_bytes`, `executable`, and `phase` metadata. Non-executable scripts are still surfaced (they're dormant but present) with a `note` explaining they won't run. Each script fires on every network state change (T1037.005-class — boot/logon initialization scripts). |
| `display_manager` | X session hooks: per-user `~/.xprofile`, `~/.xsession`, `~/.xinitrc`, `~/.xsessionrc`; system `/etc/X11/xinit/xinitrc`, `/etc/X11/Xsession`, `/etc/X11/Xsession.d/*` (Debian/Ubuntu sourced fragments), `/etc/lightdm/Xsession`, `/etc/gdm/{PostLogin,PreSession}/Default`. One finding per file with `size_bytes`, `executable`, and `dm` metadata (`xinit`/`xsession`/`lightdm`/`gdm`; omitted for per-user dotfiles since they're read by multiple DMs). Each runs at login — T1547.013-class XDG/session-startup persistence. |
| `apt_hooks` | Apt config hooks under `/etc/apt/apt.conf` and `/etc/apt/apt.conf.d/*.conf`. One finding per shell command in any of the persistence-relevant directives — `DPkg::Pre-Install-Pkgs`, `DPkg::{Pre,Post}-Invoke`, `DPkg::Post-Invoke-Success`, `APT::Update::{Pre,Post}-Invoke`, `APT::Update::Post-Invoke-Success`. Parser handles the three apt.conf forms (single-value, append-list `::`, and `{ "cmd"; "cmd"; }` block) and respects `//`, `/* */`, and `#` comments without truncating inside quoted strings. T1543/T1546-class — fires on every apt/dpkg operation. |

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

# Diff two snapshots — surface persistence vectors that appeared or
# disappeared between runs. The actually-useful operational workflow.
cargo run --release -- --format json > today.json
# ... time passes, system gets rerun ...
cargo run --release -- --diff yesterday.json today.json
```

## Baseline + diff workflow

The `UNTRACKED` filter answers "what's not in any package?" The `--diff` mode
answers the more important question: **what changed since last time?**

```sh
# Snapshot the host
whogoesthere --format json > /var/lib/whogoesthere/baseline.json

# Later — after package updates, after suspected compromise, on a schedule:
whogoesthere --format json > /tmp/current.json
whogoesthere --diff /var/lib/whogoesthere/baseline.json /tmp/current.json
```

Findings present only in the new snapshot are emitted with `+`; findings
present only in the old snapshot with `-`. JSON output (`--format json`)
emits `{"added": [...], "removed": [...]}`.

Diff identity matches on the persistence vector — `category`, `source`,
`target`, `mechanism`, `scope` — and deliberately ignores `package` status
and `metadata`. So a `pam` rule that gets renumbered when a line is
inserted above it won't appear in the diff; only the actually-new rule
will. Similarly, a finding flipping from `UNTRACKED` to `Owned` (because
the host installed the package between runs) is not a diff event.

## Reading the output

Each finding looks like:

```
[ssh] authorized_keys entry — grants passwordless SSH login
  source:  /home/madden/.ssh/authorized_keys
  target:  madden@old-laptop
  scope:   user madden (uid 1000)
  package: UNTRACKED
  keytype: ssh-ed25519
  line:    3
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

A full run on Fedora 44 (1725 findings across all 14 checkers) takes
~0.7s. Package-ownership attribution is the hot path; it's done once at
startup by ingesting the entire `rpm` / `dpkg` / `pacman` / `apk` file index
into a hash map, then served as O(1) lookups against each finding's source
path. All available package-manager backends are detected and their indices
merged, so multi-PM hosts (e.g. Fedora with `dpkg` installed for cross-distro
builds) don't silently lose attribution for the unselected backend.

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

v1 is feature-complete. 14 checker categories cover the major Linux
persistence vectors; four package-manager attribution backends (rpm,
dpkg, pacman, apk) all detected at startup and merged. `--diff` mode
gives the operational workflow.

Validated on:
- **Fedora 44 (x86_64)** — 1725 findings, 13 UNTRACKED (irreducible: 9
  SSH keys + 4 user dotfiles, exactly the analyst-worthy set).
- **Ubuntu 24.04 (arm64)** — 1696 findings, 8 UNTRACKED (irreducible: 4
  user dotfiles + 2 SSH keys + 1 custom unit + 1 netplan runtime case).
- **Manjaro (pacman)** — pacman backend attributes every owned package
  correctly (epoch-prefixed versions, e.g. `avahi-1:0.9rc4-1`, included).
  UNTRACKED set is the same shape: per-user dotfiles, autostart entries,
  and a custom `~/.xinitrc`, plus a distro-customized `/etc/pam.d/polkit-1`.
- **Alpine (apk, OpenRC)** — 73 findings, 1 UNTRACKED (`/root/.profile`,
  the lone triage target) after the busybox-openrc post-install allowlist
  reattributes the 5 baseline root-crontab entries. Confirms the apk
  backend handles `-rN` revision suffixes and `_pN` patch markers
  (`openssh-server-common-openrc-10.3_p1-r0`), and that the systemd /
  PAM / udev / dbus / autostart checkers gracefully no-op when their
  substrates aren't present.
- **AlmaLinux 10.2 (rpm, RHEL-family server)** — 7 UNTRACKED, all user
  dotfiles. rpm pkgids carry the AlmaLinux vendor markers cleanly
  (`systemd-257-23.el10_2.2.alma.1.x86_64`). SSSD, SELinux PAM
  (`pam_selinux_permit.so`, `pam_sepermit.so`), the RHEL `substack`
  PAM control, Cockpit, podman, and dnf-system-upgrade all parse and
  attribute correctly. `sshd_config` 0600 perms gracefully degrade
  (the entry surfaces with `unreadable` metadata, "rerun as root").

All on irreducible noise floors — every remaining UNTRACKED is a real
triage target, not a false positive.

## Why the name?

`whogoesthere` is the sentry's challenge — same idea as KnockKnock (who's
at the door?) but it's its own tool with its own scope, not a port. The
name also avoids collisions with the existing macOS KnockKnock binary if
both ever sit on the same machine.
