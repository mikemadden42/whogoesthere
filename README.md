# knockknock

Linux persistence enumeration. A port of Patrick Wardle's macOS
[KnockKnock](https://objective-see.org/products/knockknock.html) to Linux.

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

## Usage

```sh
# All checkers, human-readable
cargo run --release

# JSON output
cargo run --release -- --format json

# Just one checker (repeatable)
cargo run --release -- --checker systemd --checker cron
```

## Reading the output

Each finding looks like:

```
[systemd] systemd service ExecStart= (system)
  source:  /etc/systemd/system/dbus-org.bluez.service
  target:  /usr/libexec/bluetooth/bluetoothd
  scope:   system
  package: UNTRACKED
  directive: ExecStart
  location: system
  service_type: dbus
  wanted_by: bluetooth.target
```

- `source` — the config file that defines the persistence
- `target` — what runs (binary path, command, schedule, listen address, etc.)
- `scope` — system-wide or scoped to a specific user
- `package` — `Owned { package: "..." }`, `UNTRACKED`, or `Unknown`
- `metadata` — checker-specific extras

**`UNTRACKED` is the signal.** A persistence entry that no package owns is
either user-edited (dotfiles), admin-installed (D-Bus aliases, custom
units), or malware. Filter for it and triage:

```sh
cargo run --release -- --format json | jq '[.[] | select(.package.status == "untracked")]'
```

## Building a single static binary

```sh
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
# binary: target/x86_64-unknown-linux-musl/release/knockknock
```

The release profile is configured with LTO + single codegen unit + symbol
stripping, so the binary is tight (~3–5 MB) and self-contained.

## Status

v1 is feature-complete for the eight checkers above. Tested on Fedora 44.
Debian/Ubuntu validation pending. See [TODO.md](TODO.md) for the follow-up
backlog: package-ownership caching (12× speedup), distro coverage,
`--untracked-only` and baseline+diff modes, and the v2 vector list (SSH,
PAM, D-Bus, dynamic linker, display manager, dispatcher scripts,
package-manager hooks).

## Why a port, not a rewrite of KnockKnock?

The original is macOS-only — it understands LaunchAgents, LaunchDaemons,
kexts, login items, etc. Linux's persistence surface is entirely different
(systemd, cron, init, dotfiles, udev). Same idea, different mechanisms.
