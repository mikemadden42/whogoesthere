# whogoesthere TODO

## Known bugs & correctness gaps

- [x] **dpkg attribution breaks on merged-`/usr` systems (high severity).**
      *Fixed.* On modern Debian/Ubuntu, `/lib`, `/bin`, `/sbin` are symlinks into
      `/usr/lib`, etc. dpkg records the *unmerged* spelling in its `.list`
      files (e.g. `/lib/systemd/system/rsyslog.service`), so the ownership
      index is keyed under `/lib/...`. But checkers scan unit/rule dirs
      through `util::canonical_unique`, which resolves the symlink, so a
      finding's `source` is the *merged* spelling (`/usr/lib/systemd/system/
      rsyslog.service`). `OwnershipIndex::owner` does a literal `HashMap`
      lookup, the two spellings never match, and every package-shipped file
      under `/usr/{lib,bin,sbin}` is misreported `UNTRACKED`.
      Impact: on a stock Ubuntu test run, ~956 of 1019 UNTRACKED findings
      were false positives (clustered under `/usr/lib/systemd/system` and
      `/usr/lib/udev/rules.d`) — only ~60 were genuinely unowned. This
      drowns the primary malware signal. rpm is unaffected because Fedora's
      rpm DB already stores the canonical `/usr/...` spelling, which is why
      the README's clean Fedora run never surfaced it. (See git
      `371d2dd Flag dpkg cache as unverified on real Debian data`.)
      Fix: normalize both sides into one namespace. Preferred approach —
      in `build_dpkg_index`, detect merged-`/usr` once (is `/lib` a
      symlink?) and insert each path under *both* its raw spelling and its
      `/lib→/usr/lib`, `/bin→/usr/bin`, `/sbin→/usr/sbin` rewrite, so
      lookups hit regardless of which spelling a finding carries. Cheaper
      than per-file `canonicalize()` (no extra syscalls) and stays correct
      on non-merged systems. Verify by re-running on a merged box and
      confirming the UNTRACKED count collapses to the genuinely-unowned set.
      *Result: on this Ubuntu box UNTRACKED dropped 1019 → 73 (total findings
      unchanged at 1288); under `/usr/lib/systemd/system`, 414 now attributed
      vs 11 genuinely unowned. Unit-tested in `package_ownership::tests`.*
- [ ] **`detect()` picks a single package-manager backend, first match wins**
      (`package_ownership.rs`). On a host with both `dpkg` and `rpm`
      installed, only dpkg-owned files get attributed; every rpm-owned file
      falls through to `UNTRACKED`. Rare, but it produces false positives in
      exactly the signal that matters. Consider building all available
      backends and merging their indices, or at least documenting the
      first-match behavior.
- [x] **Unreadable files are silently flagged as findings with no indication
      they couldn't be read.** *Fixed.* `shell::check_file`,
      `init::scan_initd`, and `init::scan_rc_local` now probe readability via
      `fs::File::open()` after the stat-based finding is built. If the open
      fails, an `unreadable: rerun as root to inspect` metadata key is added,
      so a `0600 root:root` file like `/etc/profile.d/debuginfod.sh` running
      unprivileged is no longer indistinguishable from a benign empty
      finding. `scan_inittab` already reads content directly and returns no
      findings on failure — separate bug, out of scope here.
- [ ] **`which()` shells out per probe** (`package_ownership.rs`) via
      `sh -c "command -v <prog>"`. Works, but a direct `$PATH` scan would drop
      the shell dependency. Low priority — `prog` is always a hardcoded literal
      today, so there's no injection surface.
- [ ] **`autostart::SYSTEM_DIRS` includes `/usr/xdg/autostart`**, which is not
      a standard XDG path (the real one is `/etc/xdg/autostart`). Harmless — it
      just no-ops — but it's dead config worth removing or documenting.
- [ ] **`real_users()` scopes to root + UID 1000–65533**, deliberately skipping
      system accounts (1–999). Those can still own dotfile/crontab persistence
      if they have a real login shell. Reasonable default, but undocumented —
      add a comment noting the exclusion is intentional.

## Testing

- [ ] **No unit tests exist anywhere in the tree.** The entire value of the
      tool is parser correctness, and the riskiest logic is exactly the
      parsing — all pure functions over `&str`, ideal for table-driven tests
      with zero filesystem dependency. A silent parser regression produces
      *wrong attribution* in a security tool, which is worse than a crash.
      Highest-value targets:
      - `udev::extract_with_prefixes` — manual byte-scanning with
        earliest-match-wins prefix selection; subtle and completely
        unexercised.
      - `cron::parse_cron_line` — field counting, `@reboot` vs 5-field
        schedules, env-var-line skipping, presence/absence of the user field.
      - `systemd::parse_ini` and the timer/path/socket activation-resolution
        logic (`activated_unit_name`).
      - `package_ownership` dpkg/pacman/rpm index parsers — three of these are
        already flagged "unverified on real data" elsewhere in this file.

## Performance

- [x] Cache package ownership lookups. *Done.* Pre-scan via
      `rpm -qa --qf "[%{=NAME}-%{=VERSION}-%{=RELEASE}.%{=ARCH}\t%{FILENAMES}\n]"`
      on RHEL/Fedora and `/var/lib/dpkg/info/*.list` walk on Debian builds a
      `HashMap<PathBuf, String>` at startup. Fedora full run: 15s → 0.76s
      (~20× speedup).
- [ ] Consider parallel checker dispatch. Currently sequential; checkers are
      embarrassingly parallel and could run on a thread pool. Lower priority
      now that total runtime is sub-second.

## Distro coverage

- [ ] Exercise the `init` checker on Debian/Ubuntu. Fedora has no SysV init at
      all, so init returned 0 findings — the parsing path is unexercised on
      real data.
- [ ] Verify per-user crontabs on Debian. The `/var/spool/cron/crontabs/` path
      is supported in code but unexercised on this baseline.
- [ ] Smoke-test the dpkg branch of the package-ownership cache on a real
      Debian/Ubuntu box. Coded against the standard `/var/lib/dpkg/info/*.list`
      layout (one absolute path per line, `:arch` stripped from filename to
      match `dpkg -S`) but never exercised on real data. Check: total finding
      count, UNTRACKED count looks sane, dpkg-diverted paths aren't producing
      noisy false-UNTRACKEDs.
- [ ] Smoke-test the pacman branch of the package-ownership cache on a real
      Arch box. Same caveat as dpkg — code is written against documented
      `/var/lib/pacman/local/*/files` layout but unverified. Check that
      `%FILES%`-section parsing is correct, total/UNTRACKED counts are sane,
      and that the directory-name-as-pkgid format reads cleanly in output.
- [ ] Check snap-generated systemd units on Ubuntu. They live in
      `/etc/systemd/system/` and may all show as UNTRACKED because snapd
      synthesizes them rather than dpkg-installing them. A pattern filter for
      `snap.*` may be needed.
- [ ] Run against Alpine (OpenRC, no systemd). Most checkers should
      gracefully no-op; verify nothing panics.

## Package-manager backends (beyond rpm/dpkg)

The package-ownership cache currently has two backends: rpm (via `rpm -qa`)
and dpkg (via `/var/lib/dpkg/info/*.list`). On any other distro, `detect()`
returns `PackageManager::None` and every finding gets `PackageOrigin::Unknown`
— the tool still surveys persistence, it just can't attribute. Tiered by
ROI for adding more:

### Worth adding
- [x] **Arch (pacman).** *Code-complete, unverified on real Arch.* Pre-scan
      walks `/var/lib/pacman/local/<pkg>-<ver>-<rel>/files`, reads the
      `%FILES%` section (one relative path per line; leading `/` prepended),
      and uses the directory name verbatim as the package identifier (so
      output matches `pacman -Qo`). Needs the same smoke-test treatment as
      the dpkg branch on a real Arch box.

### Worth considering (containers/cloud)
- [ ] **Alpine (apk)**. Small distro but ubiquitous in Docker. Package DB
      at `/lib/apk/db/installed` is a single concatenated file with `F:`
      lines for files (relative to current `P:`/`o:` package). Slightly
      different parser but cheap. Pairs with the existing "Run against
      Alpine" TODO under Distro coverage.

### Awkward fit — likely skip or detect-and-bail
- [ ] **NixOS**. Fundamentally different model: everything in `/nix/store`
      is package-owned by definition, and most config paths are symlinks
      into the store. `UNTRACKED` either fires on nothing or everything,
      depending on whether we resolve symlinks. Real malware persistence
      on NixOS lives in `configuration.nix` evaluation — a different
      problem entirely. Better to detect `/nix/store` and warn that
      whogoesthere's model doesn't apply, than to half-support it.

### Long tail (low ROI, skip unless asked)
- [ ] Gentoo (`/var/db/pkg/<cat>/<pkg>/CONTENTS`), Void Linux (xbps under
      `/var/db/xbps/`), Slackware (`/var/lib/pkgtools/packages/`). Each
      needs a bespoke parser; small userbases.

## Noise reduction & output

- [ ] Built-in allowlist for the Fedora `dbus-org.*` activation aliases under
      `/etc/systemd/system/`. They reliably show UNTRACKED but are benign.
- [ ] `--untracked-only` flag. The malware-detection workflow is "show me
      what's not in any package" — currently the user pipes through `jq`.
- [ ] Baseline + diff mode. `--baseline` writes a snapshot; `--diff old.json
      new.json` shows additions/removals. The diff is the actually-useful
      detection signal in practice.

## Additional persistence vectors (v2 candidates)

- [ ] SSH persistence: `~/.ssh/authorized_keys`, `~/.ssh/rc`, `/etc/ssh/sshrc`,
      `ForceCommand` in sshd_config.
- [ ] PAM: `/etc/pam.d/*` (auth-time module injection).
- [ ] D-Bus services: `/usr/share/dbus-1/services/`, `/etc/dbus-1/services/`
      (related to the systemd alias noise observed in v1).
- [ ] Dynamic linker search path: `/etc/ld.so.conf.d/*.conf`.
- [ ] Display-manager session hooks: gdm/sddm/lightdm Xsession scripts;
      `~/.xsession`, `~/.xinitrc`, `~/.xprofile`.
- [ ] NetworkManager dispatcher scripts: `/etc/NetworkManager/dispatcher.d/`.
- [ ] APT/DNF hooks: `/etc/apt/apt.conf.d/`, `/etc/dnf/plugins/`.

## Parser edge cases

- [ ] systemd unit-file line continuation (`\` at EOL) is not handled. Rare in
      the persistence-relevant keys but technically valid syntax.
- [ ] udev rule line continuation (`\` at EOL) likewise unhandled.
- [ ] systemd drop-in dirs (`<unit>.d/*.conf`) are not walked — a malicious
      override that adds `ExecStart` via a drop-in would be missed. NOTE: this
      is a genuine *detection blind spot*, not a cosmetic parser nicety — it's
      arguably the most security-relevant gap in this file and deserves
      promotion above the line-continuation items.
