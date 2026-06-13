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

- [x] **No unit tests exist anywhere in the tree.** *Largely addressed.* All
      four high-value parser targets now have unit-test coverage; the suite
      stands at 31 tests across `systemd`, `udev`, `cron`, and
      `package_ownership`:
      - `udev::extract_with_prefixes` — 7 tests covering each assignment
        operator variant (`+=`/`:=`/`=`), multiple directives per line, the
        no-quote skip path, the unterminated-quote early return, the
        substring-in-value false-positive guard, and the
        `IMPORT{program}`-vs-`IMPORT{file,db,cmdline}` discrimination.
      - `cron::parse_cron_line` — 6 tests covering the 5-field
        with/without-user shapes, `@reboot` as a single-token schedule, blank
        and comment skipping, env-var assignment skipping, and
        truncated-input rejection.
      - `systemd::parse_ini` and `activated_unit_name` — 6 tests covering
        repeated-key list semantics (load-bearing for `emit_service`),
        comment and blank handling, whitespace trimming, the
        filename-stem-`.service` default, the explicit override, and
        last-write-wins on repeated keys.
      - `package_ownership` dpkg/pacman/rpm parsers — 6 tests after
        extracting `parse_rpm_qf_output`, `dpkg_pkg_from_stem`,
        `parse_dpkg_list_content`, and `parse_pacman_files_content` from
        their respective `build_*_index` functions. Covers tab-split parsing
        with format-drift tolerance, `:arch` stripping including multi-colon
        edge cases, blank-line handling, `%FILES%` section gating including
        multiple `%FILES%` headers, `%BACKUP%`/other-section rejection, and
        the `/`-prefix prepending.
      Remaining gaps are intentional: per-checker `run()` entry points still
      touch the filesystem and aren't unit-testable without a temp-dir
      framework; the merged-`/usr` rewrite and dbus-org alias discriminators
      were already covered in prior commits.

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

- [x] Built-in allowlist for the Fedora `dbus-org.*` activation aliases under
      `/etc/systemd/system/`. They reliably show UNTRACKED but are benign.
      *Fixed via attribute-through-symlink rather than a blunt allowlist.*
      `OwnershipIndex::resolve_benign_alias` recognizes
      `/etc/systemd/{system,user}/dbus-org.*.service`, canonicalizes the
      symlink, and *only* reattributes to the target's owning package if the
      canonicalized target is itself package-owned. A malicious
      `dbus-org.evil.service → /tmp/evil.service` would not resolve to an
      owned target and stays `UNTRACKED` — the security property holds. The
      reattributed finding gains `benign_pattern: fedora-dbus-alias` and
      `alias_target: <resolved path>` metadata so the attribution is
      auditable. Result on this Fedora box: 22 → 10 UNTRACKED across all
      checkers (12 dbus-org.* aliases reattributed at both system and
      user-global scope). Unit-tested via `is_fedora_dbus_alias` cases for
      both scopes plus rejection of wrong-prefix, wrong-extension, and
      wrong-directory shapes.
- [x] `--untracked-only` flag. The malware-detection workflow is "show me
      what's not in any package" — currently the user pipes through `jq`.
      *Done.* New `Cli::untracked_only` bool; when set, the post-attribution
      pass in `main` retains only findings whose `package` is `Untracked`.
      Works for both text and JSON output, plays nicely with `--checker`
      narrowing, and falls through to the existing "no findings" branch when
      the filter empties the set. README updated to show
      `whogoesthere --untracked-only` in both the Usage and the
      malware-triage section, replacing the documented `jq` pipeline.
- [ ] Baseline + diff mode. `--baseline` writes a snapshot; `--diff old.json
      new.json` shows additions/removals. The diff is the actually-useful
      detection signal in practice.

## Additional persistence vectors (v2 candidates)

- [x] SSH persistence: `~/.ssh/authorized_keys`, `~/.ssh/rc`, `/etc/ssh/sshrc`,
      `ForceCommand` in sshd_config. *Done — promoted into the v1 checker
      matrix.* New `ssh` checker emits: one finding per `authorized_keys`
      key (surfacing the comment field as target, keytype + line + options
      as metadata, and `forced_command` extracted from `command="..."`
      options when present); existence + size + unreadable marker for
      `/etc/ssh/sshrc` and `~/.ssh/rc`; one finding per `ForceCommand` /
      `AuthorizedKeysCommand` directive in `/etc/ssh/sshd_config` and
      `/etc/ssh/sshd_config.d/*.conf`, with `Match` block context as
      `match_block` metadata. Unreadable `sshd_config` (mode 0600 root)
      produces a marker finding rather than silently disappearing. The
      authorized-keys parser uses a whole-token-boundary scan for the
      key-type position with fallback `None` on unrecognized types — see
      the doc comment on `parse_authorized_key` for the one known
      limitation (literal key-type tokens inside `command="..."` option
      values). Validated against a synthetic
      `command="/tmp/malicious-payload --steal" ssh-ed25519 ... attacker@evilhost`
      key: surfaced as `UNTRACKED` with `forced_command:
      /tmp/malicious-payload --steal` metadata. 11 unit tests cover the
      parser, the forced-command extractor, the whole-token boundary
      check, and the `sshd_config` directive stripper (both whitespace and
      `=` separators, case-insensitive key).
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
- [x] systemd drop-in dirs (`<unit>.d/*.conf`) are not walked — a malicious
      override that adds `ExecStart` via a drop-in would be missed. *Fixed.*
      `scan_unit_dir` now recurses into `<unit>.<ext>.d` subdirectories whose
      stem ends in a surveyed unit extension (service/timer/path/socket),
      filtering out the unrelated `*.wants/` and `*.requires/` symlink farms.
      Each `*.conf` is parsed by the existing `parse_ini` and dispatched to
      the matching emit function, so any Exec*/OnCalendar=/Listen=/Path*
      directive in a drop-in produces a finding attributed to the conf path
      (not the base unit). Mechanism gains an " override" qualifier and an
      `overrides: <unit>` metadata key surfaces the target. Validated against
      a synthetic `~/.config/systemd/user/test-evil.service.d/99-override.conf`
      with `ExecStart=/tmp/malicious-payload`: flagged `UNTRACKED` as
      expected. `is_dropin_dir` discriminator unit-tested. Out of scope:
      auditing the *merged* unit (e.g. a drop-in that only sets `User=` of an
      existing service is still silent — would require loading base + all
      drop-ins together).
