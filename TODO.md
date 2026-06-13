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
- [x] **`detect()` picks a single package-manager backend, first match wins**
      (`package_ownership.rs`). *Done.* Renamed to `detect_all()`,
      returns `Vec<PackageManager>` of every available backend.
      `OwnershipIndex::build` now iterates available backends, builds
      each index, and merges via a new `merge_indices` helper.
      Per-backend collisions (rare in practice — different PMs target
      different file roots) resolve last-write-wins; either attribution
      names a real owning package, and the `UNTRACKED` signal we
      actually care about is unaffected. The empty-input case (no PM
      on the host) still yields `None`, matching pre-change behavior
      for PM-less hosts. The `PackageManager::None` variant was removed
      — its role is now expressed by an empty `Vec`. Live Fedora: zero
      change (only `rpm` installed, behavior identical). 3 unit tests
      added: non-overlapping union, empty-input → `None`, collision
      last-write-wins.
- [x] **Unreadable files are silently flagged as findings with no indication
      they couldn't be read.** *Fixed.* `shell::check_file`,
      `init::scan_initd`, and `init::scan_rc_local` now probe readability via
      `fs::File::open()` after the stat-based finding is built. If the open
      fails, an `unreadable: rerun as root to inspect` metadata key is added,
      so a `0600 root:root` file like `/etc/profile.d/debuginfod.sh` running
      unprivileged is no longer indistinguishable from a benign empty
      finding. `scan_inittab` already reads content directly and returns no
      findings on failure — separate bug, out of scope here.
- [x] **`which()` shells out per probe** (`package_ownership.rs`) via
      `sh -c "command -v <prog>"`. *Done.* Replaced with a native `$PATH`
      walk that reads `$PATH`, splits on `:`, and checks each candidate
      via `fs::metadata` for the executable bit. Drops the shell
      dependency entirely (no `/bin/sh` fork per probe) and works on
      minimal containers that may not ship a shell. Symlinks are
      followed via `metadata()` (not `symlink_metadata`), so
      `which("apk")` matches when `/sbin/apk → /bin/busybox` on Alpine.
      Live Fedora regression: total 1725, UNTRACKED 13 — identical to
      pre-change (rpm correctly detected by the new probe).
- [x] **`autostart::SYSTEM_DIRS` includes `/usr/xdg/autostart`**, which is not
      a standard XDG path. *Done — removed.* `SYSTEM_DIRS` now contains only
      the real `/etc/xdg/autostart`.
- [x] **`real_users()` scopes to root + UID 1000–65533**, deliberately skipping
      system accounts (1–999). *Done — documented.* Added a doc comment to
      `real_users` explaining the Debian/Ubuntu/Fedora UID convention
      (1–999 = daemons, 1000–65533 = human users, 65534 = `nobody`),
      why we exclude the 1–999 range (daemon dotfiles are noise, and
      daemons don't typically host persistence in their `$HOME`), and
      the accepted trade-off (a service account at UID 500 with a real
      login shell wouldn't be surveyed). No behavior change.
- [x] **`SystemdChecker` reports `Scope::System` for the `user-global` unit
      dirs** (`/etc/systemd/user`, `/usr/lib/systemd/user`, etc.). *Done.*
      Added `Scope::UserGlobal` variant to the `Scope` enum
      (`finding.rs`), serializing as `{"kind": "user_global"}`. The
      `SystemdChecker` now emits this variant for the three global-user
      unit dirs instead of `Scope::System`. The text renderer
      (`main.rs::print_finding`) and the diff identity function
      (`diff.rs::diff_key`) both gained handling for the new variant —
      a UserGlobal finding is now distinguishable from a System finding
      with the same source path. 2 unit tests added: serde round-trip
      via JSON (so snapshots from `--format json` deserialize cleanly
      via `--diff`), and diff identity confirming a unit that crosses
      between System and UserGlobal scope on the same source path shows
      up as removed+added (a *real* semantic change worth surfacing,
      not a metadata-only delta).
      Live Fedora measurement: 152 findings now carry `scope: user_global`
      that previously carried `scope: system` (these were always
      user-global semantically — they live in `/etc/systemd/user/`,
      `/usr/lib/systemd/user/`, etc. — the typed scope just now matches).
      **One-time upgrade impact:** any pre-existing baseline JSON has
      these findings as `scope: system`; the first `--diff` against an
      old baseline will show all 152 as removed-from-System +
      added-as-UserGlobal even though no real persistence change
      occurred. Regenerate the baseline after upgrading. Total findings,
      UNTRACKED counts, and attribution all unchanged.
- [x] **`cron::scan_user_spool` falls back to uid 0 for unknown usernames**
      (`src/checkers/cron.rs:276`). *Done.* The lookup now returns
      `(uid, orphan: bool)` instead of silently using uid 0. When the
      user doesn't exist, the finding is still emitted (its presence is
      triage-relevant — stale admin state, or an attacker creating a
      spool for a not-yet-existent user) and tagged with
      `orphan_spool_owner: "user does not exist — cron skips this file
      at run time"` metadata so the analyst sees that cron itself won't
      run it. No-orphan path is unchanged.

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

- [x] Exercise the `init` checker on Debian/Ubuntu. Fedora has no SysV init at
      all, so init returned 0 findings — the parsing path was unexercised on
      real data. *Confirmed on an Ubuntu 24.04 arm64 capture: 53 SysV scripts
      surfaced, every one attributed to its owning deb (anacron → anacron,
      docker → docker-ce, open-iscsi → open-iscsi, samba → samba, etc.). The
      runlevel cross-reference via `build_runlevel_map` also resolves
      correctly on this distro. Zero UNTRACKED in the init category.*
- [x] Verify per-user crontabs on Debian. The `/var/spool/cron/crontabs/`
      path is supported in code but unexercised on this baseline.
      *Validated.* The Ubuntu 24.04 capture exercises this path: the
      cron checker walks both `/var/spool/cron` and
      `/var/spool/cron/crontabs` via `USER_SPOOLS`, and the capture
      shows expected per-user crontab findings emerging from the
      Debian-style layout with no parsing errors.
- [x] Smoke-test the dpkg branch of the package-ownership cache on a real
      Debian/Ubuntu box. *Validated.* The Ubuntu 24.04 arm64 capture has
      driven the entire session's noise-reduction work. Total/UNTRACKED
      counts are sane (1696 / 8 after all noise-collapse landed); the
      merged-`/usr` rewrite was specifically validated (1019 → 73
      UNTRACKED drop measured), and the postinst allowlist's entries
      (`/etc/profile`, `/etc/pam.d/common-*`, `/etc/modules`) were all
      diagnosed from this dpkg data. The 8 remaining UNTRACKED are the
      irreducible set (user dotfiles + ssh keys + admin-installed
      custom unit + the netplan runtime case). dpkg-diverted paths
      didn't appear as a noise class on this host.
- [ ] Smoke-test the pacman branch of the package-ownership cache on a real
      Arch box. Same caveat as dpkg — code is written against documented
      `/var/lib/pacman/local/*/files` layout but unverified. Check that
      `%FILES%`-section parsing is correct, total/UNTRACKED counts are sane,
      and that the directory-name-as-pkgid format reads cleanly in output.
- [ ] Check snap-generated systemd units on Ubuntu. They live in
      `/etc/systemd/system/` and may all show as UNTRACKED because snapd
      synthesizes them rather than dpkg-installing them. A pattern filter for
      `snap.*` may be needed. *Confirmed on the 24.04 capture: ~13 systemd
      units (`/etc/systemd/system/snap.*.service` and `/etc/systemd/user/
      snap.*.service|timer`) plus 15 udev rules
      (`/etc/udev/rules.d/70-snap.*.rules`) UNTRACKED — together ~28 of 84
      total UNTRACKED, the single largest noise class on Ubuntu. See the
      proposed snapd-attribution / pattern-tag follow-up under "Noise
      reduction & output".*
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
- [x] **Alpine (apk).** *Code-complete, unverified on real Alpine.* New
      `PackageManager::Apk` variant in `detect_all()` probes via
      `which("apk")`; `build_apk_index()` reads `/lib/apk/db/installed`
      and the new `parse_apk_db_content` walks the file with a small
      state machine tracking the current `P:<name>` / `V:<version>` /
      `F:<dir>` across each stanza, emitting one `(path, "<name>-<version>")`
      pair per `R:<filename>` line. Blank lines reset state so a stanza
      can't leak into the next one — that's the load-bearing case
      because incorrect leakage would attribute paths under the wrong
      package. Unknown tags (`A:`/`S:`/`D:`/`m:`/`t:`/`c:`/`Z:`/`a:` etc.)
      pass through silently. The package ID format `<name>-<version>`
      matches what `apk info --who-owns` reports. 5 unit tests: basic
      per-`R:` emission with mid-stanza `F:` change, blank-line stanza
      separator, unknown-tag passthrough + orphan-`R:` rejection,
      empty-`F:` for root files, empty-input. Same caveat as the pacman
      branch: needs the same smoke-test treatment on a real Alpine box
      to confirm `which("apk")` detection and the path forms reported
      match the actual `apk info --who-owns` output. Pairs with the
      "Run against Alpine" TODO under Distro coverage.

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
- [x] **Generalize `resolve_benign_alias` beyond `dbus-org.*` to cover any
      `systemctl enable` symlink under `/etc/systemd/{system,user}`.**
      *Done.* `is_fedora_dbus_alias` replaced by
      `is_systemd_enable_symlink_candidate`, which accepts any
      `/etc/systemd/{system,user}/*.{service,timer,path,socket}` path; the
      `resolve_benign_alias` body is unchanged — it still canonicalizes
      and only reattributes if the target is itself package-owned, so the
      security property holds (a malicious `→ /tmp/evil.service` doesn't
      resolve to an owned target and stays UNTRACKED). Metadata tag
      renamed from `fedora-dbus-alias` to `systemd-enable-symlink`.
      Measured on the live Fedora 44 box: UNTRACKED 19 → 13, with 18
      findings reattributed via the new pattern (12 dbus-org cases plus 6
      new: `display-manager.service`, `intel_lpmd.service`, the two
      `dbus.service` scopes, `pipewire-session-manager.service` — even
      `intel_lpmd` turned out packaged, exceeding the predicted ~15).
      Remaining 13 UNTRACKED are the irreducible set: 9 SSH keys + 4
      user dotfiles. Ubuntu effect predicted ~84 → ~54; pending a
      live-host re-run to confirm. Tests rewritten to cover both the
      original dbus-org cases and the new `sshd.service`,
      `display-manager.service`, `iscsi.service`, `*.timer`, `*.socket`,
      `*.path` shapes, plus rejection of `.conf`/`.target`/missing
      extensions, `/usr/lib/systemd/`, `/lib/systemd/`, `/run/systemd/`,
      and `*.service.d/*.conf` drop-ins.
- [x] ~~Resolve Ubuntu `/etc/pam.d/common-*` files generated by
      `pam-auth-update`.~~ *Superseded by the postinst allowlist.* All
      five `common-*` paths (`common-auth/account/password/session/
      session-noninteractive`) are entries in `POSTINST_ALLOWLIST` and
      attribute to `libpam-runtime`. The 22 UNTRACKED PAM rules in the
      24.04 capture all flipped to Owned via that mechanism — Ubuntu
      total UNTRACKED dropped 32 → 8, exceeding this item's predicted
      ~54 → ~32. Per-rule attribution back to individual
      `/usr/share/pam-configs/` snippets (option (b)) would give a finer
      mapping (e.g. `gnome-keyring`, `pam_cap`) but isn't necessary for
      triage — the `libpam-runtime` + `installer: postinst-libpam-runtime`
      tag already tells an analyst "this is pam-auth-update-managed, not
      malware". Reopen if a use case needs the finer mapping.
- [x] **snapd attribution backend.** *Done — option (b), the count-reducing
      one.* New `OwnershipIndex::resolve_snap_attribution` pre-scans both
      `/snap/<name>/` (directory layout, skipping the `bin/` shim) and
      `/var/lib/snapd/snaps/<name>_<rev>.snap` (blob layout) at startup
      and caches the installed snap names. The matching `extract_snap_name`
      parser recognizes two emitted shapes:
        * `/etc/systemd/{system,user}/snap.<snap>.<app>.<service|timer|path|socket>`
        * `/etc/udev/rules.d/70-snap.<snap>.rules`
      Both pick the 2nd dot-separated component as the snap name (safe
      because snapcraft restricts names to `[a-z0-9-]`). The attribution
      pass in `main.rs` only fires when the extracted name is in the
      pre-scanned set, so a malicious `snap.evil.payload.service` with no
      installed `evil` snap stays UNTRACKED — the security property holds.
      Attributed findings emit `PackageOrigin::Owned { package:
      "snap:<name>" }` and gain `installer: snapd` metadata so they're
      trivially filterable. Fedora effect: zero (no `/snap`, probe
      no-ops). Ubuntu effect: predicted 60 → ~32 UNTRACKED collapsing the
      13 systemd + 15 udev snap entries; pending a live-host re-run to
      confirm. 3 unit tests cover the parser: positive cases for
      `snap.cups.cupsd.service`, `snap.mesa-2404.component-monitor.service`,
      `snap.firmware-updater.firmware-notifier.timer`,
      `snap.snapd-desktop-integration.snapd-desktop-integration.service`,
      `70-snap.chromium.rules`, `70-snap.snap-store.rules`; negative cases
      for wrong-directory (`/usr/lib/systemd/system/`), wrong filename
      prefix, unsurveyed unit extensions (`.target`), and udev
      `99-foo.rules` / `70-snap.*.conf` shapes.
- [x] **Symlink-resolve `/etc/profile.d/*.sh` to attribute through to the
      target's owning package.** *Done.* `resolve_benign_alias` was
      refactored to dispatch via a `benign_alias_pattern` predicate chain
      that returns the matching pattern tag, so the same canonicalize +
      lookup body now handles both `systemd-enable-symlink` and the new
      `shell-profile-symlink` shape. The discriminator
      `is_profile_d_symlink_candidate` matches any `*.sh` directly under
      `/etc/profile.d/`. Security property holds across both patterns —
      a malicious `/etc/profile.d/evil.sh → /tmp/evil.sh` won't
      canonicalize to a package-owned target and stays UNTRACKED.
      Diagnosed on Ubuntu 24.04: `/etc/profile.d/debuginfod.sh →
      /usr/share/libdebuginfod-common/debuginfod.sh`, which should now
      reattribute to `libdebuginfod-common`. Fedora effect: zero (Fedora's
      `/etc/profile.d/*.sh` entries are real files, not symlinks; live
      UNTRACKED still 13). Ubuntu effect predicted: 33 → 32 (just the one
      symlink on this capture; the discriminator generalizes to any
      future postinst-dropped `/etc/profile.d/*.sh → /usr/share/...`
      symlink). 3 unit tests added: positive cases for `debuginfod.sh`
      and `01-locale-fix.sh`; negative cases for `/etc/bash.bashrc`,
      `/etc/profile.d/README` (no extension), `/etc/profile.d/foo.csh`
      (wrong ext), `/usr/share/libdebuginfod-common/debuginfod.sh` (wrong
      dir); dispatch test confirming `benign_alias_pattern` returns the
      right tag for each shape.
- [x] **Known-postinst-generated allowlist for non-symlink files like
      `/etc/profile`, `/etc/pam.d/common-*`, `/etc/modules`.** *Done.* New
      `POSTINST_ALLOWLIST` static table in `package_ownership.rs` maps each
      known postinst-emitted path to its owning Debian package:
      `/etc/profile` → `base-files`; `/etc/pam.d/common-{auth,account,
      password,session,session-noninteractive}` → `libpam-runtime`;
      `/etc/modules` → `kmod`. `OwnershipIndex::resolve_postinst_allowlist`
      gates on `self.files.is_some()` so the allowlist doesn't fire when
      no package backend was detected — fabricating package names on a
      non-dpkg/-rpm host would be wrong. Wired into `main.rs` as the third
      post-attribution pass; attributed findings emit
      `installer: postinst-<pkgname>` metadata so the attribution
      mechanism is auditable. Caveat (same as dpkg/rpm file ownership in
      general): attribution doesn't validate file contents, so an
      attacker-modified `/etc/profile` would still get marked
      `base-files`. The malware-triage workflow's primary signal remains
      UNTRACKED + the broader signal (`mtime`, contents review). 5 unit
      tests added: positive cases for all 7 catalogued paths via a small
      `idx_with_backend()` helper; negative cases for non-allowlisted
      paths (`/etc/bash.bashrc`, `/etc/pam.d/sshd`, `/etc/passwd`); a
      no-backend gate test that confirms the allowlist no-ops when
      `files` is `None`. Fedora effect: zero (rpm correctly owns
      `/etc/profile` via `setup`; the other paths don't exist there).
      Ubuntu effect predicted: 32 → ~9 (22 PAM + `/etc/profile` collapse;
      `/etc/modules` stays UNTRACKED if kmod isn't in the package index,
      but if it is, that drops too).
- [ ] **Runtime-generated units under `/run/systemd/system/` from real
      packages (low priority, single-case so far).** The Ubuntu 24.04
      capture surfaced one such entry: `/run/systemd/system/
      netplan-ovs-cleanup.service`, emitted at runtime by the `netplan.io`
      deb. The current `is_systemd_enable_symlink_candidate` deliberately
      rejects `/run/systemd/` (we don't want to silently attribute
      arbitrary runtime-generated units to a real package), so this stays
      UNTRACKED. A different mechanism could attribute by inspecting the
      unit's `ExecStart` target against the package index — `/usr/sbin/
      netplan` is owned by `netplan.io`. Not worth designing for until
      more similar cases appear; revisit if the pattern shows up on
      additional captures.
- [x] Baseline + diff mode. *Done — `--diff OLD NEW`.* The existing
      `--format json > snapshot.json` is the snapshot path (no separate
      `--baseline` flag needed). New `diff` module computes
      additions/removals between two snapshots and emits them with `+`/
      `-` prefixes in text mode or `{"added": [...], "removed": [...]}`
      in JSON mode. Identity matches on the persistence vector
      (`category`, `source`, `target`, `mechanism`, `scope`) and
      deliberately excludes `package` status and `metadata` — so a PAM
      rule that gets renumbered after a line is inserted above it
      doesn't appear as added/removed, and an `UNTRACKED → Owned` flip
      from a package install isn't a diff event either. Prerequisite
      changes: `Finding` and friends gained `Deserialize`;
      `category: &'static str` → `category: String` to make the type
      round-trip through JSON. 6 unit tests cover identical snapshots,
      pure-add, pure-remove, metadata-only-delta (no diff), package-
      status-only-delta (no diff), and per-user-scope separation. README
      updated with the workflow.

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
- [x] PAM: `/etc/pam.d/*` (auth-time module injection). *Done — promoted
      into the v1 checker matrix.* New `pam` checker walks `/etc/pam.d/`
      and emits one finding per non-comment, non-blank line. Parser handles
      the standard `<type> <control> <module-path> [args...]` shape, the
      leading-dash type variants (`-auth`/etc., which silently skip if the
      module is missing), and the bracketed `[key=value ...]` complex
      control form. Metadata records service (filename), type, control,
      line number, and module args. `include` and `substack` controls are
      handled naturally — the next token is just recorded as the module
      slot. Caveats: the older `@include filename` legacy form is
      intentionally unsupported (didn't appear on the Fedora baseline);
      tampering with an existing package-owned file still attributes the
      finding to the package's owner — improving that requires resolving
      module paths against the package index, which is left for follow-up.
      9 unit tests cover the parser (minimal/with-args/leading-dash/
      bracketed-control/include/whitespace-tolerance/comment-skip/
      unknown-type-rejection/truncated-line-rejection). On this Fedora
      box: 230 rules surfaced across all services in `/etc/pam.d/`, all
      attributed to their owning packages — zero UNTRACKED, which is the
      expected clean baseline.
- [x] D-Bus services: `/usr/share/dbus-1/services/`, `/etc/dbus-1/services/`
      (related to the systemd alias noise observed in v1). *Done — promoted
      into the v1 checker matrix.* New `dbus` checker walks both session-
      and system-bus dirs at `/usr/share/dbus-1/{services,system-services}/`,
      the admin overrides under `/etc/dbus-1/{services,system-services}/`,
      `/usr/local/share/dbus-1/{services,system-services}/`, and per-user
      `~/.local/share/dbus-1/services/`. Each `.service` file emits one
      finding: target is `Exec=` directly, or `(activates systemd unit)
      <name>` if only `SystemdService=` is set. Metadata: `bus_name`,
      `bus` (session/system), `run_as` (`User=`), and `systemd_service`
      (when both `Exec=` and `SystemdService=` are present —
      `Exec=` wins per dbus-daemon semantics, but the alternate
      activation path is auditable). Prerequisite refactor: the INI
      parser moved from `systemd.rs` to `util.rs` as `parse_ini`/`IniDoc`/
      `IniSection` and is now shared between the two checkers. Live
      Fedora 44: 135 findings surfaced, every one attributed to its
      owning rpm — zero UNTRACKED. 6 unit tests cover the parser
      (Exec-only, SystemdService-only, User-surfaced, both-present
      Exec-wins, missing section, no-activation-directive).
- [x] Dynamic linker search path: `/etc/ld.so.conf.d/*.conf`. *Done — folded
      into the existing `ld_so` checker.* New `scan_conf_file` walks both
      the top-level `/etc/ld.so.conf` and every `*.conf` under
      `/etc/ld.so.conf.d/`. Each non-blank, non-`#`-comment line emits a
      finding: a bare path produces a "search-path entry" finding, and an
      `include <glob>...` line produces one "include directive" finding
      per glob argument (so an injected `include /tmp/evil.conf` is itself
      visible without recursing into it). Source is the conf file itself,
      so package-ownership attribution flags an UNTRACKED `.conf` in
      `ld.so.conf.d/` — the malware-side of T1574.006-class library
      hijacking, where the attacker drops a conf that adds an
      attacker-controlled directory ahead of the legitimate search path.
      4 unit tests cover bare paths, single-glob include, multi-glob
      include, and the comment/blank skip path via a synthetic temp file.
      On this Fedora box: 5 ld_so findings total, all package-attributed,
      zero UNTRACKED — clean baseline.
- [x] Display-manager session hooks: gdm/sddm/lightdm Xsession scripts;
      `~/.xsession`, `~/.xinitrc`, `~/.xprofile`. *Done — promoted into
      the v1 checker matrix.* New `display_manager` checker emits one
      finding per file across three families:
        * Per-user dotfiles (Scope::User): `~/.xprofile`, `~/.xsession`,
          `~/.xinitrc`, `~/.xsessionrc`. `dm` metadata deliberately
          omitted — these are read by multiple DMs.
        * System DM hooks (Scope::System): `/etc/X11/xinit/xinitrc`
          (`dm: xinit`), `/etc/X11/Xsession` (`dm: xsession`),
          `/etc/lightdm/Xsession` (`dm: lightdm`),
          `/etc/gdm/PostLogin/Default` + `/etc/gdm/PreSession/Default`
          (`dm: gdm`).
        * System sourced-fragment dirs: `/etc/X11/Xsession.d/*` with
          dotfile + `*~` editor-backup skip rules. Each fragment is
          sourced at session start by `/etc/X11/Xsession`.
      Metadata: `size_bytes`, `executable` (bool), `dm` (when known),
      `unreadable` marker when current user can't open the file. Live
      Fedora 44: 2 findings surfaced — `/etc/X11/xinit/xinitrc` →
      `xorg-x11-xinit` and `/etc/X11/Xsession.d/90xbrlapi` → `brltty`
      (a braille-display install hook, benign but exactly the vector
      this checker is built to catch). Zero new UNTRACKED. Total
      findings 1723 → 1725. 5 unit tests via tempdirs cover the basic
      finding path with dm metadata, the per-user `dm`-omitted path,
      zero-byte / missing rejection, sourced-fragment dir scan with
      backup/dotfile skip, and the missing-directory no-op. SDDM
      `*.conf` settings + per-DM `*.conf.d/` overrides deliberately
      excluded for v1 — those are configuration, not script
      persistence, a different vector class.
- [x] NetworkManager dispatcher scripts: `/etc/NetworkManager/dispatcher.d/`.
      *Done — promoted into the v1 checker matrix.* New `network_manager`
      checker walks the main `dispatcher.d/` body plus the three phase
      sub-dirs (`pre-up.d/`, `pre-down.d/`, `no-wait.d/`). Each
      executable script emits one finding with `size_bytes`,
      `executable`, and (when applicable) `phase` metadata. Non-
      executable scripts still emit a finding but gain a `note`
      explaining they won't run on dispatch — their presence is admin
      or attacker intent worth surfacing even when dormant. Editor
      backups (`*~`) and dotfiles are skipped, matching NM's actual
      dispatch behavior. The mechanism string differentiates phase
      timing: main dir "runs on every network event"; pre-up.d/
      "runs before an interface comes up"; pre-down.d/ "runs before
      an interface goes down"; no-wait.d/ "runs on every network
      event, in parallel". Live Fedora 44: zero findings (NM active,
      dispatcher.d/ tree empty — clean baseline). 5 unit tests cover
      the executable + metadata path via tempdirs, the non-executable
      note path, dotfile/`*~` skip, phase metadata + distinct
      mechanism for sub-dirs, and the missing-directory no-op.
- [x] APT/DNF hooks: `/etc/apt/apt.conf.d/`, `/etc/dnf/plugins/`. *Partial
      — APT hooks done, DNF deferred as its own item.* New `apt_hooks`
      checker walks `/etc/apt/apt.conf` and every non-dotfile,
      non-`*~` file under `/etc/apt/apt.conf.d/`. Recognizes seven
      persistence-relevant directives — `DPkg::Pre-Install-Pkgs`,
      `DPkg::Pre-Invoke`, `DPkg::Post-Invoke`,
      `DPkg::Post-Invoke-Success`, `APT::Update::Pre-Invoke`,
      `APT::Update::Post-Invoke`, `APT::Update::Post-Invoke-Success` —
      and extracts every shell command they hold across all three
      apt.conf surface forms: single-value (`<dir> "cmd";`), append-
      list (`<dir>:: "cmd";`), and block (`<dir> { "cmd1"; "cmd2"; };`).
      Comment stripper handles `//`, `/* */`, and `#` while leaving
      quoted strings intact (a literal `//` inside a command body
      survives). Boundary check distinguishes `DPkg::Pre-Invoke::Foo`
      (namespace continuation, not our directive) from
      `DPkg::Pre-Invoke::` (append-list operator, our directive plus
      `::`). One finding per command with the directive name as
      metadata. Live Fedora 44: zero findings (no apt; checker
      no-ops cleanly). 11 unit tests cover each value form, comment
      handling including `//` inside quotes, partial-match rejection,
      namespace-continuation rejection, escaped-quote handling,
      nested-braces-in-value, repeated-directive emission, and empty.
      Known limitation: the hierarchical nested form
      (`DPkg { Pre-Invoke "cmd"; }`) is not parsed — every Ubuntu
      vendor file we have data for uses the flat form; revisit if a
      real-world driver appears. DNF side intentionally deferred:
      `/etc/dnf/plugins/*.conf` only enables plugins, the actual hook
      logic lives in plugin Python source; the right Fedora analog
      is probably rpm scriptlet enumeration (`%pre`/`%post`/etc.) but
      that's a structurally different design.

## Parser edge cases

- [x] systemd unit-file line continuation (`\` at EOL) is not handled. Rare in
      the persistence-relevant keys but technically valid syntax. *Done.*
      New `util::fold_line_continuations` joins backslash-at-EOL into a
      single logical line (continuations joined with a single space, with
      leading/trailing whitespace around the join trimmed so multi-line
      `ExecStart=` doesn't get spurious extra spaces). `parse_ini` calls
      it before walking lines, so every systemd checker emit path
      (service/timer/path/socket) automatically inherits the support. 4
      unit tests cover passthrough, single-continuation join, multiple
      consecutive continuations, and a dangling-`\` at EOF.
- [x] udev rule line continuation (`\` at EOL) likewise unhandled. *Done.*
      `udev::scan_rules_file` now calls `fold_line_continuations` on the
      file content before per-line tokenizing, so a multi-line
      `RUN+="..."` or `IMPORT{program}="..."` directive presents as one
      logical line to the existing extractor. Same shared helper as the
      systemd path.
- [x] **`cron::parse_cron_line` collapses internal whitespace in the command
      field** (`src/checkers/cron.rs:97-105`). *Done.* `parse_cron_line`
      now calls a new `byte_offset_after_n_tokens` helper to find the
      byte position just past the schedule (and optional user) tokens in
      the original line, then takes the remainder verbatim — preserving
      multi-space, tabs, and any other internal whitespace cron would pass
      through to the shell. `scan_anacrontab` got the same treatment.
      Unit test covers the multi-space-plus-tab round-trip case.
- [x] **`ld_so::check_environment_file` strips quotes with `trim_matches`**
      (`src/checkers/ld_so.rs:63`). *Done.* New `unquote_env_value` helper
      only strips one matching pair of outer quotes (same kind on both
      sides). `"'inner'"` now correctly resolves to `'inner'` instead of
      having both layers eaten. Unit test covers `""` / `''` pairs,
      matched-outer-different-inner, asymmetric (no-strip), unquoted
      (passthrough), and empty/single-char inputs.
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

## Style / cosmetic

- [x] **`is_fedora_dbus_alias` is named Fedora-specific but the pattern likely
      generalizes** (`src/package_ownership.rs:75`). *Done — implicitly
      addressed when the discriminator was generalized.* `is_fedora_dbus_alias`
      was replaced by `is_systemd_enable_symlink_candidate`, which is named
      for the broader pattern it actually recognizes (any
      `/etc/systemd/{system,user}/<name>.{service,timer,path,socket}` enable
      symlink), not specifically the Fedora dbus-org case. The Ubuntu 24.04
      capture confirmed the same shape — `sshd.service`, `samba.service`,
      `iscsi.service`, etc. — applies to Debian-family hosts too.
