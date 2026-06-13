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
- [ ] **`SystemdChecker` reports `Scope::System` for the `user-global` unit
      dirs** (`/etc/systemd/user`, `/usr/lib/systemd/user`, etc. — see
      `src/checkers/systemd.rs:50`). These units don't actually run as root,
      they're user-scope unit definitions shipped system-wide. The `location:
      user-global` metadata disambiguates, but the typed `Scope` is misleading
      for any downstream that consumes scope structurally. Consider a
      `Scope::UserGlobal` variant if/when a baseline+diff or filter UI needs
      to distinguish.
- [ ] **`cron::scan_user_spool` falls back to uid 0 for unknown usernames**
      (`src/checkers/cron.rs:276`). A stale spool file left over from a
      deleted user would attribute persistence to root, which is wrong and
      could obscure triage. Niche, but the fix is one line — skip the file
      (or tag the finding with `orphan_spool_owner: <filename>`) when
      `get_user_by_name` returns `None`.

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
- [ ] **Resolve Ubuntu `/etc/pam.d/common-*` files generated by
      `pam-auth-update`.** The 24.04 capture shows 22 UNTRACKED PAM rules
      across `common-auth/account/password/session/session-noninteractive`.
      These files aren't shipped by any deb — they're aggregated at install
      time from snippets in `/usr/share/pam-configs/` (which *are* package-
      owned). Two options: (a) low-cost — tag any `/etc/pam.d/common-*`
      finding with `generated_by: pam-auth-update` metadata so a triage
      filter can exclude them as a class without losing the data; (b)
      structured — resolve each rule back to its `pam-configs` snippet and
      reattribute. Option (a) is one branch in `pam::scan_pam_file`;
      option (b) needs grep-equivalent across pam-configs files. Start with
      (a). Expected effect: Ubuntu UNTRACKED ~54 → ~32.
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
- [ ] D-Bus services: `/usr/share/dbus-1/services/`, `/etc/dbus-1/services/`
      (related to the systemd alias noise observed in v1).
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
- [ ] Display-manager session hooks: gdm/sddm/lightdm Xsession scripts;
      `~/.xsession`, `~/.xinitrc`, `~/.xprofile`.
- [ ] NetworkManager dispatcher scripts: `/etc/NetworkManager/dispatcher.d/`.
- [ ] APT/DNF hooks: `/etc/apt/apt.conf.d/`, `/etc/dnf/plugins/`.

## Parser edge cases

- [ ] systemd unit-file line continuation (`\` at EOL) is not handled. Rare in
      the persistence-relevant keys but technically valid syntax.
- [ ] udev rule line continuation (`\` at EOL) likewise unhandled.
- [ ] **`cron::parse_cron_line` collapses internal whitespace in the command
      field** (`src/checkers/cron.rs:97-105`). The parser splits on
      whitespace then re-joins with single spaces, so a command like
      `echo  "hello  world"` is recorded as `echo "hello world"`. The
      recorded target then differs from what cron actually runs — cosmetic
      noise during triage, not a security issue. Same lossiness in
      `scan_anacrontab` (`src/checkers/cron.rs:224`). Fix by capturing the
      remainder of the line by byte position rather than rejoining tokens.
- [ ] **`ld_so::check_environment_file` strips quotes with `trim_matches`**
      (`src/checkers/ld_so.rs:63`), which removes *all* leading/trailing `"`
      and `'` characters indiscriminately. Mildly lossy on edge inputs like
      `LD_PRELOAD="'mixed'"`. Trivial; only matters if someone hand-crafts
      adversarial quoting.
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

- [ ] **`is_fedora_dbus_alias` is named Fedora-specific but the pattern likely
      generalizes** (`src/package_ownership.rs:75`). D-Bus activation aliases
      at `/etc/systemd/{system,user}/dbus-org.*.service` aren't unique to
      Fedora. Once Debian/Arch baselines are taken, either confirm the same
      shape and rename to `is_dbus_activation_alias`, or document the
      distro-specificity in the function comment.
