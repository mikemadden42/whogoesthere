# whogoesthere TODO

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
      override that adds `ExecStart` via a drop-in would be missed.
