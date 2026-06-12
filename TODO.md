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
- [ ] Check snap-generated systemd units on Ubuntu. They live in
      `/etc/systemd/system/` and may all show as UNTRACKED because snapd
      synthesizes them rather than dpkg-installing them. A pattern filter for
      `snap.*` may be needed.
- [ ] Run against Alpine (OpenRC, no systemd). Most checkers should
      gracefully no-op; verify nothing panics.

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
