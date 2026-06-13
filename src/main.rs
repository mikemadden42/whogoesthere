mod checker;
mod checkers;
mod diff;
mod finding;
mod package_ownership;
mod util;

use std::path::PathBuf;

use clap::{Parser, ValueEnum};

use crate::checker::Checker;
use crate::finding::{Finding, PackageOrigin, Scope};

#[derive(Parser)]
#[command(name = "whogoesthere", about = "Linux persistence enumeration")]
struct Cli {
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,

    /// Only run the named checker (repeatable). Default: all.
    #[arg(long = "checker", value_name = "NAME")]
    only: Vec<String>,

    /// Show only findings no package owns — the malware-triage signal.
    #[arg(long)]
    untracked_only: bool,

    /// List the available checker names and exit. Use with --checker.
    #[arg(long)]
    list_checkers: bool,

    /// Compare two snapshot JSON files (produced by `--format json`) and
    /// print findings that appeared or disappeared between them. Skips the
    /// scan entirely.
    #[arg(long, value_names = ["OLD", "NEW"], num_args = 2)]
    diff: Option<Vec<PathBuf>>,
}

#[derive(Clone, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if let Some(paths) = &cli.diff {
        // `num_args = 2` guarantees exactly two paths.
        let old: Vec<Finding> = serde_json::from_reader(std::fs::File::open(&paths[0])?)?;
        let new: Vec<Finding> = serde_json::from_reader(std::fs::File::open(&paths[1])?)?;
        let diff = diff::diff_snapshots(old, new);
        match cli.format {
            OutputFormat::Text => print_diff(&diff),
            OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&diff)?),
        }
        return Ok(());
    }

    let checkers: Vec<Box<dyn Checker>> = vec![
        Box::new(checkers::systemd::SystemdChecker),
        Box::new(checkers::cron::CronChecker),
        Box::new(checkers::init::InitChecker),
        Box::new(checkers::shell::ShellChecker),
        Box::new(checkers::autostart::AutostartChecker),
        Box::new(checkers::udev::UdevChecker),
        Box::new(checkers::modules::ModulesChecker),
        Box::new(checkers::ld_so::LdSoChecker),
        Box::new(checkers::pam::PamChecker),
        Box::new(checkers::ssh::SshChecker),
        Box::new(checkers::dbus::DbusChecker),
        Box::new(checkers::network_manager::NetworkManagerChecker),
        Box::new(checkers::display_manager::DisplayManagerChecker),
    ];

    if cli.list_checkers {
        let mut names: Vec<&str> = checkers.iter().map(|c| c.name()).collect();
        names.sort_unstable();
        for n in names {
            println!("{n}");
        }
        return Ok(());
    }

    let index = package_ownership::OwnershipIndex::build();
    let mut findings: Vec<Finding> = Vec::new();

    for c in &checkers {
        if !cli.only.is_empty() && !cli.only.iter().any(|n| n == c.name()) {
            continue;
        }
        let mut chunk = c.run();
        for f in &mut chunk {
            if matches!(f.package, PackageOrigin::Unknown) {
                f.package = index.owner(&f.source);
            }
            // Recover attribution for benign-symlink shapes — currently
            // `systemctl enable` unit-file symlinks under
            // /etc/systemd/{system,user}/, and /etc/profile.d/*.sh symlinks
            // that postinst scripts drop pointing into /usr/share/. A bogus
            // symlink pointing at an unowned target (e.g. /tmp/evil) won't
            // resolve to an owned file and stays UNTRACKED — the security
            // property holds for every pattern.
            if matches!(f.package, PackageOrigin::Untracked)
                && let Some((pkg, target, pattern)) = index.resolve_benign_alias(&f.source)
            {
                f.package = PackageOrigin::Owned { package: pkg };
                f.metadata
                    .insert("benign_pattern".to_string(), pattern.to_string());
                f.metadata
                    .insert("alias_target".to_string(), target.display().to_string());
            }
            // Attribute snapd-emitted files (snap.<name>.<app>.service|.timer
            // and 70-snap.<name>.rules) to their owning snap, but only if the
            // snap is actually installed — an attacker dropping a file with
            // that shape pointing at a non-existent snap stays UNTRACKED.
            if matches!(f.package, PackageOrigin::Untracked)
                && let Some(pkg) = index.resolve_snap_attribution(&f.source)
            {
                f.package = PackageOrigin::Owned { package: pkg };
                f.metadata
                    .insert("installer".to_string(), "snapd".to_string());
            }
            // Attribute Debian/Ubuntu files known to be created by a
            // package's postinst script (and therefore invisible to dpkg's
            // file index): /etc/profile (base-files), /etc/pam.d/common-*
            // (libpam-runtime), /etc/modules (kmod). Only fires when the
            // finding is still UNTRACKED at this point.
            if matches!(f.package, PackageOrigin::Untracked)
                && let Some(pkg) = index.resolve_postinst_allowlist(&f.source)
            {
                f.package = PackageOrigin::Owned {
                    package: pkg.to_string(),
                };
                f.metadata
                    .insert("installer".to_string(), format!("postinst-{pkg}"));
            }
        }
        findings.extend(chunk);
    }

    if cli.untracked_only {
        findings.retain(|f| matches!(f.package, PackageOrigin::Untracked));
    }

    match cli.format {
        OutputFormat::Text => print_text(&findings),
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&findings)?),
    }

    Ok(())
}

fn print_text(findings: &[Finding]) {
    if findings.is_empty() {
        println!("no findings");
        return;
    }
    for f in findings {
        print_finding(f, "");
    }
}

fn print_diff(diff: &diff::Diff) {
    if diff.added.is_empty() && diff.removed.is_empty() {
        println!("no changes");
        return;
    }
    for f in &diff.added {
        print_finding(f, "+ ");
    }
    for f in &diff.removed {
        print_finding(f, "- ");
    }
}

fn print_finding(f: &Finding, prefix: &str) {
    println!("{prefix}[{}] {}", f.category, f.mechanism);
    println!("{prefix}  source:  {}", f.source.display());
    if let Some(t) = &f.target {
        println!("{prefix}  target:  {t}");
    }
    match &f.scope {
        Scope::System => println!("{prefix}  scope:   system"),
        Scope::User { uid, name } => println!("{prefix}  scope:   user {name} (uid {uid})"),
    }
    match &f.package {
        PackageOrigin::Owned { package } => println!("{prefix}  package: {package}"),
        PackageOrigin::Untracked => println!("{prefix}  package: UNTRACKED"),
        PackageOrigin::Unknown => println!("{prefix}  package: unknown"),
    }
    for (k, v) in &f.metadata {
        println!("{prefix}  {k}: {v}");
    }
    println!();
}
