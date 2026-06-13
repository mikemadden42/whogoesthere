mod checker;
mod checkers;
mod finding;
mod package_ownership;
mod util;

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
}

#[derive(Clone, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

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
            // Recover attribution for `systemctl enable` (and D-Bus activation)
            // symlinks under /etc/systemd/{system,user}/ that point back to a
            // package-owned unit. A bogus symlink pointing at an unowned
            // target (e.g. /tmp/evil.service) won't resolve to an owned file
            // and stays UNTRACKED — the security property holds.
            if matches!(f.package, PackageOrigin::Untracked)
                && let Some((pkg, target)) = index.resolve_benign_alias(&f.source)
            {
                f.package = PackageOrigin::Owned { package: pkg };
                f.metadata.insert(
                    "benign_pattern".to_string(),
                    "systemd-enable-symlink".to_string(),
                );
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
        println!("[{}] {}", f.category, f.mechanism);
        println!("  source:  {}", f.source.display());
        if let Some(t) = &f.target {
            println!("  target:  {t}");
        }
        match &f.scope {
            Scope::System => println!("  scope:   system"),
            Scope::User { uid, name } => println!("  scope:   user {name} (uid {uid})"),
        }
        match &f.package {
            PackageOrigin::Owned { package } => println!("  package: {package}"),
            PackageOrigin::Untracked => println!("  package: UNTRACKED"),
            PackageOrigin::Unknown => println!("  package: unknown"),
        }
        for (k, v) in &f.metadata {
            println!("  {k}: {v}");
        }
        println!();
    }
}
