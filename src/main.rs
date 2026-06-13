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
    ];

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
            // Recover attribution for known-benign alias patterns (currently
            // Fedora's dbus-org.*.service activation symlinks): if the symlink
            // resolves to a package-owned target, attribute through it and
            // tag for filtering. A bogus dbus-org.* alias pointing at an
            // unowned target stays UNTRACKED.
            if matches!(f.package, PackageOrigin::Untracked)
                && let Some((pkg, target)) = index.resolve_benign_alias(&f.source)
            {
                f.package = PackageOrigin::Owned { package: pkg };
                f.metadata.insert(
                    "benign_pattern".to_string(),
                    "fedora-dbus-alias".to_string(),
                );
                f.metadata
                    .insert("alias_target".to_string(), target.display().to_string());
            }
        }
        findings.extend(chunk);
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
