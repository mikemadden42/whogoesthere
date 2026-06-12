use crate::checker::Checker;
use crate::finding::Finding;

pub struct ModulesChecker;

impl Checker for ModulesChecker {
    fn name(&self) -> &'static str {
        "modules"
    }

    fn run(&self) -> Vec<Finding> {
        // TODO: kernel modules auto-loaded at boot.
        //   /etc/modules                 (Debian/Ubuntu legacy list)
        //   /etc/modules-load.d/*.conf   (systemd standard)
        //   /usr/lib/modules-load.d/*.conf
        //   /etc/modprobe.d/*.conf       (options, blacklists, install hooks)
        //   /lib/modprobe.d/, /usr/lib/modprobe.d/
        // also surface lsmod output (currently-loaded) as comparison signal.
        // `install <mod> <cmd>` lines in modprobe.d are particularly interesting —
        //  they run a command instead of loading the module.
        Vec::new()
    }
}
