use crate::checker::Checker;
use crate::finding::Finding;

pub struct UdevChecker;

impl Checker for UdevChecker {
    fn name(&self) -> &'static str {
        "udev"
    }

    fn run(&self) -> Vec<Finding> {
        // TODO: udev rules can execute commands on device events.
        //   /etc/udev/rules.d/    (admin overrides — most interesting)
        //   /run/udev/rules.d/
        //   /lib/udev/rules.d/    (package-shipped — usually fine)
        //   /usr/lib/udev/rules.d/
        // surface lines containing RUN+= or IMPORT{program}=
        Vec::new()
    }
}
