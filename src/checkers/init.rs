use crate::checker::Checker;
use crate::finding::Finding;

pub struct InitChecker;

impl Checker for InitChecker {
    fn name(&self) -> &'static str {
        "init"
    }

    fn run(&self) -> Vec<Finding> {
        // TODO (SysV / legacy init, still present on many distros):
        //   /etc/init.d/         (scripts)
        //   /etc/rc{0..6}.d/     (symlinks → run order)
        //   /etc/rc.local        (often shipped, sometimes user-edited)
        //   /etc/inittab         (mostly historical, occasionally present)
        Vec::new()
    }
}
