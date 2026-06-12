use crate::checker::Checker;
use crate::finding::Finding;

pub struct SystemdChecker;

impl Checker for SystemdChecker {
    fn name(&self) -> &'static str {
        "systemd"
    }

    fn run(&self) -> Vec<Finding> {
        // TODO: walk system unit dirs:
        //   /etc/systemd/system/
        //   /run/systemd/system/
        //   /lib/systemd/system/, /usr/lib/systemd/system/
        // and user dirs (per-uid):
        //   ~/.config/systemd/user/
        //   /etc/systemd/user/
        //   /usr/lib/systemd/user/
        // for *.service, *.timer, *.path, *.socket
        // parse `[Service] ExecStart=` and `[Install] WantedBy=`
        Vec::new()
    }
}
