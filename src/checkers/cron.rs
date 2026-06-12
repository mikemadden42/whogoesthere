use crate::checker::Checker;
use crate::finding::Finding;

pub struct CronChecker;

impl Checker for CronChecker {
    fn name(&self) -> &'static str {
        "cron"
    }

    fn run(&self) -> Vec<Finding> {
        // TODO:
        //   /etc/crontab
        //   /etc/cron.d/
        //   /etc/cron.{hourly,daily,weekly,monthly}/
        //   /var/spool/cron/{crontabs/,}*  (per-user, root-only readable)
        //   /etc/anacrontab
        //   at jobs: /var/spool/at/
        // parse minute hour dom mon dow user command (no `user` field in user crontabs)
        // flag @reboot specifically
        Vec::new()
    }
}
