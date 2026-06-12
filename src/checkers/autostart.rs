use crate::checker::Checker;
use crate::finding::Finding;

pub struct AutostartChecker;

impl Checker for AutostartChecker {
    fn name(&self) -> &'static str {
        "autostart"
    }

    fn run(&self) -> Vec<Finding> {
        // TODO: XDG autostart spec (.desktop files run at desktop login).
        //   System: /etc/xdg/autostart/
        //   User:   ~/.config/autostart/
        // parse .desktop INI:
        //   Exec=          (target command)
        //   Hidden=true    (disabled)
        //   X-GNOME-Autostart-enabled=false  (disabled)
        Vec::new()
    }
}
