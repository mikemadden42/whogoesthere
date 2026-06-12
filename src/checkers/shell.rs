use crate::checker::Checker;
use crate::finding::Finding;

pub struct ShellChecker;

impl Checker for ShellChecker {
    fn name(&self) -> &'static str {
        "shell"
    }

    fn run(&self) -> Vec<Finding> {
        // TODO: shell init files (per shell, system + user scope).
        //   System: /etc/profile, /etc/profile.d/*, /etc/bash.bashrc, /etc/zsh/*,
        //           /etc/environment (already covered by ld_so for LD_PRELOAD)
        //   User:   ~/.profile, ~/.bashrc, ~/.bash_profile, ~/.bash_login,
        //           ~/.zshrc, ~/.zshenv, ~/.zlogin, ~/.zprofile
        // surface non-empty files; flag suspicious patterns (eval, base64, curl|sh).
        // for v1: list each file's existence + size; deeper parsing later.
        Vec::new()
    }
}
