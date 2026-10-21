//! A below-threshold note from the security review: argv-parsing gaps in
//! stop detection. These used to slip through: bracketed glob patterns
//! (`systemctl stop 'kor[u]'`), `sh /etc/init.d/<service> stop`, `invoke-rc.d` and `rc-service`, and
//! the ABBREVIATED long options getopt_long allows (`--sig SIGKILL`, `--ful`, `--reg`):
//! an abbreviated option's value was read as positional. In the test detector, Koru's service
//! name is `koru`, its process name `koru-agent`, its pid 4242.

use crate::common::*;

fn rules(exe: &str, command: &[&str]) -> Vec<String> {
    let p = s(7000, 6999, exe, command).lineage(vec![ancestor(6999, "/usr/bin/bash", &["-bash"])]);
    rule_names(&findings_of(vec![exec(&p, 0)]))
}

fn table(examples: &[(&str, &[&str], bool)], rule: &str) {
    for (exe, command, expected) in examples {
        let outcome = rules(exe, command);
        let expected_list: Vec<&str> = if *expected { vec![rule] } else { vec![] };
        assert_eq!(outcome, expected_list, "{command:?}");
    }
}

#[test]
fn systemctl_bracket_glob_patterns() {
    table(
        &[
            ("/usr/bin/systemctl", &["systemctl", "stop", "kor[u]"], true),
            ("/usr/bin/systemctl", &["systemctl", "stop", "k[o]ru"], true),
            ("/usr/bin/systemctl", &["systemctl", "stop", "[kK]oru"], true),
            ("/usr/bin/systemctl", &["systemctl", "stop", "kor[a-z]"], true),
            ("/usr/bin/systemctl", &["systemctl", "stop", "k[!x]ru"], true),
            ("/usr/bin/systemctl", &["systemctl", "disable", "kor[u].service"], true),
            ("/usr/bin/systemctl", &["systemctl", "mask", "ko*.service"], true),
            ("/usr/bin/systemctl", &["systemctl", "stop", "k[x]oru"], false),
            ("/usr/bin/systemctl", &["systemctl", "stop", "kor[a-t]"], false),
            ("/usr/bin/systemctl", &["systemctl", "stop", "k[!o]ru"], false),
            ("/usr/bin/systemctl", &["systemctl", "stop", "n[g]inx"], false),
            ("/usr/bin/systemctl", &["systemctl", "stop", "[]koru"], false),
        ],
        "koru_service_stop",
    );
}

#[test]
fn systemctl_abbreviated_option_values_are_not_positional() {
    table(
        &[
            ("/usr/bin/systemctl", &["systemctl", "--sig", "SIGKILL", "kill", "koru"], true),
            ("/usr/bin/systemctl", &["systemctl", "--signal", "SIGKILL", "kill", "koru"], true),
            ("/usr/bin/systemctl", &["systemctl", "--kill-who", "main", "kill", "koru"], true),
            ("/usr/bin/systemctl", &["systemctl", "--ty", "service", "stop", "koru"], true),
            ("/usr/bin/systemctl", &["systemctl", "--type=service", "stop", "koru"], true),
            ("/usr/bin/systemctl", &["systemctl", "--prop", "Id", "stop", "koru"], true),
            ("/usr/bin/systemctl", &["systemctl", "--sig", "SIGKILL", "kill", "nginx"], false),
            ("/usr/bin/systemctl", &["systemctl", "--sig", "SIGKILL", "status", "koru"], false),
            ("/usr/bin/systemctl", &["systemctl", "--ty", "service", "start", "koru"], false),
        ],
        "koru_service_stop",
    );
}

#[test]
fn init_scripts_and_wrappers() {
    table(
        &[
            ("/bin/sh", &["sh", "/etc/init.d/koru", "stop"], true),
            ("/usr/bin/bash", &["bash", "/etc/init.d/koru", "restart"], true),
            ("/usr/bin/dash", &["dash", "-x", "/etc/init.d/koru", "stop"], true),
            ("/bin/sh", &["/bin/sh", "/etc/init.d/koru", "force-stop"], true),
            ("/usr/sbin/invoke-rc.d", &["invoke-rc.d", "koru", "stop"], true),
            ("/usr/sbin/invoke-rc.d", &["invoke-rc.d", "--quiet", "koru", "restart"], true),
            ("/sbin/rc-service", &["rc-service", "koru", "stop"], true),
            ("/sbin/rc-service", &["rc-service", "-v", "koru", "restart"], true),
            ("/bin/sh", &["sh", "/etc/init.d/nginx", "stop"], false),
            ("/bin/sh", &["sh", "/etc/init.d/koru", "status"], false),
            ("/bin/sh", &["sh", "/etc/init.d/koru", "start"], false),
            ("/usr/sbin/invoke-rc.d", &["invoke-rc.d", "nginx", "stop"], false),
            ("/usr/sbin/invoke-rc.d", &["invoke-rc.d", "koru", "status"], false),
            ("/sbin/rc-service", &["rc-service", "koru", "status"], false),
            ("/sbin/rc-service", &["rc-service", "nginx", "stop"], false),
        ],
        "koru_service_stop",
    );
}

#[test]
fn pkill_and_killall_abbreviated_long_options() {
    table(
        &[
            ("/usr/bin/pkill", &["pkill", "--ful", "koru-agent"], true),
            ("/usr/bin/pkill", &["pkill", "--full", "koru-agent"], true),
            ("/usr/bin/pkill", &["pkill", "--exa", "koru-agent"], true),
            ("/usr/bin/pkill", &["pkill", "--sig", "9", "koru-agent"], true),
            ("/usr/bin/pkill", &["pkill", "--signal", "9", "koru-agent"], true),
            ("/usr/bin/pkill", &["pkill", "--eu", "root", "koru-agent"], true),
            ("/usr/bin/pkill", &["pkill", "--euid", "root", "koru-agent"], true),
            ("/usr/bin/killall", &["killall", "--sig", "KILL", "koru-agent"], true),
            ("/usr/bin/killall", &["killall", "--old", "1h", "koru-agent"], true),
            ("/usr/bin/killall", &["killall", "--reg", "koru.*"], true),
            ("/usr/bin/killall", &["killall", "--regexp", "koru.*"], true),
            ("/usr/bin/pkill", &["pkill", "--sig", "9", "nginx"], false),
            ("/usr/bin/pkill", &["pkill", "--ful", "nginx"], false),
            ("/usr/bin/pkill", &["pkill", "--exa", "koru"], false),
            ("/usr/bin/killall", &["killall", "--sig", "KILL", "sshd"], false),
            ("/usr/bin/killall", &["killall", "--reg", "nginx.*"], false),
        ],
        "koru_process_kill",
    );
}
