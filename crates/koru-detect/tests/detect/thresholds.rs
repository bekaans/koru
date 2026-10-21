//! `thresholds.toml`: schema (deny_unknown_fields) and consistency checks.

use std::fs;

use koru_detect::parse_thresholds;

use crate::common::{repo_root, thresholds};

fn text() -> String {
    fs::read_to_string(repo_root().join("thresholds.toml")).unwrap()
}

fn replace_in(old: &str, new: &str) -> String {
    let m = text();
    assert!(m.contains(old), "missing from thresholds.toml: {old}");
    m.replacen(old, new, 1)
}

#[test]
fn repo_thresholds_are_valid_and_consistent() {
    let e = thresholds();
    assert_eq!(e.version, 1);
    let a = &e.actor;
    for g in [
        a.agent_signature_confidence,
        a.agent_signature_and_machine_speed_confidence,
        a.machine_speed_and_discovery_confidence,
        a.interactive_shell_confidence,
        a.interactive_shell_and_human_speed_confidence,
    ] {
        assert!(g > 0.0 && g <= 1.0, "{g}");
    }
    assert!(a.agent_signature_and_machine_speed_confidence >= a.agent_signature_confidence);
    assert!(a.interactive_shell_and_human_speed_confidence >= a.interactive_shell_confidence);
    assert!(a.human_speed.command_interval_median_ms > a.machine_speed.command_interval_median_ms);
    assert!(a.discovery.commands.iter().any(|k| k == "whoami"));
    assert!(a.shell.names.iter().any(|k| k == "bash"));
    assert!(e.memory.max_sessions > 0 && e.memory.max_commands_per_session > 0);
}

#[test]
fn broken_thresholds_are_rejected() {
    let examples: Vec<(&str, String)> = vec![
        ("unknown field", format!("{}extra = 1\n", text())),
        ("an unknown top field", replace_in("version = 1\n", "version = 1\nextra = 1\n")),
        ("missing field", replace_in("agent_signature_confidence = 0.8\n", "")),
        ("version", replace_in("version = 1", "version = 2")),
        ("confidence above 1", replace_in("agent_signature_confidence = 0.8", "agent_signature_confidence = 1.5")),
        (
            "negative confidence",
            replace_in("interactive_shell_confidence = 0.5", "interactive_shell_confidence = -0.1"),
        ),
        (
            "inconsistent confidence order",
            replace_in(
                "agent_signature_and_machine_speed_confidence = 0.9",
                "agent_signature_and_machine_speed_confidence = 0.7",
            ),
        ),
        (
            "human speed below machine speed",
            replace_in(
                "[actor.human_speed]\ncommand_interval_median_ms = 2000",
                "[actor.human_speed]\ncommand_interval_median_ms = 500",
            ),
        ),
        ("zero intervals", replace_in("min_intervals = 3", "min_intervals = 0")),
        ("zero window", replace_in("window_secs = 300\n\n# Human speed", "window_secs = 0\n\n# Human speed")),
        ("an empty discovery list", replace_in("commands = [", "commands = []\nold = [")),
        (
            "an empty shell list",
            replace_in(
                "names = [\"bash\", \"sh\", \"dash\", \"zsh\", \"fish\", \"ksh\", \"mksh\", \"tcsh\", \"csh\"]",
                "names = []",
            ),
        ),
        ("zero memory", replace_in("max_sessions = 4096", "max_sessions = 0")),
        ("a number as text", replace_in("max_sessions = 4096", "max_sessions = \"4096\"")),
    ];
    for (name, m) in &examples {
        assert!(parse_thresholds(m).is_err(), "{name}: was accepted");
    }
    assert!(parse_thresholds(&text()).is_ok());
}
