//! AI-agent signatures: `schemas/agent-signature.v1.json`, the Rust types, and match examples.

use std::collections::BTreeMap;
use std::fs;

use koru_detect::{AgentKind, parse_agent_signature, read_agent_signatures};
use serde_json::Value;

use crate::common::{agent_directory, agents, argv, files, temporary};
use crate::json_schema::with_schema;

const SCHEMA: &str = "agent-signature.v1.json";

const SAMPLE_SIGNATURE: &str = r#"schema = 1
id = "sample-agent"
name = "Sample agent"
kind = "coding_assistant"
references = ["https://example.com/sample-agent"]
description = "A sample signature for tests."
validation_date = "2026-10-10"

[[condition]]
exe_name = ["sample-agent"]

[[condition]]
exe_name = ["node", "python3.*"]
script_name = ["sample-agent"]
"#;

fn toml_json(text: &str) -> Value {
    let value: toml::Value = toml::from_str(text).unwrap_or_else(|e| panic!("invalid TOML: {e}"));
    serde_json::to_value(value).unwrap()
}

fn replace_in(old: &str, new: &str) -> String {
    assert!(SAMPLE_SIGNATURE.contains(old), "not in the sample: {old}");
    SAMPLE_SIGNATURE.replacen(old, new, 1)
}

#[test]
fn a_sample_signature_is_valid_on_both_sides() {
    with_schema(SCHEMA, &toml_json(SAMPLE_SIGNATURE)).unwrap();
    let i = parse_agent_signature(SAMPLE_SIGNATURE).unwrap();
    assert_eq!(i.id, "sample-agent");
    assert_eq!(i.kind, AgentKind::CodingAssistant);
    assert_eq!(i.kind.name(), "coding_assistant");
    assert!(i.matches("/opt/sample/bin/sample-agent", &argv(&["sample-agent"])));
    assert!(i.matches("/usr/bin/python3.12", &argv(&["python3", "/usr/local/bin/sample-agent", "--x"])));
    assert!(!i.matches("/usr/bin/cat", &argv(&["cat", "/usr/local/bin/sample-agent"])), "not an interpreter");
    assert!(!i.matches("/usr/bin/python3.12", &argv(&["python3", "other.py"])));
}

#[test]
fn every_repo_signature_is_valid_on_both_sides() {
    let files = files(&agent_directory(), "toml");
    assert!(files.len() >= 11, "{}", files.len());
    for file in &files {
        let text = fs::read_to_string(file).unwrap();
        let name = file.file_stem().unwrap().to_string_lossy().into_owned();
        with_schema(SCHEMA, &toml_json(&text)).unwrap_or_else(|e| panic!("{name}: JSON schema: {e}"));
        let i = parse_agent_signature(&text).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(i.id, name, "the file name must equal the id");
        assert!(!i.references.is_empty());
        for k in &i.references {
            assert!(k.starts_with("https://"), "{name}: the official source must be https: {k}");
        }
    }
    assert_eq!(agents().signatures().len(), files.len());
}

#[test]
fn every_requested_agent_is_covered() {
    let kinds: BTreeMap<String, AgentKind> = agents().signatures().iter().map(|i| (i.id.clone(), i.kind)).collect();
    let expected = [
        ("claude-code", AgentKind::CodingAssistant),
        ("cursor-cli", AgentKind::CodingAssistant),
        ("codex-cli", AgentKind::CodingAssistant),
        ("aider", AgentKind::CodingAssistant),
        ("gemini-cli", AgentKind::CodingAssistant),
        ("goose", AgentKind::CodingAssistant),
        ("openhands", AgentKind::CodingAssistant),
        ("github-copilot-cli", AgentKind::CodingAssistant),
        ("mcp-server", AgentKind::McpServer),
        ("langgraph-cli", AgentKind::AgentFramework),
        ("crewai", AgentKind::AgentFramework),
        ("autogen-studio", AgentKind::AgentFramework),
    ];
    for (id, kind) in expected {
        assert_eq!(kinds.get(id), Some(&kind), "{id}");
    }
}

/// (expected signature or None, exe, argv)
const EXAMPLES: &[(Option<&str>, &str, &[&str])] = &[
    // Coding assistants
    (Some("claude-code"), "/home/devops/.local/share/claude/versions/2.1.3", &["claude"]),
    (Some("claude-code"), "/home/devops/.local/share/claude/versions/2.1.3", &["/home/devops/.local/bin/claude", "-p"]),
    (Some("claude-code"), "/usr/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe", &["claude"]),
    (Some("claude-code"), "/usr/bin/node", &["node", "/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js"]),
    (Some("codex-cli"), "/home/devops/.local/bin/codex", &["codex", "exec", "ls"]),
    (Some("codex-cli"), "/usr/bin/node", &["node", "/usr/lib/node_modules/@openai/codex/bin/codex.js"]),
    (Some("gemini-cli"), "/usr/bin/node", &["node", "/usr/local/bin/gemini"]),
    (Some("cursor-cli"), "/home/devops/.local/share/cursor-agent/versions/2026.10.01-e373342/cursor-agent", &["agent"]),
    (
        Some("cursor-cli"),
        "/usr/bin/node",
        &["node", "/home/devops/.local/share/cursor-agent/versions/2026.10.01-e373342/index.js"],
    ),
    (Some("aider"), "/home/devops/.local/bin/aider", &["aider"]),
    (Some("aider"), "/usr/bin/python3.12", &["/usr/bin/python3", "/home/devops/.local/bin/aider", "--yes"]),
    (Some("aider"), "/usr/bin/python3.12", &["python3", "-m", "aider"]),
    (Some("goose"), "/home/devops/.local/bin/goose", &["goose", "session"]),
    (
        Some("openhands"),
        "/home/devops/.local/share/uv/tools/openhands/bin/python",
        &["/home/devops/.local/share/uv/tools/openhands/bin/python", "/home/devops/.local/bin/openhands"],
    ),
    (Some("github-copilot-cli"), "/usr/bin/node", &["node", "/usr/local/bin/copilot"]),
    (Some("opencode"), "/home/devops/.opencode/bin/opencode", &["opencode"]),
    (Some("qwen-code"), "/usr/bin/node", &["node", "/usr/local/bin/qwen"]),
    // MCP servers
    (Some("mcp-server"), "/usr/bin/node", &["npm", "exec", "-y", "@modelcontextprotocol/server-memory"]),
    (
        Some("mcp-server"),
        "/usr/bin/node",
        &["node", "/root/.npm/_npx/4f1c/node_modules/.bin/mcp-server-filesystem", "/srv"],
    ),
    (Some("mcp-server"), "/root/.local/bin/uvx", &["uvx", "mcp-server-git", "--repository", "/srv/repo"]),
    (Some("mcp-server"), "/usr/bin/python3.12", &["python3", "-m", "mcp_server_fetch"]),
    (Some("mcp-server"), "/usr/bin/python3.12", &["python3", "/opt/koru-scenario/mcp-server-notes.py"]),
    (Some("mcp-server"), "/usr/local/bin/github-mcp-server", &["github-mcp-server", "stdio"]),
    // Agent frameworks
    (Some("langgraph-cli"), "/usr/bin/python3.12", &["/usr/bin/python3", "/home/devops/.local/bin/langgraph", "dev"]),
    (
        Some("crewai"),
        "/home/devops/.local/share/uv/tools/crewai/bin/python",
        &["/home/devops/.local/share/uv/tools/crewai/bin/python", "/home/devops/.local/bin/crewai", "run"],
    ),
    (Some("autogen-studio"), "/usr/bin/python3.12", &["python3", "/usr/local/bin/autogenstudio", "ui"]),
    (Some("autogen-studio"), "/usr/bin/python3.12", &["python3", "-m", "autogenstudio"]),
    // Negative examples: the name only appears as an argument, generic names, ordinary processes.
    (None, "/usr/bin/cat", &["cat", "/tmp/claude"]),
    (None, "/usr/bin/cat", &["cat", "/tmp/mcp-server-notes.txt"]),
    (None, "/usr/bin/grep", &["grep", "-r", "@modelcontextprotocol", "/srv"]),
    (None, "/home/devops/.local/bin/agent", &["agent"]),
    (None, "/usr/bin/python3.12", &["python3", "/opt/application/server.py"]),
    (None, "/usr/bin/node", &["node", "/srv/app/index.js"]),
    (None, "/usr/bin/bash", &["bash", "-c", "ls"]),
    (None, "/usr/bin/vim", &["vim", "/home/devops/.local/bin/aider"]),
];

#[test]
fn matching_examples() {
    let a = agents();
    for (expected, exe, command) in EXAMPLES {
        let found_agent = a.match_pattern(exe, &argv(command)).map(|i| i.id.as_str());
        assert_eq!(found_agent, *expected, "exe {exe}, argv {command:?}");
    }
}

#[test]
fn the_exe_path_is_matched_normalized() {
    let a = agents();
    let found_agent = a.match_pattern("/home/devops/.local/share//claude/./versions/2.1.3", &argv(&["x"]));
    assert_eq!(found_agent.map(|i| i.id.as_str()), Some("claude-code"));
    let found_agent = a.match_pattern("/home/devops/.local/share/claude/versions/../../../../tmp/x", &argv(&["x"]));
    assert_eq!(found_agent, None, "the normalized path is /home/devops/tmp/x, not under the claude directory");
}

#[test]
fn invalid_signatures_are_rejected() {
    // Rejected by both sides.
    let both_sides: Vec<(&str, String)> = vec![
        (
            "unknown field",
            format!("{SAMPLE_SIGNATURE}extra = 1\n").replacen("[[condition]]", "extra_top = 1\n[[condition]]", 1),
        ),
        ("source missing", replace_in("references = [\"https://example.com/sample-agent\"]\n", "")),
        ("an empty source list", replace_in("[\"https://example.com/sample-agent\"]", "[]")),
        ("a wrong kind", replace_in("kind = \"coding_assistant\"", "kind = \"browser\"")),
        ("no condition", SAMPLE_SIGNATURE.split("\n[[condition]]").next().unwrap().to_string() + "\n"),
        ("an empty condition", replace_in("[[condition]]\nexe_name = [\"sample-agent\"]\n", "[[condition]]\n")),
        (
            "an unknown field in the condition",
            replace_in("exe_name = [\"sample-agent\"]", "process_name = [\"sample-agent\"]"),
        ),
        ("an empty value list", replace_in("exe_name = [\"sample-agent\"]", "exe_name = []")),
        ("schema version", replace_in("schema = 1", "schema = 2")),
        ("no description", replace_in("description = \"A sample signature for tests.\"\n", "")),
    ];
    for (name, text) in &both_sides {
        assert!(with_schema(SCHEMA, &toml_json(text)).is_err(), "{name}: the JSON schema accepted it");
        assert!(parse_agent_signature(text).is_err(), "{name}: Rust accepted it");
    }
    // The Rust side only (patterns and semantic rules).
    let rust: Vec<(&str, String)> = vec![
        ("non-https source", replace_in("https://example.com/sample-agent", "http://example.com/sample-agent")),
        ("a match-everything pattern", replace_in("exe_name = [\"sample-agent\"]", "exe_name = [\"*\"]")),
        ("single pattern with a fixed character", replace_in("exe_name = [\"sample-agent\"]", "exe_name = [\"a*\"]")),
        ("too short a substring", replace_in("exe_name = [\"sample-agent\"]", "argument_contains = [\"ab\"]")),
        ("an uppercase id", replace_in("id = \"sample-agent\"", "id = \"Sample-Agent\"")),
        ("an invalid date", replace_in("validation_date = \"2026-10-10\"", "validation_date = \"2026-02-30\"")),
    ];
    for (name, text) in &rust {
        assert!(parse_agent_signature(text).is_err(), "{name}: Rust accepted it");
    }
}

#[test]
fn duplicate_ids_and_file_names_are_checked() {
    let d = temporary();
    fs::write(d.path.join("sample-agent.toml"), SAMPLE_SIGNATURE).unwrap();
    assert_eq!(read_agent_signatures(&d.path).unwrap().signatures().len(), 1);
    fs::write(d.path.join("sample-agent 2.toml"), SAMPLE_SIGNATURE).unwrap();
    assert!(read_agent_signatures(&d.path).is_err(), "the file name is not the id (an iCloud copy)");
    let d = temporary();
    assert!(read_agent_signatures(&d.path).is_err(), "an empty directory");
    assert!(read_agent_signatures(&d.path.join("missing")).is_err());
}
