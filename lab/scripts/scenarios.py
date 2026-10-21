#!/usr/bin/env python3
"""Scenario driver (root inside the VM): runs the 100 attack + legitimate scenarios in the
frozen list (lab/scenarios/list.toml) with the live_detect agent, produces a result table, and
writes golden data (data/golden/{synthetic,legitimate} + catalog.txt). ADR-0009.

Usage: scenarios.py <target-dir> [--only S001,S002] [--write-golden]
Output: a table on stdout + /tmp/koru-scenarios/result.json. Golden data is written under /koru/data/golden.
"""
import json
import os
import subprocess
import sys
import time
import tomllib

TARGET_DIR = sys.argv[1]
ONLY = None
GOLDEN = "--write-golden" in sys.argv
for a in sys.argv:
    if a.startswith("--only="):
        ONLY = set(a.split("=", 1)[1].split(","))
REPO = "/koru"
WORK = "/tmp/koru-scenarios"
HOME_DIR = "/home/devops"
USER = "devops"
STATE = "/var/lib/koru-demo/state"
DEMO_ETC = "/etc/koru-demo"
DEMO_LIB = "/var/lib/koru-demo"
FINDINGS = f"{WORK}/findings.jsonl"
EVENTS = f"{WORK}/events.jsonl"
IMAGE = "docker.io/library/alpine:3.22"


def run(argv, **kw):
    return subprocess.run(argv, capture_output=True, text=True, timeout=kw.get("timeout", 120))


def devops(argv, **kw):
    return run(["sudo", "-u", USER, "--"] + argv, **kw)


def info(m):
    print(f"[scenarios] {m}", flush=True)


def lines(path):
    try:
        with open(path) as f:
            return f.read().splitlines()
    except FileNotFoundError:
        return []


def wait_finding(target, previous, timeout_secs=25):
    """(finding, latency_ms): the first finding among new finding lines that contains the target."""
    start = time.time()
    deadline = start + timeout_secs
    while time.time() < deadline:
        current = lines(FINDINGS)
        for line in current[previous:]:
            if target in line:
                try:
                    return json.loads(line), int((time.time() - start) * 1000)
                except json.JSONDecodeError:
                    continue
        time.sleep(0.3)
    return None, int((time.time() - start) * 1000)


METHODS = {
    "cat": "cat {H}",
    "head": "head -c 64 {H}",
    "grep": "grep -a -m1 . {H}",
    "cp": "cp {H} /tmp/.copy-{I}",
    "dd": "dd if={H} of=/dev/null bs=64 count=1",
    "base64": "base64 {H}",
    "python3": "python3 -c \"open('{Q}').read()\"",
    "tar": "tar -cf /tmp/.archive-{I}.tar {H}",
    "awk": "awk 'NR==1' {H}",
    "xargs": "echo {H} | xargs cat",
}


def make_wrapper(name, command):
    path = f"{HOME_DIR}/.local/lib/node_modules/{name}"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write("#!/bin/bash\ncd " + HOME_DIR + "\n" + command + " >/dev/null 2>&1\n:\n")
    os.chmod(path, 0o755)
    run(["chown", f"{USER}:{USER}", path])
    return path


def run_scenario(s, paths):
    target = paths.get(s["class"])
    if not target:
        return {"id": s["id"], "status": "FAIL", "reason": f"no path for class: {s['class']}"}
    command = METHODS[s["method"]].format(H=f"'{target}'", Q=target, I=s["id"])
    previous = len(lines(FINDINGS))
    context = s["context"]
    if context == "human":
        devops(["bash", "--noprofile", "--norc", "-c", command])
    elif context == "script":
        devops(["bash", "--noprofile", "--norc", "-c", f"exec {command}"])
    elif context in ("ai-claude", "ai-mcp"):
        name = ("@anthropic-ai/claude-code/bin/claude" if context == "ai-claude"
              else "@modelcontextprotocol/server-notes/mcp-server-notes")
        wrapper = make_wrapper(name, command.replace("exec ", ""))
        devops([wrapper])
    elif context == "container":
        image = "docker.io/library/python:3.14-alpine" if s["method"] == "python3" else IMAGE
        run(["podman", "run", "--rm", "-v", f"{HOME_DIR}:{HOME_DIR}:ro", image, "sh", "-c", command])
    else:
        return {"id": s["id"], "status": "FAIL", "reason": f"unknown context {context}"}
    finding, latency_ms = wait_finding(target, previous)
    if not finding:
        return {"id": s["id"], "status": "FAIL", "reason": "no finding arrived", "class": s["class"],
                "method": s["method"], "context": context}
    event = finding.get("event", {})
    actor = (event.get("actor") or {}).get("kind")
    techniques = [t if isinstance(t, str) else t.get("technique", "?")
                 for t in (event.get("detection") or {}).get("attack", [])]
    result = {"id": s["id"], "status": "PASS", "class": s["class"], "method": s["method"],
             "context": context, "actor": actor, "techniques": techniques, "latency_ms": latency_ms}
    if context in ("ai-claude", "ai-mcp") and actor != "ai_agent":
        result["status"] = "FAIL"
        result["reason"] = f"actor is not ai_agent: {actor}"
    return result


def main():
    if os.geteuid() != 0:
        print("root required", file=sys.stderr)
        return 1
    koru = f"{TARGET_DIR}/koru"
    agent = f"{TARGET_DIR}/examples/live_detect"
    for binary in (koru, agent):
        if not os.access(binary, os.X_OK):
            print(f"missing binary: {binary}", file=sys.stderr)
            return 1
    os.makedirs(WORK, exist_ok=True)
    with open(f"{REPO}/lab/scenarios/list.toml", "rb") as f:
        listing = tomllib.load(f)
    scenarios = [s for s in listing.get("scenario", []) if not ONLY or s["id"] in ONLY]
    legit = listing.get("legitimate", [])

    pulsard = run(["systemctl", "is-active", "pulsard.service"]).stdout.strip() == "active"
    if pulsard:
        run(["systemctl", "stop", "pulsard.service"])
    agent_proc = None
    try:
        # Setup: decoys + fake Koru paths (the live-detect pattern).
        run(["rm", "-rf", DEMO_ETC, DEMO_LIB])
        os.makedirs(DEMO_ETC, mode=0o700, exist_ok=True)
        os.makedirs(f"{DEMO_LIB}/store", mode=0o700, exist_ok=True)
        with open(f"{DEMO_ETC}/koru.toml", "w") as f:
            f.write("# fake configuration (lab)\nversion = 1\n")
        with open(f"{DEMO_ETC}/.env", "w") as f:
            f.write("KORU_SAMPLE=fake\n")
        run([koru, "decoy", "plant", "--package", f"{REPO}/packages/decoys",
                  "--root", HOME_DIR, "--state", STATE])
        run(["bash", "-c", f"mkdir -p {HOME_DIR}/.local/share && chown -R {USER}:{USER} {HOME_DIR}/.local"])
        for image in (IMAGE, "docker.io/library/python:3.14-alpine"):
            if run(["podman", "image", "exists", image]).returncode != 0:
                run(["podman", "pull", "-q", image], timeout=600)
        catalog_text = run([koru, "decoy", "list", "--state", STATE]).stdout
        with open(f"{WORK}/catalog.txt", "w") as f:
            f.write(catalog_text)
        known = {s["class"] for s in listing.get("scenario", [])}
        import glob as _glob
        for _p in _glob.glob(f"{REPO}/packages/decoys/*.toml"):
            with open(_p, "rb") as _f:
                known.add(tomllib.load(_f)["class"])
        paths = {}
        for line in catalog_text.splitlines():
            fields = line.split()
            cls = next((a for a in fields if a in known), None)
            if cls:
                paths.setdefault(cls, fields[-1])
        info(f"catalog: {len(paths)} classes")

        config = f"{WORK}/pulsar.toml"
        with open(config, "w") as f:
            f.write(f'[pulsar]\napi_socket_path = "/run/koru-scenarios.sock"\n')
        for path in (FINDINGS, EVENTS):
            open(path, "w").close()
        agent_proc = subprocess.Popen(
            [agent, "agent", "--source-tag", "synthetic",
             "--rules", f"{REPO}/packages/rules", "--agents", f"{REPO}/packages/agents",
             "--thresholds", f"{REPO}/thresholds.toml", "--decoy-state", STATE,
             "--koru-config", DEMO_ETC, "--koru-secret", f"{DEMO_ETC}/.env",
             "--koru-store", f"{DEMO_LIB}/store", "--koru-state", STATE,
             "--koru-binary", koru, "--koru-service", "koru-scenarios-demo",
             "--koru-process", "live_detect",
             "--pulsar-config", config, "--event-output", EVENTS],
            stdout=open(FINDINGS, "a"), stderr=open(f"{WORK}/agent.log", "a"))
        # Wait for the warmup finding (the agent-ready signal).
        ready = False
        for _ in range(120):
            if agent_proc.poll() is not None:
                break
            run(["bash", "-c", f"echo warmup >> {DEMO_ETC}/warmup.conf"])
            if any("warmup.conf" in s for s in lines(FINDINGS)):
                ready = True
                break
            time.sleep(0.5)
        if not ready:
            print(open(f"{WORK}/agent.log").read(), file=sys.stderr)
            print("the agent did not become ready", file=sys.stderr)
            return 1
        info(f"agent ready; running {len(scenarios)} scenarios")

        results = []
        for s in scenarios:
            r = run_scenario(s, paths)
            results.append(r)
            info(f"{r['id']} {r['status']} {s['class']}/{s['method']}/{s['context']}"
                  f" actor={r.get('actor')} {r.get('reason', '')}")
        # Legitimate phase: the same agent, non-decoy work; findings must not increase.
        findings_before = len(lines(FINDINGS))
        event_lines = len(lines(EVENTS))
        legit_event_start = event_lines
        devops(["bash", "-c", "mkdir -p apps/example-project notes backups/mysql && "
                 "echo '# example project' > apps/example-project/README.md && "
                 "printf 'fn main(){}\\n' > apps/example-project/main.rs"], )
        for m in legit:
            command = m["command"]
            if m.get("context") == "ai-claude":
                wrapper = make_wrapper("@anthropic-ai/claude-code/bin/claude", command)
                devops([wrapper])
            elif m.get("context") == "container":
                run(["podman", "run", "--rm", "-v", f"{HOME_DIR}:{HOME_DIR}:ro", IMAGE, "sh", "-c", command])
            elif m["id"] == "M03":
                devops(["bash", "-c", "cd apps/example-project && rustc -O main.rs -o /tmp/example-m03 || cc main.rs -o /tmp/example-m03 || true"])
            else:
                devops(["bash", "--noprofile", "--norc", "-c", f"cd {HOME_DIR} && {command}"], timeout=300)
            time.sleep(0.5)
        time.sleep(3)
        legit_findings = len(lines(FINDINGS)) - findings_before
        legit_result = {"finding_count": legit_findings, "status": "PASS" if legit_findings == 0 else "FAIL"}
        info(f"legitimate phase: {legit_findings} findings (0 expected)")

        if GOLDEN:
            catalog_paths = set(paths.values())
            synthetic, legit_events = [], []
            for i, line in enumerate(lines(EVENTS)):
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                path = ((event.get("target") or {}).get("path")) or ""
                if i < legit_event_start and path in catalog_paths:
                    synthetic.append(line)
                elif i >= legit_event_start and path not in catalog_paths:
                    legit_events.append(line)
            os.makedirs(f"{REPO}/data/golden/synthetic", exist_ok=True)
            os.makedirs(f"{REPO}/data/golden/legitimate", exist_ok=True)
            with open(f"{REPO}/data/golden/synthetic/events.jsonl", "w") as f:
                f.write("\n".join(synthetic) + "\n")
            with open(f"{REPO}/data/golden/legitimate/events.jsonl", "w") as f:
                f.write("\n".join(legit_events) + "\n")
            with open(f"{REPO}/data/golden/catalog.txt", "w") as f:
                f.write(catalog_text)
            info(f"golden data: {len(synthetic)} synthetic, {len(legit_events)} legitimate events")

        # Extra evidence (not counted toward the 100): the report_archive decoy added by data file only.
        extra = {"status": "ABSENT"}
        if "report_archive" in paths:
            previous = len(lines(FINDINGS))
            devops(["bash", "--noprofile", "--norc", "-c", f"cat '{paths['report_archive']}'"])
            b, _ = wait_finding(paths["report_archive"], previous)
            rule = ((b or {}).get("event", {}).get("detection") or {}).get("rule")
            extra = {"status": "PASS" if rule == "decoy_report_archive" else "FAIL", "rule": rule}
            info(f"extra new decoy (report_archive): {extra}")
        passed = sum(1 for r in results if r["status"] == "PASS")
        table = {"attack": {"passed": passed, "total": len(results), "results": results},
                 "legit": legit_result, "extra_new_decoy": extra}
        with open(f"{WORK}/result.json", "w") as f:
            json.dump(table, f, ensure_ascii=False, indent=1)
        print(f"\nATTACK: {passed}/{len(results)}  LEGIT_FALSE_POSITIVES: {legit_findings}")
        return 0 if passed == len(results) and legit_findings == 0 else 1
    finally:
        if agent_proc and agent_proc.poll() is None:
            agent_proc.terminate()
            try:
                agent_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                agent_proc.kill()
        run([koru, "decoy", "uninstall", "--state", STATE])
        run(["rm", "-rf", DEMO_ETC, DEMO_LIB])
        if pulsard:
            run(["systemctl", "start", "pulsard.service"])


if __name__ == "__main__":
    sys.exit(main())
