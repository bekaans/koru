#!/usr/bin/env python3
"""Resilience tests (root inside the VM): kill -9, full disk,
network outage, corrupt configuration. In each scenario Koru either recovers or alarms
(controlled fail / service failed / queue + delivery). Output: /tmp/koru-resilience/result.json
Usage: resilience.py <release-dir>
"""
import json
import os
import subprocess
import sys
import time

RELEASE = sys.argv[1]
WORK = "/tmp/koru-resilience"
AD = "system-observer"
PORT = 18082


def run(argv, **kw):
    return subprocess.run(argv, capture_output=True, text=True, timeout=kw.get("timeout", 300))


def info(m):
    print(f"[resilience] {m}", flush=True)


def service_pid():
    return int(run(["systemctl", "show", "-p", "MainPID", "--value", AD]).stdout.strip() or 0)


def notification_count():
    path = f"{WORK}/received.txt"
    return len(open(path).read().split()) if os.path.exists(path) else 0


def main():
    if os.geteuid() != 0:
        print("root required", file=sys.stderr)
        return 1
    os.makedirs(WORK, exist_ok=True)
    run(["bash", "-c",
         f"cd {WORK} && openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 "
         f"-aes-256-cbc -pass pass:resil-temporary -out key.pem 2>/dev/null && "
         f"openssl pkey -in key.pem -passin pass:resil-temporary -pubout -out public.pem 2>/dev/null"])
    key_b64 = run(["bash", "-c",
                       f"openssl pkcs8 -topk8 -in {WORK}/key.pem -passin pass:resil-temporary "
                       f"-passout pass:resil-temporary 2>/dev/null | base64 -w0"]).stdout.strip()
    env = dict(os.environ, KORU_SIGNING_KEY=key_b64, KORU_SIGNING_KEY_PASSWORD="resil-temporary")
    package_dir = f"{WORK}/package_dir"
    run(["rm", "-rf", package_dir])
    r = subprocess.run(["sh", "/koru/distribution/prepare-release.sh", package_dir, "--version", "0.1.0-a6d",
                        "--binary-dir", RELEASE], capture_output=True, text=True, env=env, timeout=300)
    if r.returncode != 0:
        print(r.stdout, r.stderr, file=sys.stderr)
        return 1
    fingerprint = run(["bash", "-c", f"sha256sum {WORK}/public.pem | cut -d' ' -f1"]).stdout.strip()
    receiver_code = f"{WORK}/receiver.py"
    with open(receiver_code, "w") as f:
        f.write(
            "import http.server, time, sys\n"
            "class H(http.server.BaseHTTPRequestHandler):\n"
            "    def do_POST(self):\n"
            "        n=int(self.headers.get('Content-Length','0')); self.rfile.read(n)\n"
            f"        open('{WORK}/received.txt','a').write(str(time.time_ns())+'\\n')\n"
            "        self.send_response(200); self.send_header('Content-Length','0'); self.end_headers()\n"
            "    def log_message(self,*a): pass\n"
            f"http.server.HTTPServer(('127.0.0.1',{PORT}),H).serve_forever()\n")
    open(f"{WORK}/received.txt", "w").close()
    with open(f"{WORK}/environment.env", "w") as f:
        f.write(f"KORU_NTFY_URL=http://127.0.0.1:{PORT}/topic\n")
    os.chmod(f"{WORK}/environment.env", 0o600)
    results = {}
    receiver = subprocess.Popen(["python3", receiver_code])
    try:
        r = run(["sh", "/koru/distribution/install.sh", "--public-key", f"{WORK}/public.pem",
                 "--fingerprint", fingerprint, package_dir, "--", "--source-tag", "synthetic",
                 "--decoy-root", "/home/devops", "--environment", f"{WORK}/environment.env"], timeout=600)
        if r.returncode != 0:
            print(r.stdout[-2000:], r.stderr[-2000:], file=sys.stderr)
            return 1
        time.sleep(5)
        target = "/home/devops/.aws/credentials"

        def wait_access_notification(previous, secs=40):
            run(["sudo", "-u", "devops", "--", "cat", target])
            deadline = time.time() + secs
            while time.time() < deadline:
                if notification_count() > previous:
                    return True
                time.sleep(0.5)
            return False

        # 1) kill -9: systemd recovers it, the notification flow continues.
        previous = notification_count()
        pid0 = service_pid()
        run(["kill", "-9", str(pid0)])
        new_pid = 0
        for _ in range(60):
            time.sleep(1)
            new_pid = service_pid()
            if new_pid and new_pid != pid0 and run(["systemctl", "is-active", AD]).stdout.strip() == "active":
                break
        recovered = bool(new_pid and new_pid != pid0)
        flows = wait_access_notification(previous) if recovered else False
        results["kill_9"] = {"status": "PASS" if (recovered and flows) else "FAIL",
                              "old_pid": pid0, "new_pid": new_pid, "notification_flows": flows}
        info(f"kill-9: {results['kill_9']}")

        # 2) Network outage: while the receiver is down, notifications queue; on return they are delivered.
        receiver.terminate()
        receiver.wait(timeout=10)
        previous = notification_count()
        run(["sudo", "-u", "devops", "--", "cat", target])
        time.sleep(8)
        outage_count = notification_count()
        receiver = subprocess.Popen(["python3", receiver_code])
        delivered = False
        for _ in range(90):
            if notification_count() > outage_count:
                delivered = True
                break
            time.sleep(1)
        results["network_outage"] = {"status": "PASS" if (outage_count == previous and delivered) else "FAIL",
                                    "arrived_during_outage": outage_count - previous, "delivered_after": delivered}
        info(f"network outage: {results['network_outage']}")

        # 3) Full disk: on a small tmpfs, store writes fail in a controlled way; the process does not crash.
        run(["bash", "-c", f"mkdir -p {WORK}/full && mount -t tmpfs -o size=8M tmpfs {WORK}/full"])
        try:
            input_file = f"{WORK}/large.jsonl"
            line = open("/koru/data/golden/synthetic/events.jsonl").readline()
            with open(input_file, "w") as f:
                for _ in range(4000):
                    f.write(line)
            r = run([f"{RELEASE}/koru", "event", "ingest", "--store", f"{WORK}/full/event.db",
                     "--input", input_file], timeout=120)
            controlled = r.returncode != 0 and ("panicked" not in (r.stdout + r.stderr))
            results["full_disk"] = {"status": "PASS" if controlled else "FAIL",
                                     "exit_code": r.returncode}
        finally:
            run(["umount", f"{WORK}/full"])
        info(f"full disk: {results['full_disk']}")

        # 4) Corrupt configuration: validation rejects it; if the installed service's config is corrupted it goes failed.
        with open(f"{WORK}/corrupt.toml", "w") as f:
            f.write('schema_version = 1\n[unknown]\nx = 1\n')
        r = run([f"{RELEASE}/koru-agent", "--validate", "--config", f"{WORK}/corrupt.toml"])
        validate_rejected = r.returncode != 0
        cfg = f"/etc/{AD}/config.toml"
        backup = open(cfg).read()
        with open(cfg, "a") as f:
            f.write("\n[unknown]\nx = 1\n")
        run(["systemctl", "restart", AD], timeout=120)
        time.sleep(5)
        service_state = run(["systemctl", "is-active", AD]).stdout.strip()
        with open(cfg, "w") as f:
            f.write(backup)
        run(["systemctl", "restart", AD], timeout=120)
        time.sleep(5)
        fixed = run(["systemctl", "is-active", AD]).stdout.strip() == "active"
        results["corrupt_config"] = {
            "status": "PASS" if (validate_rejected and service_state != "active" and fixed) else "FAIL",
            "validate_exit": r.returncode, "service_when_corrupt": service_state, "active_after_fix": fixed}
        info(f"corrupt configuration: {results['corrupt_config']}")
    finally:
        receiver.terminate()
        run(["systemctl", "stop", AD], timeout=60)
        run([f"{RELEASE}/koru", "uninstall", "--config", f"/etc/{AD}/config.toml"], timeout=300)
    with open(f"{WORK}/result.json", "w") as f:
        json.dump(results, f, ensure_ascii=False, indent=1)
    return 0 if all(v["status"] == "PASS" for v in results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())