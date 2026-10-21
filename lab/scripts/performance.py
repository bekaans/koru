#!/usr/bin/env python3
"""Performance measurement (root inside the VM; the measurement definitions are fixed):
- Install: signed package (temporary key) -> install.sh -> systemd service (koru-agent).
- Under the reference load (build + file operations) for 600+ s: the agent's CPU must be
  <2% of the system's total capacity (the single-core value is reported too), peak RSS < 100 MB.
- Latency: 50 decoy accesses (13 s apart; the rate-limit token is 12 s) -> the local fake ntfy
  receiver's record times; p95 < 5 s.
Output: /tmp/koru-perf/result.json + a stdout summary. Usage: performance.py <release-dir>
"""
import json
import os
import subprocess
import sys
import time

RELEASE = sys.argv[1]
WORK = "/tmp/koru-perf"
AD = "system-observer"
PORT = 18081
CLK = os.sysconf("SC_CLK_TCK")


def run(argv, **kw):
    return subprocess.run(argv, capture_output=True, text=True, timeout=kw.get("timeout", 300))


def info(m):
    print(f"[performance] {m}", flush=True)


def proc_stat():
    with open("/proc/stat") as f:
        first = f.readline().split()[1:]
    return sum(int(x) for x in first)


def pid_stat(pid):
    with open(f"/proc/{pid}/stat") as f:
        fields = f.read().rsplit(")", 1)[1].split()
    # fields: state(0) ... utime(11), stime(12) (stat fields 14/15)
    return int(fields[11]) + int(fields[12])


def pid_rss_kb(pid):
    with open(f"/proc/{pid}/status") as f:
        for line in f:
            if line.startswith("VmHWM:"):
                return int(line.split()[1])
    return 0


def main():
    if os.geteuid() != 0:
        print("root required", file=sys.stderr)
        return 1
    os.makedirs(WORK, exist_ok=True)
    # Temporary signing key (for this measurement only; not the release signing).
    run(["bash", "-c",
         f"cd {WORK} && openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 "
         f"-aes-256-cbc -pass pass:perf-temporary -out key.pem 2>/dev/null && "
         f"openssl pkey -in key.pem -passin pass:perf-temporary -pubout -out public.pem 2>/dev/null"])
    key_b64 = run(["bash", "-c",
                       f"openssl pkcs8 -topk8 -in {WORK}/key.pem -passin pass:perf-temporary "
                       f"-passout pass:perf-temporary 2>/dev/null | base64 -w0"]).stdout.strip()
    env = dict(os.environ, KORU_SIGNING_KEY=key_b64, KORU_SIGNING_KEY_PASSWORD="perf-temporary")
    package_dir = f"{WORK}/package_dir"
    run(["rm", "-rf", package_dir])
    r = subprocess.run(["sh", "/koru/distribution/prepare-release.sh", package_dir, "--version", "0.1.0-a6",
                        "--binary-dir", RELEASE],
                       capture_output=True, text=True, env=env, timeout=300)
    if r.returncode != 0:
        print(r.stdout, r.stderr, file=sys.stderr)
        return 1
    fingerprint = run(["bash", "-c", f"sha256sum {WORK}/public.pem | cut -d' ' -f1"]).stdout.strip()
    # Fake ntfy receiver (timestamped).
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
    receiver = subprocess.Popen(["python3", receiver_code])
    with open(f"{WORK}/environment.env", "w") as f:
        f.write(f"KORU_NTFY_URL=http://127.0.0.1:{PORT}/perf\n")
    os.chmod(f"{WORK}/environment.env", 0o600)
    try:
        r = run(["sh", "/koru/distribution/install.sh", "--public-key", f"{WORK}/public.pem",
                 "--fingerprint", fingerprint, package_dir, "--", "--source-tag", "synthetic",
                 "--decoy-root", "/home/devops", "--environment", f"{WORK}/environment.env"], timeout=600)
        info(f"install exit: {r.returncode}")
        if r.returncode != 0:
            print(r.stdout[-3000:], r.stderr[-3000:], file=sys.stderr)
            return 1
        time.sleep(5)
        pid = int(run(["systemctl", "show", "-p", "MainPID", "--value", AD]).stdout.strip())
        info(f"agent pid {pid}")
        target = "/home/devops/.aws/credentials"
        if not os.path.exists(target):
            listing = run([f"{RELEASE}/koru", "decoy", "list", "--state",
                         f"/var/lib/{AD}/decoy"]).stdout
            info(f"listing: {listing[:200]}")
            return 1
        # Reference load: build + file operations (devops).
        load = subprocess.Popen(["sudo", "-u", "devops", "--", "bash", "-c",
                                "mkdir -p /tmp/load && cd /tmp/load && "
                                "python3 -c \"print('fn f0(){}')\" > b.rs && "
                                "for i in $(seq 1 4000); do echo \"pub fn f$i() {{}}\" >> b.rs; done && "
                                "while true; do rustc -O b.rs --crate-type lib -o /dev/null 2>/dev/null; "
                                "dd if=/dev/zero of=d.bin bs=1M count=100 conv=fsync 2>/dev/null; "
                                "cat d.bin > /dev/null; rm -f d.bin; done"])
        accesses = []
        rss_peak = 0
        total0, agent0 = proc_stat(), pid_stat(pid)
        start = time.time()
        measure_s = 650
        next_access = start
        while time.time() - start < measure_s:
            now = time.time()
            rss_peak = max(rss_peak, pid_rss_kb(pid))
            if now >= next_access and len(accesses) < 50:
                t0 = time.time_ns()
                run(["sudo", "-u", "devops", "--", "cat", target])
                accesses.append(t0)
                next_access = now + 13
            time.sleep(1)
        total1, agent1 = proc_stat(), pid_stat(pid)
        load.terminate()
        duration = time.time() - start
        # A short wait for the notifications to arrive.
        time.sleep(10)
        received = [int(x) for x in open(f"{WORK}/received.txt").read().split()]
        latencies = []
        for t0 in accesses:
            later = [a for a in received if a >= t0]
            if later:
                latencies.append((min(later) - t0) / 1e9)
        latencies.sort()
        p95 = latencies[min(len(latencies) - 1, int(len(latencies) * 0.95))] if latencies else None
        cpu_total_pct = (agent1 - agent0) / max(1, (total1 - total0)) * 100
        cpu_core_pct = (agent1 - agent0) / CLK / duration * 100
        result = {
            "duration_s": round(duration), "access_count": len(accesses),
            "notifications_matched": len(latencies), "latency_p95_s": p95,
            "latency_max_s": latencies[-1] if latencies else None,
            "cpu_total_capacity_pct": round(cpu_total_pct, 3),
            "cpu_single_core_pct": round(cpu_core_pct, 2),
            "rss_peak_mb": round(rss_peak / 1024, 1),
            "pass": bool(p95 is not None and p95 < 5 and cpu_total_pct < 2 and rss_peak / 1024 < 100),
        }
        with open(f"{WORK}/result.json", "w") as f:
            json.dump(result, f, indent=1)
        info(json.dumps(result, ensure_ascii=False))
        return 0 if result["pass"] else 1
    finally:
        receiver.terminate()
        run(["systemctl", "stop", AD], timeout=60)
        run([f"{RELEASE}/koru", "uninstall", "--config", f"/etc/{AD}/config.toml"], timeout=300)


if __name__ == "__main__":
    sys.exit(main())