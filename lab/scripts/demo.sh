#!/usr/bin/env bash
# Demo (root inside the VM): the end-to-end scenario where an AI agent reads a fake MCP/SSH decoy
# and Koru produces a finding; records docs/demo/koru-demo.cast with asciinema.
# Usage: demo.sh <target-dir>
set -uo pipefail
TARGET=${1:?target directory}
REPO=/koru
WORK=/tmp/koru-demo
HOME_DIR=/home/devops
STATE=/var/lib/koru-demo/state
# The demo runs on the throwaway lab VM and resets the devops home, so leftovers from earlier
# runs cannot block planting.
userdel -r devops 2>/dev/null || true
useradd --create-home --shell /bin/bash devops
chmod 750 /home/devops
rm -rf /var/lib/koru-demo "$WORK"
mkdir -p "$WORK" "$REPO/docs/demo" /var/lib/koru-demo
command -v asciinema >/dev/null 2>&1 || { apt-get update -qq && apt-get install -y -qq asciinema >/dev/null; }

# Prints "rule|actor|technique" of the decoy_ssh_key finding by an ai_agent; exits 1 if none.
cat > "$WORK/check.py" <<'PC'
import json, sys
for line in open(sys.argv[1]):
    try:
        o = json.loads(line).get('event', {})
    except ValueError:
        continue
    t = o.get('detection') or {}
    actor = (o.get('actor') or {}).get('kind')
    if t.get('rule') == 'decoy_ssh_key' and actor == 'ai_agent':
        print('%s|%s|%s' % (t.get('rule'), actor, t.get('attack')))
        sys.exit(0)
sys.exit(1)
PC

cat > "$WORK/inner.sh" <<IC
#!/usr/bin/env bash
set -euo pipefail
fail() { echo; echo "Demo failed: \$1"; exit 1; }
echo '\$ koru decoy plant (decoys and breadcrumbs are being planted)'
$TARGET/koru decoy plant --package $REPO/packages/decoys --root $HOME_DIR --state $STATE > $WORK/plant.out 2>&1 \
  || { cat $WORK/plant.out; fail "koru decoy plant"; }
head -6 $WORK/plant.out
SSH_PATH=\$($TARGET/koru decoy list --state $STATE | awk '\$3=="ssh_key"{print \$NF}')
[ -n "\$SSH_PATH" ] || fail "no SSH decoy was planted"
mkdir -p /etc/koru-demo
printf '# fake configuration (lab)\nversion = 1\n' > /etc/koru-demo/koru.toml
printf '[pulsar]\napi_socket_path = "/run/koru-demo.sock"\n' > $WORK/pulsar.toml
$TARGET/examples/live_detect agent --source-tag synthetic --rules $REPO/packages/rules \
  --agents $REPO/packages/agents --thresholds $REPO/thresholds.toml --decoy-state $STATE \
  --koru-config /etc/koru-demo --pulsar-config $WORK/pulsar.toml \
  > $WORK/findings.jsonl 2>$WORK/agent.log &
AGENT=\$!
for i in \$(seq 1 90); do
  echo warmup >> /etc/koru-demo/warmup.conf
  grep -q warmup.conf $WORK/findings.jsonl 2>/dev/null && break
  sleep 1
done
rm -f /etc/koru-demo/warmup.conf
echo
echo "\$ The AI agent (claude chain) reads the fake SSH key: \$SSH_PATH"
install -d -m 755 -o devops -g devops $HOME_DIR/.local/lib/node_modules/@anthropic-ai/claude-code/bin
printf '#!/bin/bash\ncat "%s" >/dev/null\n' "\$SSH_PATH" > $HOME_DIR/.local/lib/node_modules/@anthropic-ai/claude-code/bin/claude
chmod 755 $HOME_DIR/.local/lib/node_modules/@anthropic-ai/claude-code/bin/claude
chown devops:devops $HOME_DIR/.local/lib/node_modules/@anthropic-ai/claude-code/bin/claude
sudo -u devops -- $HOME_DIR/.local/lib/node_modules/@anthropic-ai/claude-code/bin/claude
sleep 4
echo
echo '\$ Koru finding (rule / actor):'
RESULT=\$(python3 $WORK/check.py $WORK/findings.jsonl) || fail "no decoy_ssh_key finding with actor ai_agent"
IFS='|' read -r F_RULE F_ACTOR F_TECH <<< "\$RESULT"
echo "  \$F_RULE | actor: \$F_ACTOR | technique: \$F_TECH"
kill -TERM \$AGENT 2>/dev/null || true
sleep 2
$TARGET/koru decoy uninstall --state $STATE >/dev/null || true
rm -rf /etc/koru-demo
echo
echo "Demo done: the decoy access was caught (rule \$F_RULE, actor kind \$F_ACTOR)."
IC
chmod +x "$WORK/inner.sh"
asciinema rec --overwrite -t "Koru demo: an AI agent falls for the decoy" -c "bash $WORK/inner.sh" "$REPO/docs/demo/koru-demo.cast"
ls -la "$REPO/docs/demo/koru-demo.cast"
python3 "$WORK/check.py" "$WORK/findings.jsonl" >/dev/null || { echo "Demo failed: no decoy_ssh_key finding with actor ai_agent" >&2; exit 1; }
