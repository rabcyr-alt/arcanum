#!/usr/bin/env bash
# arcanum plugin: secrets_gitleaks
#
# Wraps the gitleaks binary to detect secrets (API keys, tokens, private keys)
# in text segments.  This plugin supplements the built-in Secrets detector with
# gitleaks' comprehensive ruleset.
#
# Requires: gitleaks >= 8  (https://github.com/gitleaks/gitleaks)
#
# Config block (under detectors.secrets_gitleaks in arcanum config):
#
#   {
#     "enabled": false,
#     "gitleaks_path": "gitleaks",   // path or name on $PATH
#     "timeout": 30
#   }
#
# arcanum plugin contract: reads one JSON object from stdin,
# writes one JSON object (with "findings" array) to stdout.
# Non-zero exit = failure; arcanum logs warning and continues.

set -euo pipefail

# ── Locate gitleaks ──────────────────────────────────────────────────────────

GITLEAKS_BIN="gitleaks"

# Read config from environment if set (arcanum may inject it)
if [ -n "${PII_GITLEAKS_PATH:-}" ]; then
    GITLEAKS_BIN="$PII_GITLEAKS_PATH"
fi

if ! command -v "$GITLEAKS_BIN" >/dev/null 2>&1; then
    echo '{"error":"gitleaks not found; install from https://github.com/gitleaks/gitleaks"}' >&2
    exit 1
fi

# ── Read stdin ───────────────────────────────────────────────────────────────

INPUT="$(cat)"

ACTION="$(echo "$INPUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('action','detect'))" 2>/dev/null || echo detect)"

if [ "$ACTION" = "ping" ]; then
    VER="$("$GITLEAKS_BIN" version 2>/dev/null || echo unknown)"
    echo "{\"status\":\"ok\",\"gitleaks_version\":\"$VER\"}"
    exit 0
fi

# ── Extract segments and scan ────────────────────────────────────────────────

TMPDIR_WORK="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_WORK"' EXIT

# Write each segment to a temp file and run gitleaks detect over it
FINDINGS_JSON="[]"

# Parse segments using Python (bash JSON parsing is fragile)
SEGMENTS_FILE="$TMPDIR_WORK/segments.json"
echo "$INPUT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
segs = d.get('segments', [])
with open('$SEGMENTS_FILE', 'w') as f:
    json.dump(segs, f)
" 2>/dev/null || { echo '{"findings":[]}'; exit 0; }

# Run gitleaks over each segment as a temp file
FINDINGS_JSON="$(python3 - <<'PYEOF'
import sys, json, subprocess, tempfile, os

with open('$SEGMENTS_FILE') as f:
    segments = json.load(f)

findings = []
for seg in segments:
    seg_id = seg.get('id', 'seg-?')
    text   = seg.get('text', '')
    if not text:
        continue

    # Write segment text to temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as tf:
        tf.write(text)
        tmp_path = tf.name

    try:
        result = subprocess.run(
            ['$GITLEAKS_BIN', 'detect', '--source', tmp_path,
             '--no-git', '--report-format', 'json', '--report-path', '/dev/stdout',
             '--exit-code', '0'],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0 and result.stdout.strip():
            try:
                leaks = json.loads(result.stdout)
                if isinstance(leaks, list):
                    for leak in leaks:
                        findings.append({
                            'segment_id': seg_id,
                            'type':       'secrets',
                            'value':      leak.get('Secret', leak.get('Match', '')),
                            'confidence': 0.90,
                            'start':      0,
                            'end':        0,
                            'rule_id':    leak.get('RuleID', ''),
                        })
            except json.JSONDecodeError:
                pass
    except Exception:
        pass
    finally:
        os.unlink(tmp_path)

print(json.dumps({'findings': findings}))
PYEOF
)"

echo "$FINDINGS_JSON"
