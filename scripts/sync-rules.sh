#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

DATA_DIR="$PROJECT_ROOT/policies/data"
REGO_DIR="$PROJECT_ROOT/policies/rego"

mkdir -p "$DATA_DIR" "$REGO_DIR"

GTFOBINS_URL="https://gtfobins.github.io/api.json"
GTFOBINS_FILE="$DATA_DIR/gtfobins.json"
FALCO_FILE="$DATA_DIR/falco_lists.json"
COMMANDS_FILE="$DATA_DIR/commands.yaml"
MERGED_FILE="$REGO_DIR/data.json"

echo "==> Fetching GTFOBins data..."
if ! curl -sL "$GTFOBINS_URL" | python3 -c "
import json, sys
data = json.load(sys.stdin)
execs = data.get('executables', {})
result = {}
for name, info in execs.items():
    funcs = list(info.get('functions', {}).keys())
    if funcs:
        result[name] = {'functions': funcs}
json.dump(result, sys.stdout, indent=2, sort_keys=True)
" > "$GTFOBINS_FILE.tmp" 2>/dev/null; then
    echo "    WARNING: GTFOBins API unavailable, keeping existing file"
    rm -f "$GTFOBINS_FILE.tmp"
else
    mv "$GTFOBINS_FILE.tmp" "$GTFOBINS_FILE"
    echo "    OK: $(python3 -c "import json; print(len(json.load(open('$GTFOBINS_FILE'))))" 2>/dev/null || echo '?') binaries"
fi

echo "==> Writing Falco lists..."
cat > "$FALCO_FILE" <<'FALCO_EOF'
{
  "shell_binaries": ["bash", "csh", "ksh", "sh", "tcsh", "zsh", "dash", "fish"],
  "sensitive_file_names": ["/etc/shadow", "/etc/sudoers", "/etc/pam.conf", "/etc/security/passwd", "/etc/ssh/sshd_config"],
  "network_tools": ["curl", "wget", "nc", "ncat", "netcat", "socat", "ssh", "scp", "rsync", "telnet", "ftp"]
}
FALCO_EOF
echo "    OK"

echo "==> Merging into OPA data..."
python3 -c "
import json, sys, re

with open('$GTFOBINS_FILE') as f:
    gtfobins = json.load(f)

with open('$FALCO_FILE') as f:
    falco = json.load(f)

commands = {}
with open('$COMMANDS_FILE') as f:
    content = f.read()

in_commands = False
for line in content.split('\n'):
    if line.startswith('commands:'):
        in_commands = True
        continue
    if in_commands:
        if line and not line[0].isspace() and line[0] != '#':
            break
        m = re.match(r'^\s+(\w[\w\d]*)\s*:\s*\{(.+)\}', line)
        if m:
            name = m.group(1)
            props_str = m.group(2)
            props = {}
            for prop in props_str.split(','):
                prop = prop.strip()
                if ':' in prop:
                    k, v = prop.split(':', 1)
                    props[k.strip()] = v.strip().strip('\"')
            commands[name] = props

merged = {'gtfobins': gtfobins, 'falco': falco, 'commands': commands}
with open('$MERGED_FILE', 'w') as f:
    json.dump(merged, f, indent=2, sort_keys=True)
    f.write('\n')
print(f'    OK: {len(gtfobins)} gtfobins, {len(commands)} commands')
"

echo "==> Validating JSON files..."
for f in "$GTFOBINS_FILE" "$FALCO_FILE" "$MERGED_FILE"; do
    if python3 -c "import json; json.load(open('$f'))" 2>/dev/null; then
        echo "    PASS: $(basename "$f")"
    else
        echo "    FAIL: $(basename "$f")" >&2
        exit 1
    fi
done

echo "==> Done."
