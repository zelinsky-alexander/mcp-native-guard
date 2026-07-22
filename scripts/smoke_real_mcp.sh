#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
usage: scripts/smoke_real_mcp.sh [--guard PATH] [--timeout SECONDS] [--allowed-tool NAME] [--denied-tool NAME] -- <server> [args...]

The downstream command may contain the literal token {sandbox}; it is replaced with the temporary sandbox path.
Defaults target @modelcontextprotocol/server-filesystem@2026.7.10: allowed=read_file, denied=write_file.
USAGE
}

GUARD=${MNG_GUARD:-./build/dev-debug/mcp-native-guard}
TIMEOUT=${MNG_SMOKE_TIMEOUT:-15}
ALLOWED_TOOL=${MNG_SMOKE_ALLOWED_TOOL:-read_file}
DENIED_TOOL=${MNG_SMOKE_DENIED_TOOL:-write_file}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --guard) GUARD=${2:?}; shift 2 ;;
    --timeout) TIMEOUT=${2:?}; shift 2 ;;
    --allowed-tool) ALLOWED_TOOL=${2:?}; shift 2 ;;
    --denied-tool) DENIED_TOOL=${2:?}; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    --) shift; break ;;
    *) usage; exit 2 ;;
  esac
done
[[ $# -gt 0 ]] || { usage; exit 2; }
[[ -x "$GUARD" ]] || { echo "guard executable not found or not executable: $GUARD" >&2; exit 2; }
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 2; }

TMPDIR_SMOKE=$(mktemp -d "${TMPDIR:-/tmp}/mng-real-mcp.XXXXXX")
cleanup() { rm -rf "$TMPDIR_SMOKE"; }
trap cleanup EXIT HUP INT TERM
SANDBOX="$TMPDIR_SMOKE/sandbox"
AUDIT="$TMPDIR_SMOKE/audit.jsonl"
mkdir -p "$SANDBOX"
printf 'smoke fixture\n' > "$SANDBOX/allowed.txt"

POLICY="$TMPDIR_SMOKE/policy.json"
python3 - "$POLICY" "$DENIED_TOOL" <<'PY'
import json, sys
with open(sys.argv[1], 'w', encoding='utf-8') as f:
    json.dump({"version":1,"defaults":{"visibility":"allow","invocation":"allow"},"tools":[{"name":sys.argv[2],"visibility":"deny","invocation":"deny"}]}, f)
PY

SERVER_CMD=()
for arg in "$@"; do
  SERVER_CMD+=("${arg//\{sandbox\}/$SANDBOX}")
done

python3 - "$GUARD" "$POLICY" "$AUDIT" "$SANDBOX" "$TIMEOUT" "$ALLOWED_TOOL" "$DENIED_TOOL" -- "${SERVER_CMD[@]}" <<'PY'
import json, os, selectors, signal, subprocess, sys, time

guard, policy, audit, sandbox, timeout_s, allowed, denied = sys.argv[1:8]
sep = sys.argv.index('--')
server_cmd = sys.argv[sep+1:]
timeout = float(timeout_s)

def fail(msg, proc=None):
    sys.stderr.write(f"smoke_real_mcp: {msg}\n")
    if proc:
        try: proc.kill()
        except Exception: pass
        try:
            out, err = proc.communicate(timeout=2)
            sys.stderr.write(f"--- stdout ---\n{out}\n--- stderr ---\n{err}\n")
        except Exception: pass
    raise SystemExit(1)

cmd = [guard, 'run', '--policy', policy, '--audit-file', audit, '--'] + server_cmd
proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', bufsize=1)
sel = selectors.DefaultSelector(); sel.register(proc.stdout, selectors.EVENT_READ)
stdout_lines=[]

def send(obj):
    line=json.dumps(obj,separators=(',',':'))+'\n'
    try:
        proc.stdin.write(line); proc.stdin.flush()
    except BrokenPipeError:
        fail('proxy stdin closed while sending request', proc)

def recv_id(req_id):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        if proc.poll() is not None:
            fail(f'proxy exited before response id {req_id}', proc)
        events=sel.select(max(0.05, min(0.5, deadline-time.monotonic())))
        for key,_ in events:
            line=key.fileobj.readline()
            if not line:
                continue
            stdout_lines.append(line)
            try: msg=json.loads(line)
            except json.JSONDecodeError:
                fail(f'protocol stdout contained non-JSON diagnostics: {line!r}', proc)
            if msg.get('id') == req_id:
                return msg
    fail(f'timed out waiting for response id {req_id}', proc)

init={"jsonrpc":"2.0","id":"init-1","method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"mng-smoke","version":"0.1.0"}}}
send(init); r=recv_id('init-1')
if 'result' not in r: fail(f'initialize failed: {r}', proc)
send({"jsonrpc":"2.0","method":"notifications/initialized","params":{}})
send({"jsonrpc":"2.0","id":"list-1","method":"tools/list","params":{}}); r=recv_id('list-1')
tools=r.get('result',{}).get('tools')
if not isinstance(tools, list): fail(f'tools/list did not return result.tools: {r}', proc)
names=[t.get('name') for t in tools if isinstance(t,dict)]
if denied in names: fail(f'denied tool {denied!r} was still visible in filtered tools/list: {names}', proc)
if allowed not in names: fail(f'allowed tool {allowed!r} not present; selected server tools are {names}', proc)

allowed_args={"path": os.path.join(sandbox,'allowed.txt')}
send({"jsonrpc":"2.0","id":"call-allow","method":"tools/call","params":{"name":allowed,"arguments":allowed_args}}); r=recv_id('call-allow')
if 'result' not in r or 'smoke fixture' not in json.dumps(r): fail(f'allowed call did not appear to reach downstream server: {r}', proc)

denied_path=os.path.join(sandbox,'denied-side-effect.txt')
denied_args={"path": denied_path, "content":"denied side effect\n"}
send({"jsonrpc":"2.0","id":"call-deny","method":"tools/call","params":{"name":denied,"arguments":denied_args}}); r=recv_id('call-deny')
err=r.get('error',{})
if err.get('code') != -32001 or err.get('message') != 'Tool call denied by policy': fail(f'denied call returned wrong error: {r}', proc)
if os.path.exists(denied_path): fail('denied operation created downstream side-effect file', proc)

proc.stdin.close()
deadline=time.monotonic()+timeout
while proc.poll() is None and time.monotonic()<deadline: time.sleep(0.05)
if proc.poll() is None: fail('proxy/child did not exit cleanly after stdin close', proc)
stderr=proc.stderr.read()
if proc.returncode != 0: fail(f'proxy exited with status {proc.returncode}; stderr={stderr!r}', proc)
for line in stdout_lines:
    msg=json.loads(line)
    if isinstance(msg,dict) and msg.get('event') in ('tools/call','tools/list_tool_removed'):
        fail(f'audit record leaked to protocol stdout: {line!r}', proc)
records=[]
with open(audit, encoding='utf-8') as f:
    for line in f:
        records.append(json.loads(line))
if not any(x.get('event')=='tools/call' and x.get('decision')=='allow' and x.get('tool')==allowed for x in records): fail('audit missing allowed tools/call record')
if not any(x.get('event')=='tools/call' and x.get('decision')=='deny' and x.get('tool')==denied for x in records): fail('audit missing denied tools/call record')
if not any(x.get('event')=='tools/list_tool_removed' and x.get('tool')==denied for x in records): fail('audit missing hidden-tool record')
serialized='\n'.join(json.dumps(x,sort_keys=True) for x in records)
if 'arguments' in serialized or 'denied side effect' in serialized or denied_path in serialized: fail('audit contains full arguments payload')
print('real MCP smoke test passed')
PY
