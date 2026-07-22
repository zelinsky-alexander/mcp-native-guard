#!/usr/bin/env python3
"""Stream and summarize mcp-native-guard JSONL audit health evidence."""

import argparse
import collections
import json
import os
import sys


def summarize(paths):
    summary = {
        "files_read": 0, "invalid_json_lines": 0, "truncated_final_lines": 0,
        "total_sessions": 0, "clean_sessions": 0, "unclean_sessions": 0,
        "unmatched_session_starts": 0, "allowed_tool_calls": 0,
        "denied_tool_calls": 0, "hidden_tools": 0, "invalid_messages": 0,
        "oversized_messages": 0, "excessive_nesting_events": 0,
        "correlation_capacity_events": 0, "audit_write_failures": 0,
        "by_server_label": {}, "most_recent_session_timestamp": None,
        "most_recent_unhealthy_session": None, "policy_fingerprints_observed": [],
    }
    balances = collections.Counter()
    labels = collections.Counter()
    fingerprints = set()
    missing = []
    for path in paths:
        try:
            stream = open(os.path.expanduser(path), "rb")
        except OSError as error:
            missing.append(f"{path}: {error.strerror}")
            continue
        summary["files_read"] += 1
        with stream:
            line_number = 0
            while True:
                raw = stream.readline()
                if not raw:
                    break
                line_number += 1
                final_truncated = not raw.endswith(b"\n")
                try:
                    record = json.loads(raw)
                    if not isinstance(record, dict):
                        raise ValueError("record is not an object")
                except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                    summary["invalid_json_lines"] += 1
                    if final_truncated:
                        summary["truncated_final_lines"] += 1
                    continue
                event = record.get("event")
                reason = record.get("reason")
                label = record.get("server_label", "unlabeled")
                if not isinstance(label, str):
                    label = "unlabeled"
                if event in ("session_start", "session_end"):
                    ts = record.get("ts") or record.get("timestamp")
                    if isinstance(ts, str) and (summary["most_recent_session_timestamp"] is None or
                                                ts > summary["most_recent_session_timestamp"]):
                        summary["most_recent_session_timestamp"] = ts
                    fingerprint = record.get("policy_hash")
                    if isinstance(fingerprint, str):
                        fingerprints.add(fingerprint)
                    key = (label, record.get("downstream_executable"), fingerprint)
                    if event == "session_start":
                        summary["total_sessions"] += 1
                        labels[label] += 1
                        balances[key] += 1
                    else:
                        if balances[key] > 0:
                            balances[key] -= 1
                        clean = record.get("clean_shutdown") is True
                        summary["clean_sessions" if clean else "unclean_sessions"] += 1
                        if not clean and isinstance(ts, str):
                            previous = summary["most_recent_unhealthy_session"]
                            if previous is None or ts > previous.get("ts", ""):
                                summary["most_recent_unhealthy_session"] = {
                                    "ts": ts, "server_label": label,
                                    "child_exit_status": record.get("child_exit_status"),
                                    "termination_reason": record.get("termination_reason"),
                                }
                elif event == "tools/call":
                    key = "allowed_tool_calls" if record.get("decision") == "allow" else "denied_tool_calls"
                    summary[key] += 1
                elif event == "tools/list_tool_removed": summary["hidden_tools"] += 1
                elif event == "message_rejected":
                    if reason == "message_too_large": summary["oversized_messages"] += 1
                    elif reason == "excessive_nesting": summary["excessive_nesting_events"] += 1
                    else: summary["invalid_messages"] += 1
                elif event == "tools/list_correlation" or reason == "capacity_exhausted":
                    summary["correlation_capacity_events"] += 1
                elif event == "audit_write_failure": summary["audit_write_failures"] += 1
    summary["unmatched_session_starts"] = sum(balances.values())
    summary["by_server_label"] = dict(sorted(labels.items()))
    summary["policy_fingerprints_observed"] = sorted(fingerprints)
    return summary, missing


def main(argv=None):
    parser = argparse.ArgumentParser(description="Summarize local guard JSONL health evidence")
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument("files", nargs="+")
    args = parser.parse_args(argv)
    summary, missing = summarize(args.files)
    for error in missing:
        print(f"error: cannot read {error}", file=sys.stderr)
    if args.as_json:
        print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    else:
        for key, value in summary.items():
            if isinstance(value, (dict, list)):
                value = json.dumps(value, sort_keys=True, separators=(",", ":"))
            print(f"{key.replace('_', ' ')}: {value}")
    unhealthy = (missing or summary["invalid_json_lines"] or summary["unclean_sessions"] or
                 summary["unmatched_session_starts"])
    return 1 if unhealthy else 0


if __name__ == "__main__":
    raise SystemExit(main())
