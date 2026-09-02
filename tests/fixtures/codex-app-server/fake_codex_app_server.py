#!/usr/bin/env python3
"""Hermetic JSON-RPC fixture for kcap's Codex App Server acceptance tests.

The fixture intentionally uses small, synthetic envelopes.  It is not a copy of
or compatibility test for a live Codex App Server transcript.
"""

from __future__ import annotations

import json
import os
import signal
import sys
import time
from pathlib import Path


SCENARIO = os.environ.get("KCAP_APP_SERVER_FIXTURE_SCENARIO", "success")
LOG_PATH = Path(os.environ["KCAP_APP_SERVER_FIXTURE_LOG"])
CLEANUP_PATH = Path(os.environ["KCAP_APP_SERVER_FIXTURE_CLEANUP"])
PERMISSION_PROFILE = os.environ.get(
    "KCAP_APP_SERVER_FIXTURE_PERMISSION_PROFILE", "kcap_synthesis"
)
SECRET = "APP_SERVER_SECRET_MUST_NOT_LEAK"
SYNTHESIS_RESULT = json.loads(
    os.environ.get(
        "KCAP_APP_SERVER_FIXTURE_RESULT",
        json.dumps(
            {
                "title": "Fixture synthesis",
                "summary": "Safe structured result.",
                "takeaways": ["The fake server used JSON-RPC."],
            }
        ),
    )
)
DISABLED_ACTION_FEATURES = (
    "apps", "auth_elicitation", "browser_use", "browser_use_external", "browser_use_full_cdp_access",
    "code_mode_host", "computer_use", "deferred_executor", "enable_mcp_apps", "enable_fanout",
    "hooks", "image_generation", "in_app_browser", "memories", "multi_agent", "multi_agent_v2",
    "network_proxy", "plugin_hooks", "plugins", "remote_plugin", "request_permissions_tool",
    "shell_snapshot", "shell_tool", "skill_search", "skill_mcp_dependency_install",
    "standalone_web_search", "tool_call_mcp_elicitation", "tool_suggest", "unified_exec",
    "view_image", "workspace_dependencies",
)


def write_log(record: object) -> None:
    with LOG_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def redacted_record(value: object) -> object:
    if isinstance(value, dict):
        return {
            key: "<redacted>" if key in {"apiKey", "accessToken", "refreshToken"} else redacted_record(nested)
            for key, nested in value.items()
        }
    if isinstance(value, list):
        return [redacted_record(nested) for nested in value]
    return value


def send(value: object) -> None:
    if SCENARIO == "slow-drip":
        time.sleep(0.03)
    sys.stdout.write(json.dumps(value, separators=(",", ":")) + "\n")
    sys.stdout.flush()


THREAD_ID = "thread-fixture"
TURN_ID = "turn-fixture"


def thread_start_result(cwd: str) -> dict[str, object]:
    result: dict[str, object] = {
        "activePermissionProfile": {"extends": None, "id": PERMISSION_PROFILE},
        "approvalPolicy": "never",
        "approvalsReviewer": "user",
        "cwd": cwd,
        "instructionSources": [],
        "model": "fixture-model",
        "modelProvider": "fixture-provider",
        "runtimeWorkspaceRoots": [],
        "sandbox": {"networkAccess": False, "type": "readOnly"},
        "thread": {"id": THREAD_ID},
    }
    if SCENARIO == "attestation-profile-mismatch":
        result["activePermissionProfile"] = {"extends": None, "id": ":workspace"}
    elif SCENARIO == "attestation-approval-mismatch":
        result["approvalPolicy"] = "on-request"
    elif SCENARIO == "attestation-cwd-mismatch":
        result["cwd"] = "/unexpected"
    elif SCENARIO == "attestation-instructions-present":
        result["instructionSources"] = ["/unexpected/AGENTS.md"]
    elif SCENARIO == "attestation-roots-present":
        result["runtimeWorkspaceRoots"] = ["/unexpected"]
    elif SCENARIO == "attestation-sandbox-mismatch":
        result["sandbox"] = {"networkAccess": True, "type": "workspaceWrite", "writableRoots": [cwd]}
    return result


def item_params(item: dict[str, object], *, thread_id: str = THREAD_ID, turn_id: str = TURN_ID) -> dict[str, object]:
    return {"item": item, "threadId": thread_id, "turnId": turn_id}


def send_item(method: str, item: dict[str, object], *, thread_id: str = THREAD_ID, turn_id: str = TURN_ID) -> None:
    send({"method": method, "params": item_params(item, thread_id=thread_id, turn_id=turn_id)})


def send_item_lifecycle(item: dict[str, object]) -> None:
    send_item("item/started", item)
    send_item("item/completed", item)


def send_agent_lifecycle(item_id: str = "item-fixture") -> None:
    send_item_lifecycle(
        {
            "type": "agentMessage",
            "id": item_id,
            "text": json.dumps(SYNTHESIS_RESULT),
        }
    )


def send_turn_completed(turn_id: str = TURN_ID) -> None:
    send(
        {
            "method": "turn/completed",
            "params": {
                "threadId": THREAD_ID,
                "turn": {"id": turn_id, "status": "completed"},
            },
        }
    )


def on_terminate(_signal: int, _frame: object) -> None:
    CLEANUP_PATH.write_text("terminated\n", encoding="utf-8")
    raise SystemExit(0)


signal.signal(signal.SIGTERM, on_terminate)
signal.signal(signal.SIGINT, on_terminate)
write_log({"argv": sys.argv[1:], "pid": os.getpid()})

if sys.argv[1:3] == ["features", "list"]:
    for feature in DISABLED_ACTION_FEATURES:
        print(f"{feature} stable false")
    print("code_mode stable true")
    print("code_mode_host stable true")
    print("code_mode_only stable true")
    raise SystemExit(0)

for raw_line in sys.stdin:
    if SCENARIO == "malformed-json":
        sys.stdout.write("this is not json\n")
        sys.stdout.flush()
        raise SystemExit(0)
    if SCENARIO == "premature-exit":
        raise SystemExit(17)
    if SCENARIO == "timeout":
        time.sleep(5)
        raise SystemExit(0)

    request = json.loads(raw_line)
    write_log(redacted_record(request))
    request_id = request.get("id")
    method = request.get("method")

    if SCENARIO == "unknown-server-request":
        send({"id": 77, "method": "tools/call", "params": {}})
        raise SystemExit(0)
    if SCENARIO == "response-id-mismatch":
        send({"id": "wrong-id", "result": {}})
        raise SystemExit(0)
    if SCENARIO == "server-error":
        send(
            {
                "id": request_id,
                "error": {"code": -32000, "message": "fixture failure {}".format(SECRET)},
            }
        )
        # The broker owns the process lifetime after a protocol error.  Keep the
        # fixture alive until it receives the termination signal above.
        time.sleep(5)
        raise SystemExit(0)
    if SCENARIO == "oversized-message":
        send({"id": request_id, "result": {"padding": "x" * 4096}})
        raise SystemExit(0)

    if method == "initialize":
        send({"id": request_id, "result": {"server": "fixture"}})
    elif method == "initialized":
        continue
    elif method == "account/login/start":
        send({"id": request_id, "result": {"authenticated": True}})
    elif method == "thread/start":
        send({"id": request_id, "result": thread_start_result(str(request["params"]["cwd"]))})
    elif method == "turn/start":
        send({"id": request_id, "result": {"turn": {"id": TURN_ID}}})
        if SCENARIO == "event-flood":
            for number in range(10):
                send({"method": "warning", "params": {"event": number}})
        elif SCENARIO == "aggregate-output":
            for number in range(10):
                send({"method": "warning", "params": {"event": number}})
            send_agent_lifecycle()
            send_turn_completed()
        elif SCENARIO == "passive-items":
            for item_type in ("userMessage", "reasoning"):
                send_item_lifecycle({"type": item_type, "id": f"{item_type}-fixture"})
            send_agent_lifecycle()
            send_turn_completed()
        elif SCENARIO == "forbidden-item":
            send_item("item/completed", {"type": "commandExecution", "id": "forbidden-fixture"})
            raise SystemExit(0)
        elif SCENARIO == "forbidden-item-started":
            send_item("item/started", {"type": "commandExecution", "id": "forbidden-fixture"})
        elif SCENARIO == "turn-id-mismatch":
            send_agent_lifecycle()
            send_turn_completed("other-turn")
        elif SCENARIO == "item-thread-mismatch":
            send_item("item/started", {"type": "agentMessage", "id": "item-fixture"}, thread_id="other-thread")
        elif SCENARIO == "item-turn-mismatch":
            send_item("item/started", {"type": "agentMessage", "id": "item-fixture"}, turn_id="other-turn")
        elif SCENARIO == "item-completed-without-start":
            send_item(
                "item/completed",
                {"type": "agentMessage", "id": "item-fixture", "text": json.dumps(SYNTHESIS_RESULT)},
            )
        elif SCENARIO == "item-type-mismatch":
            send_item("item/started", {"type": "reasoning", "id": "item-fixture"})
            send_item(
                "item/completed",
                {"type": "agentMessage", "id": "item-fixture", "text": json.dumps(SYNTHESIS_RESULT)},
            )
        elif SCENARIO == "multiple-agent-messages":
            send_agent_lifecycle("first-agent")
            send_agent_lifecycle("second-agent")
        else:
            send_agent_lifecycle()
            send_turn_completed()
        raise SystemExit(0)
    else:
        send(
            {
                "id": request_id,
                "error": {"code": -32601, "message": "unsupported fixture method"},
            }
        )
        raise SystemExit(0)
