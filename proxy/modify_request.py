import json
from pathlib import Path
from typing import Any, Dict, List

from mitmproxy import http

RULES_PATH = Path(__file__).with_name("rules.json")
_cached_mtime = None
_cached_rules: List[Dict[str, Any]] = []


def load_rules() -> List[Dict[str, Any]]:
    global _cached_mtime, _cached_rules

    try:
        stat = RULES_PATH.stat()
    except FileNotFoundError:
        _cached_rules = []
        _cached_mtime = None
        return _cached_rules

    if _cached_mtime == stat.st_mtime:
        return _cached_rules

    data = json.loads(RULES_PATH.read_text(encoding="utf-8"))
    _cached_rules = data.get("rules", [])
    _cached_mtime = stat.st_mtime
    print(f"[mitmproxy] Loaded {_cached_rules.__len__()} rule(s) from {RULES_PATH}")
    return _cached_rules


def match_rule(flow: http.HTTPFlow, rule: Dict[str, Any]) -> bool:
    if not rule.get("enabled", True):
        return False

    if flow.request.pretty_host != rule.get("host"):
        return False

    if not flow.request.path.startswith(rule.get("pathPrefix", "")):
        return False

    content_type = flow.request.headers.get("content-type", "").lower()
    expected = rule.get("matchContentType", "").lower()
    return not expected or expected in content_type


def request(flow: http.HTTPFlow) -> None:
    rules = load_rules()
    matching_rule = next((rule for rule in rules if match_rule(flow, rule)), None)

    if not matching_rule:
        return

    try:
        payload = json.loads(flow.request.get_text() or "{}")
    except json.JSONDecodeError as error:
        print(f"[mitmproxy] Failed to decode request body: {error}")
        return

    inject = matching_rule.get("inject", {})
    if isinstance(inject, dict):
        for key, value in inject.items():
            payload[key] = value

    append_config = matching_rule.get("appendToField", {})
    field = append_config.get("field")
    suffix = append_config.get("suffix", "")
    if field and field in payload and isinstance(payload[field], str):
        payload[field] = f"{payload[field]}{suffix}"

    flow.request.set_text(json.dumps(payload, ensure_ascii=False))
    print(f"[mitmproxy] Modified request body for {flow.request.pretty_url}")
    print(json.dumps(payload, ensure_ascii=False, indent=2))


def response(flow: http.HTTPFlow) -> None:
    rules = load_rules()
    matching_rule = next((rule for rule in rules if match_rule(flow, rule)), None)

    if not matching_rule:
        return

    print(f"[mitmproxy] Response status: {flow.response.status_code}")
    print("[mitmproxy] Response body:")
    print(flow.response.get_text(strict=False))
