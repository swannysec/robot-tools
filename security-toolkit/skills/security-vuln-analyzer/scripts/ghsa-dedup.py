#!/usr/bin/env python3
"""Deterministic GHSA deduplication steps for security-vuln-analyzer.

Subcommands:
  index        D0 fingerprints and the cross-advisory index (IDs, digests, hashed shingles, literals)
  cluster      D0 candidate pairs, SAME_TEXT proposals, and D2 clusters from an index
  reanchor     D3 symbol anchoring at one common revision
  d4-packet    code-derived D4 packet for a pair (no reporter text)
  m1           membership-check literal coverage
  m2-packet    M2 packet: Y's typed literals and X's contract only
  m4-packet    M4 packet: X's code-derived records, Y's claim quotes, M1 and M3 results
  route-d4     map D4 verdicts and a D5 result to a relation record
  route-m      map M1-M4 results to a relation record or FULL_ANALYSIS
  relate       record a D0 SAME_TEXT proposal or a human-set relation
  human        record the D6 human decision on a relation
  invalidate   compare a relation's dependencies with current digests

The script never weighs evidence, merges findings, or changes a finding's status.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import unicodedata
from typing import Any

ADAPTER_NAME = "security-vuln-analyzer-ghsa-dedup"
ADAPTER_VERSION = "1.0.0"
SHINGLE_WORDS = 5
SAME_TEXT_SIMILARITY = 0.9
CANDIDATE_SIMILARITY = 0.5
LITERAL_PATTERNS = {
    "paths": re.compile(r"(?<![\w/.-])(?:[\w.-]+/)+[\w.-]+\.[A-Za-z0-9]{1,8}(?![\w/])"),
    "symbols": re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)+\b|\b[a-z_][a-z0-9_]{2,}(?=\()"),
    "config_keys": re.compile(r"\b[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){1,5}\b"),
    "advisory_ids": re.compile(r"\bGHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\b|\bCVE-\d{4}-\d{4,7}\b"),
    "shas": re.compile(r"\b[0-9a-f]{7,40}\b"),
    "versions": re.compile(r"\bv?\d+\.\d+(?:\.\d+)?\b"),
}
MAX_LITERAL = 200
CODE_DERIVED_FIELDS = (
    "record_id", "ghsa_id", "claim_ids", "locations", "anchors", "control_site", "primitive_class",
    "variant_family", "enumerated_variants", "invariant_test_contract", "final_status", "fix_revision",
)
D4_RELATIONS = {"SAME_ROOT_CAUSE", "VARIANT", "DISTINCT"}
EXIT_OK = 0
EXIT_USAGE = 2
EXIT_ROUTED_ELSEWHERE = 8


class UsageError(ValueError):
    pass


def load(path: str | Path) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise UsageError(f"cannot read JSON {path}: {error}") from error


def dump(path: str | Path, value: Any) -> None:
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def digest(value: Any) -> str:
    data = value if isinstance(value, bytes) else json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def normalize_text(text: str) -> str:
    text = unicodedata.normalize("NFC", text).replace("\r\n", "\n").replace("\r", "\n").lower()
    text = re.sub(r"[^\w]+", " ", text)  # punctuation and spacing differences are not textual differences
    return re.sub(r"\s+", " ", text).strip()


def shingle_hashes(text: str) -> list[str]:
    words = normalize_text(text).split(" ")
    if len(words) < SHINGLE_WORDS:
        return [hashlib.sha256(" ".join(words).encode()).hexdigest()[:16]] if words and words[0] else []
    return sorted({hashlib.sha256(" ".join(words[i:i + SHINGLE_WORDS]).encode()).hexdigest()[:16]
                   for i in range(len(words) - SHINGLE_WORDS + 1)})


def extract_literals(text: str) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for kind, pattern in LITERAL_PATTERNS.items():
        values = {match.group(0) for match in pattern.finditer(text) if len(match.group(0)) <= MAX_LITERAL}
        found[kind] = sorted(values)
    return found


def jaccard(a: list[str], b: list[str]) -> float:
    left, right = set(a), set(b)
    return len(left & right) / len(left | right) if left | right else 0.0


# ---------- D0 / D2 ----------

def command_index(args: argparse.Namespace) -> dict[str, Any]:
    entries = []
    for item in load(args.entries).get("entries", []):
        intake = load(item["intake"])
        advisory = intake["advisory"]
        text = "\n".join([advisory.get("summary", ""), advisory.get("description", "")])
        typed = {}
        if item.get("h1_check"):
            typed = load(item["h1_check"]).get("typed_literals", {})
        entries.append({
            "ghsa_id": advisory["ghsa_id"],
            "state": advisory.get("state", ""),
            "created_at": advisory.get("created_at", ""),
            "updated_at": advisory.get("updated_at", ""),
            "body_sha256": advisory.get("body_sha256", ""),
            "normalized_text_sha256": hashlib.sha256(normalize_text(text).encode()).hexdigest(),
            "shingles": shingle_hashes(text),
            "d0_literals": extract_literals(text),
            "typed_literals": typed,
        })
    entries.sort(key=lambda e: (e["created_at"], e["ghsa_id"]))
    index = {"record_type": "ghsa_dedup_index", "adapter": ADAPTER_NAME, "adapter_version": ADAPTER_VERSION,
             "created_at_utc": utc_now(), "advisories": entries}
    dump(args.out, index)
    return {"status": "COMPLETE", "advisories": len(entries)}


def literal_set(entry: dict[str, Any]) -> set[tuple[str, str]]:
    joinable = ("paths", "symbols", "config_keys")
    values = {(kind, value) for kind in joinable for value in entry.get("d0_literals", {}).get(kind, [])}
    typed_map = {"file_paths": "paths", "entry_point_symbols": "symbols", "config_keys": "config_keys"}
    for kind, mapped in typed_map.items():
        values |= {(mapped, value) for value in entry.get("typed_literals", {}).get(kind, [])}
    return values


def all_extracted(entry: dict[str, Any]) -> Any:
    return {"d0": entry.get("d0_literals", {}), "typed": entry.get("typed_literals", {})}


def command_cluster(args: argparse.Namespace) -> dict[str, Any]:
    advisories = load(args.index)["advisories"]
    pairs = []
    parent = {a["ghsa_id"]: a["ghsa_id"] for a in advisories}

    def find(node: str) -> str:
        while parent[node] != node:
            parent[node] = parent[parent[node]]
            node = parent[node]
        return node

    for i, left in enumerate(advisories):
        for right in advisories[i + 1:]:
            similarity = jaccard(left["shingles"], right["shingles"])
            shared = sorted(literal_set(left) & literal_set(right))
            lineage = (right["ghsa_id"] in left["d0_literals"].get("advisory_ids", [])
                       or left["ghsa_id"] in right["d0_literals"].get("advisory_ids", []))
            if similarity < CANDIDATE_SIMILARITY and not shared and not lineage:
                continue
            same_text = similarity >= SAME_TEXT_SIMILARITY and all_extracted(left) == all_extracted(right)
            pairs.append({
                "canonical": left["ghsa_id"], "other": right["ghsa_id"],
                "similarity": round(similarity, 4), "shared_literal_count": len(shared),
                "shared_literal_kinds": sorted({kind for kind, _ in shared}),
                "lineage_reference": lineage, "same_text_proposed": same_text,
            })
            if shared or lineage:
                parent[find(right["ghsa_id"])] = find(left["ghsa_id"])
    order = {a["ghsa_id"]: (a["created_at"], a["ghsa_id"]) for a in advisories}
    groups: dict[str, list[str]] = {}
    for ghsa in parent:
        groups.setdefault(find(ghsa), []).append(ghsa)
    clusters = sorted((sorted(members, key=lambda member: order[member]) for members in groups.values() if len(members) > 1), key=lambda m: order[m[0]])
    result = {"record_type": "ghsa_dedup_clusters", "adapter": ADAPTER_NAME, "adapter_version": ADAPTER_VERSION,
              "pairs": pairs, "clusters": [{"canonical": members[0], "members": members} for members in clusters]}
    dump(args.out, result)
    return {"status": "COMPLETE", "pairs": len(pairs), "clusters": len(clusters)}


# ---------- D3 ----------

def command_reanchor(args: argparse.Namespace) -> dict[str, Any]:
    checkout = Path(args.checkout)
    head = subprocess.run(["git", "-C", str(checkout), "rev-parse", "HEAD"], check=False, stdout=subprocess.PIPE, text=True, timeout=10)
    if head.returncode != 0 or head.stdout.strip() != args.revision:
        raise UsageError("checkout HEAD does not equal the common revision")
    anchors = []
    for item in load(args.anchors).get("anchors", []):
        symbol, path = item["symbol"], item["path"]
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_:.]{0,199}", symbol) or ".." in path.split("/") or path.startswith("/"):
            raise UsageError("anchor symbol or path is malformed")
        found = subprocess.run(["git", "-C", str(checkout), "grep", "-h", "-n", "-F", "-w", "-e", symbol.split("::")[-1], "--", path],
                               check=False, stdout=subprocess.PIPE, text=True, timeout=30)
        lines = [int(line.split(":", 1)[0]) for line in found.stdout.splitlines() if line.split(":", 1)[0].isdigit()]
        status = "NOT_FOUND" if not lines else "FOUND" if item.get("line") in lines else "MOVED"
        anchors.append({"record_id": item.get("record_id", ""), "symbol": symbol, "path": path,
                        "original_revision": item.get("revision", ""), "original_line": item.get("line", 0),
                        "common_revision": args.revision, "lines_at_common": lines, "status": status})
    # Group by the resolved identity at the common revision (path, final symbol component, and
    # matched lines), not by the supplied spelling, so `a::f` and `f` resolving to the same lines
    # share a site while different names or different lines stay separate.
    control_sites: dict[tuple[str, str, tuple[int, ...]], list[str]] = {}
    for anchor in anchors:
        if anchor["status"] != "NOT_FOUND":
            key = (anchor["path"], anchor["symbol"].split("::")[-1], tuple(anchor["lines_at_common"]))
            control_sites.setdefault(key, []).append(anchor["record_id"])
    shared = [{"path": path, "symbol": symbol, "lines_at_common": list(lines), "record_ids": sorted(set(ids))}
              for (path, symbol, lines), ids in sorted(control_sites.items()) if len(set(ids)) > 1]
    dump(args.out, {"record_type": "ghsa_dedup_anchors", "common_revision": args.revision, "anchors": anchors, "shared_control_sites": shared})
    return {"status": "COMPLETE", "anchors": len(anchors), "shared_control_sites": len(shared)}


# ---------- packets ----------

def code_derived(record: dict[str, Any]) -> dict[str, Any]:
    return {key: record[key] for key in CODE_DERIVED_FIELDS if key in record}


def command_d4_packet(args: argparse.Namespace) -> dict[str, Any]:
    x, y = load(args.x_finding), load(args.y_finding)
    packet = {"packet_type": "dedup_d4", "pair": {"canonical_record_id": x.get("record_id", ""), "other_record_id": y.get("record_id", ""),
              "canonical_ghsa_id": x.get("ghsa_id", ""), "other_ghsa_id": y.get("ghsa_id", ""), "other_claim_id": args.claim_id},
              "canonical_records": code_derived(x), "other_records": code_derived(y)}
    if args.anchors:
        packet["anchors"] = load(args.anchors)
    dump(args.out, packet)
    return {"status": "COMPLETE", "packet": args.out}


def claim_by_id(h1: dict[str, Any], claim_id: str) -> dict[str, Any]:
    for claim in h1.get("claims", []):
        if claim.get("claim_id") == claim_id:
            return claim
    raise UsageError(f"claim {claim_id} not found")


def command_m2_packet(args: argparse.Namespace) -> dict[str, Any]:
    x, h1, check = load(args.x_finding), load(args.y_h1), load(args.y_h1_check)
    if check.get("effective_status") != "COMPLETE":
        raise UsageError("Y's H1 output has not passed intake-check")
    claim = claim_by_id(h1, args.claim_id)
    packet = {"packet_type": "dedup_m2", "x_record_id": x.get("record_id", ""), "x_contract": x.get("invariant_test_contract", {}),
              "y_ghsa_id": h1.get("ghsa_id", ""), "y_claim_id": args.claim_id, "y_typed_literals": claim.get("literals", {})}
    dump(args.out, packet)
    return {"status": "COMPLETE", "packet": args.out}


def command_m4_packet(args: argparse.Namespace) -> dict[str, Any]:
    x, h1, m1 = load(args.x_finding), load(args.y_h1), load(args.m1)
    claim = claim_by_id(h1, args.claim_id)
    m3 = [load(path) for path in args.m3]
    packet = {"packet_type": "dedup_m4",
              "proposition": "Y's claim shares X's root cause and is resolved by X's fix.",
              "pair": {"canonical_record_id": x.get("record_id", ""), "other_record_id": f"{h1.get('ghsa_id', '')}:{args.claim_id}",
                       "canonical_ghsa_id": x.get("ghsa_id", ""), "other_ghsa_id": h1.get("ghsa_id", ""), "other_claim_id": args.claim_id},
              "x_code_derived_records": code_derived(x),
              "y_claim_quotes": {"statement_quote": claim.get("statement_quote", ""), "entry_point_quote": claim.get("entry_point_quote", "")},
              "m1_result": {"result": m1.get("result"), "unmatched": m1.get("unmatched", {})},
              "m3_results": [{key: item.get(key) for key in ("target_revision", "frozen_test_id", "literal_check_result", "exit_status", "status")} for item in m3]}
    dump(args.out, packet)
    return {"status": "COMPLETE", "packet": args.out}


# ---------- M1 ----------

def command_m1(args: argparse.Namespace) -> dict[str, Any]:
    x, h1, check = load(args.x_finding), load(args.y_h1), load(args.y_h1_check)
    if check.get("effective_status") != "COMPLETE":
        raise UsageError("Y's H1 output has not passed intake-check")
    eligible = []
    if x.get("final_status") != "CROSS-MODEL VERIFIED":
        eligible.append("canonical finding is not CROSS-MODEL VERIFIED")
    if not x.get("contract_accepted"):
        eligible.append("canonical finding has no accepted contract")
    if not x.get("fix_revision"):
        eligible.append("canonical finding has no fix revision")
    if x.get("fallback_model") and not x.get("fallback_use_permitted"):
        eligible.append("canonical finding came from a fallback model without permission for this use")
    clusters = load(args.clusters).get("clusters", [])
    if not any(x.get("ghsa_id") in c["members"] and h1.get("ghsa_id") in c["members"] for c in clusters):
        eligible.append("Y is not in X's D2 cluster")
    location_paths = {loc[2] if isinstance(loc, list) else loc.get("relative_path", "") for loc in x.get("locations", [])}
    haystack = " ".join(str(v) for v in x.get("enumerated_variants", []))
    contract = x.get("invariant_test_contract", {})
    haystack += " " + json.dumps(contract.get("adversarial_input_classes", contract), ensure_ascii=False)
    unmatched: dict[str, list[str]] = {}
    control_site_failure = False
    for claim in h1.get("claims", []):
        for kind, values in claim.get("literals", {}).items():
            if kind == "advisory_references":
                continue
            for value in values:
                if kind == "file_paths":
                    matched = any(path == value or path.endswith("/" + value) or value.endswith("/" + path) for path in location_paths if path)
                    matched = matched or value in haystack
                else:
                    matched = value in haystack or any(value in path for path in location_paths)
                if not matched:
                    unmatched.setdefault(kind, []).append(value)
                    if kind == "file_paths":
                        control_site_failure = True
    result = "FAILED" if eligible or control_site_failure else "PASSED"
    out = {"record_type": "ghsa_membership_m1", "x_record_id": x.get("record_id", ""), "y_ghsa_id": h1.get("ghsa_id", ""),
           "result": result, "ineligible_reasons": eligible, "control_site_unmatched": control_site_failure,
           "unmatched": {k: sorted(set(v)) for k, v in unmatched.items()}}
    dump(args.out, out)
    return {"status": "COMPLETE", "result": result}


# ---------- routing and relation records ----------

def pair_matches(data: dict[str, Any], args: argparse.Namespace, *, membership: bool = False) -> bool:
    """The artifact must answer exactly the requested pair; M4's other record is a claim reference."""
    raw = data.get("pair")
    pair: dict[str, Any] = raw if isinstance(raw, dict) else {}
    expected = {"canonical_record_id": args.canonical_record, "canonical_ghsa_id": args.canonical_ghsa,
                "other_ghsa_id": args.other_ghsa, "other_claim_id": args.other_claim}
    if not membership:
        expected["other_record_id"] = args.other_record
    return all(pair.get(key) == value for key, value in expected.items())


def d4_record(path: str, args: argparse.Namespace) -> tuple[str, dict[str, Any]]:
    data = load(path)
    if not pair_matches(data, args):
        return "NON_COMPLETE", data
    status = data.get("status")
    if data.get("declined_scope"):
        status = "REFUSED"
    verdict = data.get("verdict")
    if status != "COMPLETE" or verdict not in D4_RELATIONS:
        return "NON_COMPLETE", data
    return verdict, data


def d5_result(base_path: str | None, fix_path: str | None) -> str:
    """Map two computation results to PASSED, FAILED, or NONE.

    The base entry's frozen oracle expects the failing exit status, so its literal result
    PASSED means the test failed as expected on base. The fix entry expects success.
    PASSED: failed as expected on base and passed on the fix. FAILED: failed as expected on
    base and still fails on the fix. Anything else is no result. The two results must be
    frozen-test runs of the same proposition from the same registry on two different
    revisions; otherwise there is no result.
    """
    if not base_path or not fix_path:
        return "NONE"
    items = [load(path) for path in (base_path, fix_path)]
    for item in items:
        if item.get("status") != "COMPLETE" or item.get("literal_check_result") not in ("PASSED", "FAILED"):
            return "NONE"
        if item.get("check_kind") != "FROZEN_TEST_REFERENCE":
            return "NONE"
    base, fix = items
    if (not base.get("target_revision") or base.get("target_revision") == fix.get("target_revision")
            or base.get("proposition") != fix.get("proposition") or not base.get("proposition")
            or base.get("registry_sha256") != fix.get("registry_sha256") or not base.get("registry_sha256")):
        return "NONE"
    if base["literal_check_result"] != "PASSED":
        return "NONE"
    return "PASSED" if fix["literal_check_result"] == "PASSED" else "FAILED"

def route_d4_relation(native: str, cross: str, d5: str) -> str | None:
    if "NON_COMPLETE" in (native, cross):
        return None
    if native == cross:
        if native == "SAME_ROOT_CAUSE":
            return "UNRESOLVED" if d5 == "FAILED" else "SAME_ROOT_CAUSE"
        return native
    return {"PASSED": "SAME_ROOT_CAUSE", "FAILED": "VARIANT"}.get(d5, "UNRESOLVED")


def relation_record(args: argparse.Namespace, relation: str, basis: str, **fields: Any) -> dict[str, Any]:
    deps = load(args.depends_on) if getattr(args, "depends_on", None) else {}
    record = {
        "record_type": "dedup_relation", "schema_version": "1", "adapter": ADAPTER_NAME, "adapter_version": ADAPTER_VERSION,
        "created_at_utc": utc_now(),
        "canonical": {"ghsa_id": args.canonical_ghsa, "claim_id": args.canonical_claim, "record_id": args.canonical_record},
        "other": {"ghsa_id": args.other_ghsa, "claim_id": args.other_claim, "record_id": args.other_record},
        "relation": relation, "basis": basis, "proposed": relation not in ("RELATED", "DISTINCT"),
        "d4_verdicts": fields.get("d4_verdicts", []), "d5_result": fields.get("d5", "NONE"),
        "membership": fields.get("membership", {"m1": "NOT_RUN", "m3": "NOT_RUN", "m4": []}),
        "canonical_choice": {"rule": "HUMAN_OVERRIDE" if args.override_reason else "EARLIEST_RECEIVED", "override_reason": args.override_reason or ""},
        "human_decision": {"decision": "PENDING", "relation_after": "", "recorded_at_utc": ""},
        "depends_on": {
            "canonical_body_sha256": deps.get("canonical_body_sha256", ""), "other_body_sha256": deps.get("other_body_sha256", ""),
            "canonical_updated_at": deps.get("canonical_updated_at", ""), "other_updated_at": deps.get("other_updated_at", ""),
            "canonical_claims_sha256": deps.get("canonical_claims_sha256", ""), "other_claims_sha256": deps.get("other_claims_sha256", ""),
            "canonical_finding_sha256": deps.get("canonical_finding_sha256", ""), "fix_revision": deps.get("fix_revision", ""),
            "artifact_sha256s": sorted(fields.get("artifacts", [])),
        },
        "invalidated": {"is_invalidated": False, "reasons": []},
    }
    identity = {k: record[k] for k in ("canonical", "other", "relation", "basis", "depends_on")}
    record["relation_id"] = "REL-" + digest(identity)[:20]
    return record


def distinct_providers(first: str, second: str) -> bool:
    return bool(first.strip()) and bool(second.strip()) and first.strip().lower() != second.strip().lower()


def command_route_d4(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    if not distinct_providers(args.native_provider, args.cross_provider):
        return {"status": "COMPLETE", "routing": "FULL_ANALYSIS",
                "reason": "D4 legs are not from two different providers (runtime metadata); no relation recorded"}, EXIT_ROUTED_ELSEWHERE
    native, native_data = d4_record(args.d4_native, args)
    cross, cross_data = d4_record(args.d4_cross, args)
    d5 = d5_result(args.d5_base, args.d5_fix)
    relation = route_d4_relation(native, cross, d5)
    if relation is None:
        return {"status": "COMPLETE", "routing": "FULL_ANALYSIS", "reason": "a D4 leg is non-complete; no relation recorded"}, EXIT_ROUTED_ELSEWHERE
    verdicts = [{"provider": provider, "model": model, "verdict": v, "artifact_sha256": digest(Path(p).read_bytes())}
                for v, p, provider, model in ((native, args.d4_native, args.native_provider, args.native_model),
                                              (cross, args.d4_cross, args.cross_provider, args.cross_model))]
    basis = "D4" if native == cross else "D5" if d5 != "NONE" else "D4"
    artifacts = [v["artifact_sha256"] for v in verdicts] + [digest(Path(p).read_bytes()) for p in (args.d5_base, args.d5_fix) if p]
    record = relation_record(args, relation, basis, d4_verdicts=verdicts, d5=d5, artifacts=artifacts)
    dump(args.out, record)
    return {"status": "COMPLETE", "routing": "RELATION", "relation": relation, "relation_id": record["relation_id"]}, EXIT_OK


def command_route_m(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    m1_data = load(args.m1)
    m1_matches = m1_data.get("x_record_id") == args.canonical_record and m1_data.get("y_ghsa_id") == args.other_ghsa
    m1 = m1_data.get("result") if m1_matches else "NOT_RUN"
    m3 = d5_result(args.m3_base, args.m3_fix)
    providers = args.m4_provider or []
    if len(args.m4) != 2 or len(providers) != 2 or not distinct_providers(providers[0], providers[1]):
        return {"status": "COMPLETE", "routing": "FULL_ANALYSIS",
                "reason": "M4 needs exactly two results from two different providers (runtime metadata)"}, EXIT_ROUTED_ELSEWHERE
    m4 = []
    for path in args.m4:
        data = load(path)
        ok = data.get("status") == "COMPLETE" and not data.get("declined_scope") and pair_matches(data, args, membership=True)
        m4.append(data.get("verification_result") if ok else "NON_COMPLETE")
    covered = m1 == "PASSED" and m3 == "PASSED" and len(m4) == 2 and all(v == "CONFIRMED" for v in m4)
    membership = {"m1": m1 if m1 in ("PASSED", "FAILED") else "NOT_RUN", "m3": m3 if m3 in ("PASSED", "FAILED") else "NOT_RUN", "m4": m4}
    if not covered:
        return {"status": "COMPLETE", "routing": "FULL_ANALYSIS", "membership": membership}, EXIT_ROUTED_ELSEWHERE
    artifacts = [digest(Path(p).read_bytes()) for p in [args.m1, args.m3_base, args.m3_fix, *args.m4] if p]
    record = relation_record(args, "SAME_ROOT_CAUSE", "MEMBERSHIP", membership=membership, d5=m3, artifacts=artifacts)
    dump(args.out, record)
    return {"status": "COMPLETE", "routing": "RELATION_PENDING_HUMAN", "relation": "SAME_ROOT_CAUSE", "relation_id": record["relation_id"]}, EXIT_OK


def command_invalidate(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    relation, current = load(args.relation), load(args.current)
    reasons = []
    for key, recorded in relation["depends_on"].items():
        if key == "artifact_sha256s":
            superseded = sorted(set(recorded) & set(current.get("superseded_artifact_sha256s", [])))
            if superseded:
                reasons.append("a dependent artifact was superseded by a stage retry")
            continue
        if recorded and key in current and current[key] != recorded:
            reasons.append(f"{key} changed")
    if current.get("canonical_final_status") not in (None, "CROSS-MODEL VERIFIED") and relation.get("basis") == "MEMBERSHIP":
        reasons.append("canonical final status changed")
    previous = relation.get("invalidated", {}) if isinstance(relation.get("invalidated"), dict) else {}
    kept = [reason for reason in previous.get("reasons", []) if reason not in reasons]
    # An invalidated relation stays invalidated until regenerated from fresh artifacts.
    relation["invalidated"] = {"is_invalidated": bool(previous.get("is_invalidated")) or bool(reasons), "reasons": kept + reasons}
    dump(args.out or args.relation, relation)
    return {"status": "COMPLETE", "invalidated": relation["invalidated"]["is_invalidated"], "reasons": relation["invalidated"]["reasons"]}, EXIT_OK


def command_relate(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    """Record a D0 SAME_TEXT proposal or a relation a human set at D6 (RELATED, VARIANT, DISTINCT, SAME_TEXT)."""
    if args.basis == "D0" and args.relation != "SAME_TEXT":
        raise UsageError("D0 can only propose SAME_TEXT")
    if args.basis == "D0":
        pairs = load(args.clusters).get("pairs", [])
        if not any(p["canonical"] == args.canonical_ghsa and p["other"] == args.other_ghsa and p.get("same_text_proposed") for p in pairs):
            raise UsageError("the cluster output does not propose SAME_TEXT for this pair")
    record = relation_record(args, args.relation, args.basis)
    if args.basis == "HUMAN":
        record["proposed"] = False
        record["human_decision"] = {"decision": "CONFIRMED", "relation_after": args.relation, "recorded_at_utc": utc_now()}
    dump(args.out, record)
    return {"status": "COMPLETE", "relation": args.relation, "basis": args.basis, "relation_id": record["relation_id"]}, EXIT_OK


def command_human(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    """Record the D6 human decision on an existing relation without rewriting its basis or evidence."""
    relation = load(args.relation)
    if relation.get("invalidated", {}).get("is_invalidated"):
        raise UsageError("relation is invalidated; re-run the affected stage first")
    after = args.relation_after or relation["relation"]
    relation["human_decision"] = {"decision": "CONFIRMED" if after == relation["relation"] else "CHANGED",
                                  "relation_after": after, "recorded_at_utc": utc_now()}
    if args.override_reason:
        relation["canonical_choice"] = {"rule": "HUMAN_OVERRIDE", "override_reason": args.override_reason}
    dump(args.out or args.relation, relation)
    return {"status": "COMPLETE", "decision": relation["human_decision"]["decision"], "relation_after": after}, EXIT_OK


def add_pair_arguments(parser: argparse.ArgumentParser) -> None:
    for name in ("canonical-ghsa", "canonical-claim", "canonical-record", "other-ghsa", "other-claim", "other-record"):
        parser.add_argument(f"--{name}", required=True)
    parser.add_argument("--override-reason", default="")
    parser.add_argument("--depends-on", help="JSON of dependency digests for invalidation")
    parser.add_argument("--out", required=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or ADAPTER_NAME).splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("index"); p.add_argument("--entries", required=True); p.add_argument("--out", required=True)
    p = sub.add_parser("cluster"); p.add_argument("--index", required=True); p.add_argument("--out", required=True)
    p = sub.add_parser("reanchor"); p.add_argument("--anchors", required=True); p.add_argument("--checkout", required=True)
    p.add_argument("--revision", required=True); p.add_argument("--out", required=True)
    p = sub.add_parser("d4-packet"); p.add_argument("--x-finding", required=True); p.add_argument("--y-finding", required=True)
    p.add_argument("--claim-id", required=True); p.add_argument("--anchors"); p.add_argument("--out", required=True)
    p = sub.add_parser("m1"); p.add_argument("--x-finding", required=True); p.add_argument("--y-h1", required=True)
    p.add_argument("--y-h1-check", required=True); p.add_argument("--clusters", required=True); p.add_argument("--out", required=True)
    p = sub.add_parser("m2-packet"); p.add_argument("--x-finding", required=True); p.add_argument("--y-h1", required=True)
    p.add_argument("--y-h1-check", required=True); p.add_argument("--claim-id", required=True); p.add_argument("--out", required=True)
    p = sub.add_parser("m4-packet"); p.add_argument("--x-finding", required=True); p.add_argument("--y-h1", required=True)
    p.add_argument("--claim-id", required=True); p.add_argument("--m1", required=True); p.add_argument("--m3", action="append", default=[])
    p.add_argument("--out", required=True)
    p = sub.add_parser("route-d4"); p.add_argument("--d4-native", required=True); p.add_argument("--d4-cross", required=True)
    p.add_argument("--d5-base", help="computation result on base plus Y's test"); p.add_argument("--d5-fix", help="computation result on X's fix plus Y's test")
    for leg in ("native", "cross"):
        p.add_argument(f"--{leg}-provider", required=True, help="provider from runtime metadata, not role output")
        p.add_argument(f"--{leg}-model", required=True, help="actual model from runtime metadata")
    add_pair_arguments(p)
    p = sub.add_parser("route-m"); p.add_argument("--m1", required=True); p.add_argument("--m3-base"); p.add_argument("--m3-fix")
    p.add_argument("--m4", action="append", required=True)
    p.add_argument("--m4-provider", action="append", help="provider for each --m4, in order, from runtime metadata"); add_pair_arguments(p)
    relations = ["SAME_TEXT", "SAME_ROOT_CAUSE", "VARIANT", "RELATED", "DISTINCT", "UNRESOLVED"]
    p = sub.add_parser("relate"); p.add_argument("--relation", required=True, choices=["SAME_TEXT", "VARIANT", "RELATED", "DISTINCT"])
    p.add_argument("--basis", required=True, choices=["D0", "HUMAN"]); p.add_argument("--clusters"); add_pair_arguments(p)
    p = sub.add_parser("human"); p.add_argument("--relation", required=True); p.add_argument("--relation-after", choices=relations)
    p.add_argument("--override-reason", default=""); p.add_argument("--out")
    p = sub.add_parser("invalidate"); p.add_argument("--relation", required=True); p.add_argument("--current", required=True)
    p.add_argument("--out")
    args = parser.parse_args()
    simple = {"index": command_index, "cluster": command_cluster, "reanchor": command_reanchor, "d4-packet": command_d4_packet,
              "m1": command_m1, "m2-packet": command_m2_packet, "m4-packet": command_m4_packet}
    routed = {"route-d4": command_route_d4, "route-m": command_route_m, "invalidate": command_invalidate,
              "relate": command_relate, "human": command_human}
    try:
        if args.command in simple:
            outcome, code = simple[args.command](args), EXIT_OK
        else:
            outcome, code = routed[args.command](args)
    except (UsageError, KeyError, TypeError, IndexError) as error:
        print(json.dumps({"status": "USAGE_ERROR", "error": str(error)}), file=sys.stderr)
        return EXIT_USAGE
    outcome.update({"adapter": ADAPTER_NAME, "adapter_version": ADAPTER_VERSION})
    print(json.dumps(outcome, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
