#!/usr/bin/env python3
"""Deterministic GHSA deduplication steps for security-vuln-analyzer.

Subcommands:
  records      report records from verified analysis artifacts, keyed to the analyzed issue IDs (ghsa_eligible marks records that may back write-back)
  compare-plan step 1a: earlier advisories to compare a report with, by state, from a queue listing and captures
  dispositions step 1a: per-issue COVERED / NEW / UNRESOLVED / IGNORED, the report verdict, and what analysis receives
  confirm      record the human decision on an obvious-duplicate proposal, bound to its decision digest
  brief        render the batched step 1a decision brief: both providers' reasons per referenced pair, never stale

The script never weighs evidence, merges findings, or changes a finding's status.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import unicodedata
from typing import Any

ADAPTER_NAME = "security-vuln-analyzer-ghsa-dedup"
ADAPTER_VERSION = "1.0.0"
VERIFIED = "CROSS-MODEL VERIFIED"
ASCII_SPACE = " \t\n\x0b\x0c\r"
EXIT_OK = 0
EXIT_USAGE = 2


class UsageError(ValueError):
    pass


def load(path: str | Path) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise UsageError(f"cannot read JSON {path}: {error}") from error


def dump(path: str | Path, value: Any) -> None:
    text = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        os.fchmod(handle.fileno(), 0o600)  # O_CREAT's mode applies only to a new file
        handle.write(text)


def write_text_private(path: Path, text: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        os.fchmod(handle.fileno(), 0o600)
        handle.write(text)


def digest(value: Any) -> str:
    data = value if isinstance(value, bytes) else json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# ---------- records (analysis output to GHSA records) ----------

def bundle_text(text: str) -> str:
    """Normalization from orchestrator-contract.md: NFC, LF line endings, ASCII whitespace trimmed and collapsed."""
    text = unicodedata.normalize("NFC", text).replace("\r\n", "\n").replace("\r", "\n").strip(ASCII_SPACE)
    return re.sub("[" + re.escape(ASCII_SPACE) + "]+", " ", text)


def candidate_id(item: dict[str, Any], primary_revision: str) -> str:
    """Recompute the bundle ID exactly as orchestrator-contract.md specifies; never trust a supplied one."""
    locations = sorted(([loc["repository"], loc["revision"], loc["relative_path"], loc["start_line"], loc["end_line"]] for loc in item["locations"]),
                       key=lambda value: json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    body = {"primary_revision": primary_revision, "locations": locations,
            "primitive_class": bundle_text(item["primitive_class"]), "variant_family": bundle_text(item["variant_family"]),
            "proposition": bundle_text(item["normalized_proposition"])}
    data = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "SVA-" + hashlib.sha256(data).hexdigest()[:20]


# FIRST v4.0 Table 23 grammar, copied from the repository's acceptance runner
# (`security_cvss_v4_vector_is_complete`) and scripts/cvss4-score.py: base metrics required
# in order, every optional metric at most once and in order.
CVSS_V4_BASE_GRAMMAR = (
    ("AV", "[NALP]"), ("AC", "[LH]"), ("AT", "[NP]"), ("PR", "[NLH]"),
    ("UI", "[NPA]"), ("VC", "[HLN]"), ("VI", "[HLN]"), ("VA", "[HLN]"),
    ("SC", "[HLN]"), ("SI", "[HLN]"), ("SA", "[HLN]"),
)
CVSS_V4_OPTIONAL_GRAMMAR = (
    ("E", "[XAPU]"), ("CR", "[XHML]"), ("IR", "[XHML]"), ("AR", "[XHML]"),
    ("MAV", "[XNALP]"), ("MAC", "[XLH]"), ("MAT", "[XNP]"), ("MPR", "[XNLH]"),
    ("MUI", "[XNPA]"), ("MVC", "[XNLH]"), ("MVI", "[XNLH]"), ("MVA", "[XNLH]"),
    ("MSC", "[XNLH]"), ("MSI", "[XNLHS]"), ("MSA", "[XNLHS]"),
    ("S", "[XNP]"), ("AU", "[XNY]"), ("R", "[XAUI]"), ("V", "[XDC]"),
    ("RE", "[XLMH]"), ("U", "(?:X|Clear|Green|Amber|Red)"),
)
CVSS_V4_PATTERN = re.compile(
    r"CVSS:4\.0" + "".join(f"/{name}:{values}" for name, values in CVSS_V4_BASE_GRAMMAR)
    + "".join(f"(?:/{name}:{values})?" for name, values in CVSS_V4_OPTIONAL_GRAMMAR)
)


def cvss_v4_vector_is_complete(vector: Any) -> bool:
    """Literal grammar check only; it never calculates a score or fills in a metric."""
    return isinstance(vector, str) and CVSS_V4_PATTERN.fullmatch(vector) is not None


def stage2_confirms(entry: dict[str, Any], cid: str) -> bool:
    """True when both Stage 2 legs CONFIRMED; False for a complete split. Anything inconsistent is a usage error."""
    legs = entry.get("stage2")
    if not isinstance(legs, list) or len(legs) != 2:
        raise UsageError(f"{cid}: a verified status needs exactly two Stage 2 artifacts")
    if not distinct_providers(str(legs[0].get("provider", "")), str(legs[1].get("provider", ""))):
        raise UsageError(f"{cid}: Stage 2 legs are not from two different providers")
    if Path(legs[0]["path"]).resolve() == Path(legs[1]["path"]).resolve():
        raise UsageError(f"{cid}: both Stage 2 legs name the same artifact")
    results = []
    for leg in legs:
        data = load(leg["path"])
        if data.get("candidate_id") != cid or data.get("status") != "COMPLETE" or data.get("declined_scope"):
            raise UsageError(f"{cid}: a Stage 2 artifact is for another candidate, non-complete, or refused")
        results.append(data.get("verification_result"))
    return results == ["CONFIRMED", "CONFIRMED"]


def canonical_cvss_v4(vector: str) -> str:
    """Drop optional metrics whose value is X (Not Defined), so an explicit `E:X` and an omitted `E` are one vector."""
    optional = {name for name, _ in CVSS_V4_OPTIONAL_GRAMMAR}
    parts = vector.split("/")
    return "/".join([parts[0]] + [part for part in parts[1:] if not (part.split(":", 1)[0] in optional and part.endswith(":X"))])


def command_records(args: argparse.Namespace) -> dict[str, Any]:
    issues_doc, dispositions = load(args.issues), load(args.dispositions)
    if issues_doc.get("record_type") != "ghsa_issue_list" or issues_doc.get("ghsa_id") != args.ghsa_id:
        raise UsageError("the issue list belongs to a different advisory")
    if dispositions.get("record_type") != "ghsa_dispositions" or dispositions.get("ghsa_id") != args.ghsa_id:
        raise UsageError("the dispositions belong to a different advisory")
    if dispositions.get("depends_on", {}).get("issues_sha256") != file_sha256(args.issues):
        raise UsageError("the dispositions were computed from a different issue list")
    if dispositions.get("analysis_status") == "NO_ANALYSIS":
        raise UsageError("confirmed duplicate: nothing was analyzed, so there are no records to bridge")
    if dispositions.get("analysis_status") != "READY":
        raise UsageError("the report is awaiting confirmation of an obvious-duplicate proposal; nothing was analyzed")
    analysis_issues = list(dispositions.get("analysis_issue_ids", []))
    manifest = load(args.verification).get("candidates", {})
    role_records: list[tuple[str, str, dict[str, Any]]] = []
    for path in args.discovery:
        artifact = load(path)
        artifact_digest = digest(artifact)  # role-local IDs are artifact-scoped, so identity includes the artifact
        if artifact.get("role_type") != "discovery" or artifact.get("status") != "COMPLETE" or artifact.get("declined_scope"):
            raise UsageError(f"{path} is not a complete, unrefused discovery artifact")
        for item in artifact.get("candidates", []):
            unknown = sorted(set(item["issue_ids"]) - set(analysis_issues))
            if unknown:
                raise UsageError(f"a candidate names issue IDs that analysis did not receive: {unknown}")
            role_records.append((candidate_id(item, args.primary_revision), artifact_digest, item))
    recomputed = {cid for cid, _, _ in role_records}
    if set(manifest) - recomputed:
        raise UsageError("the verification manifest names candidate IDs that the discovery artifacts do not produce")
    for cid in recomputed - set(manifest):
        if any(item["affects_security_claim"] for other, _, item in role_records if other == cid):
            raise UsageError(f"{cid} affects a security claim but has no verification entry")
    records, not_bridged, unassigned = [], [], []
    answered: set[str] = set()
    seen: set[str] = set()
    for cid, artifact_digest, item in sorted(role_records, key=lambda entry: (entry[0], entry[1], digest(entry[2]))):
        record_id = f"{cid}:{digest([artifact_digest, digest(item)])[:8]}"
        if record_id in seen:
            raise UsageError(f"duplicate record {record_id} (the same discovery artifact was supplied twice)")
        seen.add(record_id)
        entry = manifest.get(cid)
        status = entry.get("final_status", "") if entry else ""
        bridged = False
        if entry is None:
            not_bridged.append({"record_id": record_id, "reason": "not routed to verification"})
        elif status == VERIFIED:
            bridged = stage2_confirms(entry, cid)
            if not bridged:
                not_bridged.append({"record_id": record_id, "reason": "verified status is not backed by two CONFIRMED Stage 2 results "
                                    "(for example a split resolved by a frozen test); not bridged in this version"})
        else:
            not_bridged.append({"record_id": record_id, "reason": f"final status {status or '(missing)'}"})
        values: dict[str, Any] = {}
        if bridged:
            cvss = item.get("scoring", {}).get("cvss_v4", {})
            # Roles record NOT SCORED with the complete vector they chose; GitHub derives severity from the vector.
            if cvss.get("status") in ("SCORED", "NOT SCORED") and cvss_v4_vector_is_complete(cvss.get("vector")):
                values["cvss_vector_string"] = canonical_cvss_v4(cvss["vector"])
            if item.get("cwe_ids"):
                values["cwe_ids"] = sorted(set(item["cwe_ids"]))
        issue_ids = [issue_id for issue_id in analysis_issues if issue_id in set(item["issue_ids"])]
        records.append({
            "record_id": record_id, "kind": "finding", "repository": args.repository, "candidate_id": cid,
            "role_local_id": item.get("role_local_id", ""),
            "answers": [{"ghsa_id": args.ghsa_id, "issue_id": issue_id} for issue_id in issue_ids],
            "final_status": status, "ghsa_eligible": bridged,
            "fallback_model": bool(entry and entry.get("fallback_model")),
            "fallback_use_permitted": bool(entry and entry.get("fallback_use_permitted")),
            "normalized_proposition": item["normalized_proposition"], "proposed_disposition": item["proposed_disposition"],
            "values": values,
        })
        if bridged:
            answered.update(issue_ids)
            if not issue_ids:
                unassigned.append(record_id)
    out = restricted_dir(Path(args.out_dir))
    dump(out / "report-records.json", {"repository": args.repository, "ghsa_id": args.ghsa_id, "records": records})
    return {"status": "COMPLETE", "records": len(records), "bridged": len(records) - len(not_bridged),
            "issues_without_records": [issue_id for issue_id in analysis_issues if issue_id not in answered],
            "unassigned": unassigned, "not_bridged": not_bridged}


def distinct_providers(first: str, second: str) -> bool:
    return bool(first.strip()) and bool(second.strip()) and first.strip().lower() != second.strip().lower()


# ---------- step 1a: comparison plan, dispositions, confirmation ----------

OPEN_STATES = ("triage", "draft")
NON_TECHNICAL = ("DOCUMENTATION_UI", "FIX_GUIDANCE")


def restricted_dir(path: Path) -> Path:
    """Create every missing level with mode 700, not only the leaf (mkdir(parents=True) uses the umask)."""
    missing = []
    current = path
    while not current.exists():
        missing.append(current)
        current = current.parent
    for directory in reversed(missing):
        directory.mkdir(mode=0o700, exist_ok=True)
        os.chmod(directory, 0o700)
    os.chmod(path, 0o700)
    return path


def step1a_root(path: Path, ghsa_id: str, direct: bool = False) -> Path:
    """Step 1a outputs live in <run>/step1a/ of the advisory's own run, where queue selection looks for them.

    With `direct`, `path` is the output's directory and must be that step1a/ directory itself, not a level below it."""
    resolved = Path(path).resolve()
    root = next((p for p in (resolved, *resolved.parents) if p.name == "step1a"), None)
    record = None if root is None else root.parent / "intake" / "intake-record.json"
    if root is None or record is None or not record.is_file() or load(record).get("advisory", {}).get("ghsa_id") != ghsa_id \
            or (direct and resolved != root):
        raise UsageError(f"step 1a outputs for {ghsa_id} belong directly in <run>/step1a/ of a run directory whose "
                         "intake/intake-record.json captures that advisory")
    return root


def dump_private(path: str | Path, value: Any) -> None:
    restricted_dir(Path(path).parent)
    dump(path, value)


def file_sha256(path: str | Path) -> str:
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError as error:
        raise UsageError(f"cannot read {path}: {error}") from error


def rendered_sha256(intake: dict[str, Any]) -> str:
    """SHA-256 of the advisory as intake-check.py renders it into packets (same fields, labels, and newline handling)."""
    advisory = intake.get("advisory", {})
    fields: list[tuple[str, Any]] = [("summary", advisory.get("summary", "")), ("description", advisory.get("description", ""))]
    for index, comment in enumerate(advisory.get("comments", []), 1):
        if isinstance(comment, dict):
            fields.append((f"comment {index}", comment.get("body", "")))
    for index, vulnerability in enumerate(advisory.get("reporter_claims", {}).get("vulnerabilities", []), 1):
        if isinstance(vulnerability, dict):
            for key in ("package", "vulnerable_version_range", "patched_versions"):
                fields.append((f"vulnerability {index} {key}", vulnerability.get(key, "")))
            for number, function in enumerate(vulnerability.get("vulnerable_functions", []) or [], 1):
                fields.append((f"vulnerability {index} vulnerable_function {number}", function))
    text = "".join(f"<<<FIELD {label}>>>\n{value.replace(chr(13) + chr(10), chr(10)).replace(chr(13), chr(10))}\n<<<END {label}>>>\n"
                   for label, value in fields if isinstance(value, str) and value)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def order_key(entry: dict[str, Any]) -> tuple[str, str]:
    return (str(entry.get("created_at", "")), str(entry.get("ghsa_id", "")))


def command_compare_plan(args: argparse.Namespace) -> dict[str, Any]:
    step1a_root(Path(args.out).parent, args.ghsa_id, direct=True)
    listing = load(args.listing)
    captures = load(args.captures)
    missing_states = sorted({"triage", "draft", "published", "closed"} - set(listing.get("states", [])))
    if missing_states:
        raise UsageError(f"the queue listing omits states {missing_states}; rerun ghsa-fetch.py queue --state all")
    entries = {entry["ghsa_id"]: entry for entry in listing.get("advisories", [])}
    later = entries.get(args.ghsa_id)
    if later is None:
        raise UsageError(f"{args.ghsa_id} is not in the queue listing")
    if later.get("state") not in OPEN_STATES:
        raise UsageError(f"{args.ghsa_id} is {later.get('state')!r}; step 1a runs only for triage or draft advisories")
    planned, excluded, missing, stale = [], [], [], []
    for entry in sorted(entries.values(), key=order_key):
        ghsa_id = entry["ghsa_id"]
        if ghsa_id == args.ghsa_id:
            excluded.append({"ghsa_id": ghsa_id, "reason": "the report itself"})
            continue
        if order_key(entry) > order_key(later):
            excluded.append({"ghsa_id": ghsa_id, "reason": "created later"})
            continue
        state = entry.get("state")
        if state not in (*OPEN_STATES, "published", "closed"):
            excluded.append({"ghsa_id": ghsa_id, "reason": f"state {state}"})
            continue
        path = captures.get(ghsa_id)
        if not path:
            missing.append(ghsa_id)
            continue
        record = load(path)
        advisory = record.get("advisory", {})
        if advisory.get("ghsa_id") != ghsa_id:
            raise UsageError(f"the capture given for {ghsa_id} is for another advisory")
        if (advisory.get("body_sha256"), advisory.get("updated_at")) != (entry.get("body_sha256"), entry.get("updated_at")):
            stale.append(ghsa_id)
            continue
        if state in OPEN_STATES:
            role = "OPEN"
        elif state == "published":
            role = "PUBLISHED"
        else:
            raw = record.get("raw", {})
            if raw.get("comments_count_field") == 0 and raw.get("comments_status") == "CAPTURED":
                excluded.append({"ghsa_id": ghsa_id, "reason": "closed without comments"})
                continue
            role = "CLOSED_WITH_COMMENTS"
        planned.append({"ghsa_id": ghsa_id, "role": role, "state": state, "created_at": entry.get("created_at", ""), "intake": str(path)})
    if missing:
        raise UsageError(f"capture these earlier advisories first: {missing}")
    if stale:
        raise UsageError(f"recapture these advisories; their captures differ from the listing: {stale}")
    plan = {"record_type": "ghsa_compare_plan", "repository": listing.get("repository", ""), "later_ghsa_id": args.ghsa_id,
            "later_created_at": later.get("created_at", ""), "planned": planned, "excluded": excluded,
            "comparison_count": len(planned), "listing_sha256": file_sha256(args.listing)}
    dump_private(args.out, plan)
    return {"status": "COMPLETE", "comparison_count": len(planned),
            "roles": {role: sum(entry["role"] == role for entry in planned) for role in ("OPEN", "PUBLISHED", "CLOSED_WITH_COMMENTS")}}


def usable_leg(check: dict[str, Any] | None) -> bool:
    return bool(check) and check.get("effective_status") == "COMPLETE" and (  # type: ignore[union-attr]
        not check.get("fallback_model") or bool(check.get("fallback_use_permitted")))  # type: ignore[union-attr]


def load_pair(directory: Path, earlier: str, later: str, expected: list[str], issues_sha: str) -> tuple[dict[str, Any], dict[str, Any] | None, dict[str, Any] | None]:
    meta_path = directory / "compare.meta.json"
    native_path, cross_path = directory / "native.check.json", directory / "cross.check.json"
    if not meta_path.exists() or not native_path.exists():
        raise UsageError(f"{earlier}: no comparison packet or native check; run the native leg (a failed leg still writes its check)")
    meta = load(meta_path)
    checks: list[dict[str, Any] | None] = []
    for leg, path in (("native", native_path), ("cross", cross_path)):
        check = load(path) if path.exists() else None
        if check is not None and (check.get("check") != "compare-check" or check.get("leg") != leg
                                  or check.get("earlier_ghsa_id") != earlier or check.get("later_ghsa_id") != later
                                  or check.get("packet_sha256") != meta.get("packet_sha256")):
            raise UsageError(f"{path} does not answer the planned pair {earlier} -> {later}")
        checks.append(check)
    if meta.get("earlier_ghsa_id") != earlier or meta.get("later_ghsa_id") != later or meta.get("issues_sha256") != issues_sha \
            or meta.get("expected_ids") != expected:
        raise UsageError(f"{earlier}: the comparison packet was built for another pair or another issue list; rebuild it")
    return meta, checks[0], checks[1]


def decision_digest(ghsa_id: str, verdict: str, issues: list[dict[str, Any]], issues_sha: str, texts: dict[str, str]) -> str:
    """What the human judged: the verdict, each issue's disposition and canonical, the issue list itself, and each canonical's text."""
    canonicals = sorted({item["canonical"] for item in issues if item["canonical"]})
    return digest({"ghsa_id": ghsa_id, "verdict": verdict, "issues_sha256": issues_sha,
                   "issues": [{key: item[key] for key in ("issue_id", "disposition", "canonical")} for item in issues],
                   "canonical_texts": {ghsa: texts.get(ghsa, "") for ghsa in canonicals}})


def command_dispositions(args: argparse.Namespace) -> dict[str, Any]:
    issues_doc, plan = load(args.issues), load(args.plan)
    if issues_doc.get("record_type") != "ghsa_issue_list" or issues_doc.get("status") != "COMPLETE":
        raise UsageError("the issue list is missing or not complete")
    ghsa_id = issues_doc["ghsa_id"]
    root = step1a_root(Path(args.out).parent, ghsa_id, direct=True)
    if Path(args.compare_dir).resolve() != root / "compare":  # brief reads the checks beside the dispositions file
        raise UsageError("--compare-dir must be the compare/ directory inside the same step1a/ as --out, "
                         "so dispositions and the decision brief read the same comparison checks")
    if plan.get("record_type") != "ghsa_compare_plan" or plan.get("later_ghsa_id") != ghsa_id:
        raise UsageError("the comparison plan is for another report")
    issues_sha = file_sha256(args.issues)
    technical = [item["issue_id"] for item in issues_doc["issues"] if item["technical"]]
    captures = load(args.captures) if args.captures else {}
    compare_dir = Path(args.compare_dir)
    planned = {entry["ghsa_id"]: entry for entry in plan["planned"]}
    excluded = {entry["ghsa_id"] for entry in plan.get("excluded", [])}  # for example closed without comments after a comparison
    if compare_dir.exists():
        unknown = sorted(path.name for path in compare_dir.iterdir() if path.is_dir() and path.name not in planned and path.name not in excluded)
        if unknown:
            raise UsageError(f"comparison directories for advisories outside the plan: {unknown}")
    votes: dict[str, dict[str, Any]] = {}  # earlier GHSA ID -> per-pair state
    rerun_pairs, pair_deps = [], {}
    for earlier, entry in sorted(planned.items(), key=lambda item: order_key(item[1])) if technical else []:  # earliest first
        meta, native, cross = load_pair(compare_dir / earlier, earlier, ghsa_id, technical, issues_sha)
        capture = load(captures.get(earlier, entry["intake"]))
        if capture.get("advisory", {}).get("state") != entry["state"]:
            raise UsageError(f"{earlier} is now {capture.get('advisory', {}).get('state')!r}, not {entry['state']!r} as planned; "
                             "re-list, recapture, and rerun compare-plan")
        current = rendered_sha256(capture)
        native_ok = usable_leg(native)
        cross_ok = usable_leg(cross) and distinct_providers(str(native.get("provider", "")), str(cross.get("provider", ""))) if cross else False  # type: ignore[union-attr]
        n = {i: native["answers"][i]["covered"] for i in technical} if native_ok else {}  # type: ignore[index]
        c = {i: cross["answers"][i]["covered"] for i in technical} if cross_ok else {}  # type: ignore[index]
        stale = current != meta.get("x_rendered_sha256")
        if stale and ("YES" in n.values() or "YES" in c.values()):
            rerun_pairs.append(earlier)
        votes[earlier] = {"role": entry["role"], "native_ok": native_ok, "n": n, "c": c, "stale": stale}
        pair_deps[earlier] = {"x_rendered_sha256": meta.get("x_rendered_sha256", ""), "native_check_sha256": file_sha256(compare_dir / earlier / "native.check.json"),
                              "cross_check_sha256": file_sha256(compare_dir / earlier / "cross.check.json") if cross else ""}
    out_issues, ignored, fix_guidance = [], [], []
    for item in issues_doc["issues"]:
        issue_id, kinds = item["issue_id"], item["kinds"]
        record = {"issue_id": issue_id, "mechanism": item["mechanism"], "technical": item["technical"], "kinds": kinds,
                  "disposition": "IGNORED", "canonical": "", "also_covered_by": [], "unresolved": [],
                  "published_matches": [], "closed_matches": [], "information": []}
        if not item["technical"]:
            ignored.append({"issue_id": issue_id, "kinds": kinds})
            if "FIX_GUIDANCE" in kinds.values():
                fix_guidance.append(issue_id)
            out_issues.append(record)
            continue
        covers = []
        for earlier, state in votes.items():
            n, c = state["n"].get(issue_id), state["c"].get(issue_id)
            any_yes = "YES" in (n, c)
            if state["stale"] and any_yes:
                outcome = "EARLIER_REPORT_CHANGED"
            elif not state["native_ok"]:
                outcome = "COMPARISON_INCOMPLETE"
            elif n == "YES" and c == "YES":
                outcome = "MATCH"
            elif any_yes:
                outcome = "ONE_PROVIDER_YES"
            else:
                continue
            if state["role"] == "OPEN":
                if outcome == "MATCH":
                    covers.append(earlier)
                else:
                    record["unresolved"].append({"earlier_ghsa_id": earlier, "reason": outcome})
            elif outcome == "MATCH":
                record["published_matches" if state["role"] == "PUBLISHED" else "closed_matches"].append(earlier)
            else:
                record["information"].append({"earlier_ghsa_id": earlier, "role": state["role"], "reason": outcome})
        if covers:
            record.update(disposition="COVERED", canonical=covers[0], also_covered_by=covers[1:])
        else:
            record["disposition"] = "UNRESOLVED" if record["unresolved"] else "NEW"
        out_issues.append(record)
    tech = [record for record in out_issues if record["technical"]]
    analysis = [record["issue_id"] for record in tech if record["disposition"] in ("NEW", "UNRESOLVED")]
    if issues_doc.get("cross_leg") != "COMPLETE":
        verdict, analysis = "LIST_UNREVIEWED", [record["issue_id"] for record in tech]
    elif not tech:
        verdict, analysis = "NO_TECHNICAL_ISSUES", [record["issue_id"] for record in out_issues]
    elif all(record["disposition"] == "COVERED" for record in tech):
        verdict = "OBVIOUS_DUPLICATE"
    elif any(record["disposition"] == "COVERED" for record in tech):
        verdict = "PARTIAL"
    else:
        verdict = "NOT_COVERED"
    decision = decision_digest(ghsa_id, verdict, out_issues, issues_sha,
                               {earlier: deps["x_rendered_sha256"] for earlier, deps in pair_deps.items()})
    confirmation = {"applied": False, "stale": False, "decision": "", "reason": "", "recorded_at_utc": ""}
    status = "AWAITING_CONFIRMATION" if verdict == "OBVIOUS_DUPLICATE" else "READY"
    if args.confirmation:
        given = load(args.confirmation)
        if given.get("record_type") != "ghsa_confirmation" or given.get("ghsa_id") != ghsa_id:
            raise UsageError("the confirmation is for another report")
        if given.get("decision") not in ("CONFIRMED", "REJECTED"):
            raise UsageError("a confirmation records CONFIRMED or REJECTED")
        if verdict == "OBVIOUS_DUPLICATE" and given.get("decision_digest") == decision:
            confirmation = {"applied": True, "stale": False, "decision": given["decision"], "reason": given.get("reason", ""),
                            "recorded_at_utc": given.get("recorded_at_utc", "")}
            status = "NO_ANALYSIS" if given["decision"] == "CONFIRMED" else "READY"
            if given["decision"] == "REJECTED":
                analysis = [record["issue_id"] for record in tech]
        else:
            confirmation["stale"] = True
    document = {"record_type": "ghsa_dispositions", "ghsa_id": ghsa_id, "verdict": verdict, "cross_leg": issues_doc.get("cross_leg", ""),
                "analysis_status": status, "analysis_issue_ids": analysis, "issues": out_issues, "ignored": ignored,
                "fix_guidance": fix_guidance, "rerun_pairs": rerun_pairs, "decision_digest": decision, "confirmation": confirmation,
                "depends_on": {"issues_sha256": issues_sha, "plan_sha256": file_sha256(args.plan), "pairs": pair_deps}}
    dump_private(args.out, document)
    return {"status": "COMPLETE", "verdict": verdict, "analysis_status": status, "analysis_issue_ids": analysis, "rerun_pairs": rerun_pairs}


def command_confirm(args: argparse.Namespace) -> dict[str, Any]:
    document = load(args.dispositions)
    if document.get("record_type") != "ghsa_dispositions" or document.get("verdict") != "OBVIOUS_DUPLICATE":
        raise UsageError("only an obvious-duplicate proposal can be confirmed or rejected")
    step1a_root(Path(args.out).parent, document["ghsa_id"], direct=True)
    record = {"record_type": "ghsa_confirmation", "ghsa_id": document["ghsa_id"], "decision_digest": document["decision_digest"],
              "decision": args.decision, "reason": args.reason, "recorded_at_utc": utc_now()}
    dump_private(args.out, record)
    return {"status": "COMPLETE", "decision": args.decision, "decision_digest": document["decision_digest"]}


OWNER_REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def json_escape(char: str) -> str:
    code = ord(char)
    if code > 0xFFFF:  # JSON writes characters outside the BMP as a surrogate pair
        code -= 0x10000
        return "\\u%04x\\u%04x" % (0xD800 + (code >> 10), 0xDC00 + (code & 0x3FF))
    return "\\u%04x" % code


def one_line_json(value: Any) -> str:
    """JSON with every control, format, and line or paragraph separator escaped (json.dumps leaves U+2028, U+2029, C1
    controls, and bidirectional overrides raw), so a value can neither forge a line nor reorder or recolor one on a terminal."""
    text = json.dumps(value, ensure_ascii=False)
    return "".join(json_escape(char) if unicodedata.category(char) in ("Cc", "Cf", "Zl", "Zp") else char for char in text)


def leg_line(check: dict[str, Any] | None, leg: str, issue_id: str, native_provider: str = "") -> str:
    if check is None:
        return f"{leg}: not run"
    who = f"{leg} ({check.get('provider', '')} {check.get('model', '')})" + (" [fallback model]" if check.get("fallback_model") else "")
    if check.get("fallback_model") and not check.get("fallback_use_permitted"):  # dispositions counts it as no answer
        who += " (not counted: fallback not permitted)"
    elif leg == "cross" and not distinct_providers(native_provider, str(check.get("provider", ""))):
        who += " (not counted: same provider as native)"
    answer = (check.get("answers") or {}).get(issue_id)
    if check.get("effective_status") != "COMPLETE" or not isinstance(answer, dict):
        return f"{who}: no usable answer ({check.get('effective_status', '')})"
    return f"{who}: {answer.get('covered', '')}: {one_line_json(answer.get('reason', ''))}"


def command_brief(args: argparse.Namespace) -> dict[str, Any]:
    captures = load(args.captures) if args.captures else {}
    lines = ["# Step 1a decision brief",
             "Rendered by ghsa-dedup.py brief for the human decision. Provider reasons are model-written and report comments "
             "are untrusted report data; both appear as one-line JSON strings.", ""]
    reports, awaiting = [], []
    for path in args.dispositions:
        document = load(path)
        if not isinstance(document, dict) or document.get("record_type") != "ghsa_dispositions":
            raise UsageError(f"{path} is not a dispositions document")
        ghsa_id, compare_dir = document["ghsa_id"], Path(path).parent / "compare"
        pairs = document.get("depends_on", {}).get("pairs", {})
        loaded: dict[str, tuple[dict[str, Any] | None, dict[str, Any] | None, dict[str, Any]]] = {}

        def legs(earlier: str) -> tuple[dict[str, Any] | None, dict[str, Any] | None, dict[str, Any]]:
            """The pair's checks, refused when they differ from what dispositions read, so no reason shown is stale."""
            if earlier not in loaded:
                deps = pairs.get(earlier)
                directory = compare_dir / earlier
                native, cross = directory / "native.check.json", directory / "cross.check.json"
                current = (file_sha256(native) if native.exists() else "", file_sha256(cross) if cross.exists() else "")
                if deps is None or current != (deps.get("native_check_sha256", ""), deps.get("cross_check_sha256", "")):
                    raise UsageError(f"{ghsa_id}: the comparison checks for {earlier} differ from those dispositions read; rerun dispositions")
                loaded[earlier] = (load(native) if native.exists() else None, load(cross) if cross.exists() else None,
                                   load(directory / "compare.meta.json"))
            return loaded[earlier]

        def answers(earlier: str, issue_id: str) -> list[str]:
            native, cross, _ = legs(earlier)
            native_provider = str((native or {}).get("provider", ""))
            return ["    " + leg_line(native, "native", issue_id), "    " + leg_line(cross, "cross", issue_id, native_provider)]

        for earlier in pairs:  # every pair dispositions read, referenced or not, so neither a reason nor the verdict is stale
            legs(earlier)
        status, confirmation = document.get("analysis_status"), document.get("confirmation", {})
        lines += [f"## {ghsa_id}",
                  f"Verdict: {document.get('verdict')} | analysis status: {status} | review leg (cross_leg): {document.get('cross_leg')} "
                  f"| decision digest: {document.get('decision_digest')}"]
        if document.get("rerun_pairs"):
            lines.append("Rerun pairs (the earlier report changed after a YES): " + ", ".join(document["rerun_pairs"]))
        lines.append("Issues:")
        for item in document.get("issues", []):
            if not item.get("technical"):
                continue
            issue_id = item["issue_id"]
            lines.append(f"- {issue_id} {item['disposition']}: {one_line_json(item['mechanism'])}")
            if item.get("canonical"):
                also = item.get("also_covered_by") or []
                lines.append(f"  canonical: {item['canonical']}" + (f" (also covered by: {', '.join(also)})" if also else ""))
                lines += answers(item["canonical"], issue_id)
            for entry in item.get("unresolved", []):
                lines.append(f"  unresolved against {entry['earlier_ghsa_id']} ({entry['reason']})")
                lines += answers(entry["earlier_ghsa_id"], issue_id)
            for earlier in item.get("published_matches", []):
                lines.append(f"  published match (possible regression or incomplete fix): {earlier}")
                lines += answers(earlier, issue_id)
            for earlier in item.get("closed_matches", []):
                repository = str(legs(earlier)[2].get("repository", ""))
                if not OWNER_REPO.match(repository):
                    raise UsageError(f"{earlier}: the comparison packet names no OWNER/REPO repository")
                link = "/".join(("https://github.com", repository, "security", "advisories", earlier))
                lines.append(f"  closed match: {earlier} {link}")
                lines += answers(earlier, issue_id)
                if args.captures:
                    if earlier not in captures:
                        raise UsageError(f"the captures map has no capture for {earlier}")
                    capture = load(captures[earlier])
                    if capture.get("advisory", {}).get("ghsa_id") != earlier:
                        raise UsageError(f"the capture given for {earlier} is for another advisory")
                    comments = [c.get("body", "") for c in capture.get("advisory", {}).get("comments", []) or []
                                if isinstance(c, dict) and c.get("body")]
                    changed = rendered_sha256(capture) != pairs.get(earlier, {}).get("x_rendered_sha256")
                    lines.append("    last captured comment (untrusted report data): "
                                 + (one_line_json(comments[-1]) if comments else "none captured")
                                 + (" (capture changed since the comparison)" if changed else ""))
                else:
                    lines.append("    last captured comment: not shown (pass --captures)")
            for entry in item.get("information", []):
                lines.append(f"  information: {entry['earlier_ghsa_id']} ({entry['role']}, {entry['reason']})")
        ignored = document.get("ignored", [])
        if ignored:
            lines.append("Ignored (kinds): " + "; ".join(f"{entry['issue_id']} (native {entry['kinds'].get('native', '')}, cross "
                                                        f"{entry['kinds'].get('cross', '')})" for entry in ignored))
        if document.get("fix_guidance"):
            lines.append("Fix guidance for the fix author: " + ", ".join(document["fix_guidance"]))
        if status == "AWAITING_CONFIRMATION":
            if confirmation.get("stale"):
                lines.append("An earlier confirmation no longer matches this decision (the dispositions changed); decide again.")
            lines.append(f"Decision: CONFIRMED | REJECTED (record it with ghsa-dedup.py confirm --dispositions {path})")
            lines.append("Decision required: until it is recorded and dispositions is rerun, this report is not analyzed and "
                         "gets no H4 draft and no write-back.")
            awaiting.append(ghsa_id)
        elif confirmation.get("applied"):
            lines.append(f"Decision applied: {confirmation['decision']}, reason {one_line_json(confirmation.get('reason', ''))}, "
                         f"recorded {confirmation.get('recorded_at_utc', '')}")
        lines.append("")
        reports.append(ghsa_id)
    out = Path(args.out)
    restricted_dir(out.parent)
    write_text_private(out, "\n".join(lines))
    return {"status": "COMPLETE", "reports": len(reports), "awaiting_confirmation": awaiting, "out": str(out)}


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or ADAPTER_NAME).splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("records"); p.add_argument("--repository", required=True); p.add_argument("--ghsa-id", required=True)
    p.add_argument("--primary-revision", required=True)
    p.add_argument("--issues", required=True, help="the advisory's step 1a issues.json")
    p.add_argument("--dispositions", required=True, help="the advisory's current dispositions.json (analysis_status READY)")
    p.add_argument("--discovery", action="append", required=True, help="schema-valid, post-schema-checked discovery artifact")
    p.add_argument("--verification", required=True, help="orchestrator manifest of final statuses and Stage 2 artifacts")
    p.add_argument("--out-dir", required=True)
    p = sub.add_parser("compare-plan"); p.add_argument("--listing", required=True); p.add_argument("--ghsa-id", required=True)
    p.add_argument("--captures", required=True, help="JSON map of GHSA ID to intake-record path"); p.add_argument("--out", required=True)
    p = sub.add_parser("dispositions"); p.add_argument("--issues", required=True); p.add_argument("--plan", required=True)
    p.add_argument("--compare-dir", required=True); p.add_argument("--captures", help="current captures; default: the plan's")
    p.add_argument("--confirmation"); p.add_argument("--out", required=True)
    p = sub.add_parser("confirm"); p.add_argument("--dispositions", required=True)
    p.add_argument("--decision", required=True, choices=["CONFIRMED", "REJECTED"]); p.add_argument("--reason", required=True)
    p.add_argument("--out", required=True)
    p = sub.add_parser("brief"); p.add_argument("--dispositions", required=True, action="append", help="a step1a/dispositions.json; repeat per report")
    p.add_argument("--captures", help="captures map, to show each closed match's last captured comment")
    p.add_argument("--out", required=True, help="text file for the human; it may name other advisories")
    args = parser.parse_args()
    handlers = {"records": command_records, "compare-plan": command_compare_plan, "dispositions": command_dispositions,
                "confirm": command_confirm, "brief": command_brief}
    try:
        outcome = handlers[args.command](args)
    except (UsageError, KeyError, TypeError, IndexError, AttributeError, OSError) as error:
        print(json.dumps({"status": "USAGE_ERROR", "error": str(error)}), file=sys.stderr)
        return EXIT_USAGE
    outcome.update({"adapter": ADAPTER_NAME, "adapter_version": ADAPTER_VERSION})
    print(json.dumps(outcome, sort_keys=True))
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
