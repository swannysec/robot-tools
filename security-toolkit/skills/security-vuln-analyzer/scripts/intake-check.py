#!/usr/bin/env python3
"""Deterministic checks for GHSA intake roles and frozen-test registration.

Subcommands:
  h1           schema, exact-quote, and typed-literal checks for H1 / D1 claim output
  h2           schema and quote checks for H2, plus the completeness pause decision
  h4-packet    build H4's scoped packet and allowed-record set for one advisory
  h4           check an H4 draft against its allowed records and the unpublished-ID block
  poc-overlap  reject a test file that copies a long verbatim span from an H1 PoC block
  render       write the captured advisory fields as raw text for an intake or Phase 1 packet

The checks count, compare, and match strings. They never judge whether a claim is valid.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any

ADAPTER_NAME = "security-vuln-analyzer-intake-check"
ADAPTER_VERSION = "1.0.0"
POC_OVERLAP_THRESHOLD = 80  # characters of whitespace-normalized text; fixed by design
GHSA_TOKEN = re.compile(r"GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}", re.IGNORECASE)
BRIEF_PHRASES = ("previously reported", "variant", "duplicate", "same root cause", "already reported")
EXIT_PASS = 0
EXIT_USAGE = 2
EXIT_REJECTED = 5
SKILL_DIR = Path(__file__).resolve().parent.parent


class UsageError(ValueError):
    pass


def load_json(path: str | Path) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise UsageError(f"cannot read JSON {path}: {error}") from error


def load_schema(name: str) -> dict[str, Any]:
    return load_json(SKILL_DIR / "schemas" / name)


def schema_errors(value: Any, schema: dict[str, Any], path: str = "$") -> list[str]:
    """Validate the JSON Schema subset used by this package's role schemas."""
    errors: list[str] = []
    expected = schema.get("type")
    types = expected if isinstance(expected, list) else [expected] if expected else []
    checks = {
        "object": lambda v: isinstance(v, dict),
        "array": lambda v: isinstance(v, list),
        "string": lambda v: isinstance(v, str),
        "boolean": lambda v: isinstance(v, bool),
        "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
        "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
        "null": lambda v: v is None,
    }
    if types and not any(checks[t](value) for t in types):
        return [f"{path}: expected {'/'.join(types)}"]
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: value not in enum")
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            errors.append(f"{path}: shorter than minLength")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            errors.append(f"{path}: longer than maxLength")
        if "pattern" in schema and not re.search(schema["pattern"], value):
            errors.append(f"{path}: does not match pattern")
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            errors.append(f"{path}: fewer than minItems")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            errors.append(f"{path}: more than maxItems")
        for index, item in enumerate(value):
            errors.extend(schema_errors(item, schema.get("items", {}), f"{path}[{index}]"))
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{path}: missing required {key}")
        if schema.get("additionalProperties") is False:
            for key in value:
                if key not in properties:
                    errors.append(f"{path}: undeclared field {key}")
        for key, item in value.items():
            if key in properties:
                errors.extend(schema_errors(item, properties[key], f"{path}.{key}"))
    return errors


def normalize_newlines(text: str) -> str:
    """CRLF and lone CR become LF; a model reproducing visible text emits LF."""
    return text.replace("\r\n", "\n").replace("\r", "\n")


def labeled_fields(intake: dict[str, Any]) -> list[tuple[str, str]]:
    """The captured advisory fields, labeled, exactly as rendered to intake roles and compared by the checks."""
    advisory = intake.get("advisory", {})
    fields: list[tuple[str, Any]] = [("summary", advisory.get("summary", "")), ("description", advisory.get("description", ""))]
    for index, comment in enumerate(advisory.get("comments", []), 1):
        if isinstance(comment, dict):
            fields.append((f"comment {index}", comment.get("body", "")))
    # Structured vulnerability fields are part of the captured advisory in the packet, so a
    # verbatim version range, package, or vulnerable-function name is a valid quote.
    for index, vulnerability in enumerate(advisory.get("reporter_claims", {}).get("vulnerabilities", []), 1):
        if isinstance(vulnerability, dict):
            for key in ("package", "vulnerable_version_range", "patched_versions"):
                fields.append((f"vulnerability {index} {key}", vulnerability.get(key, "")))
            for number, function in enumerate(vulnerability.get("vulnerable_functions", []) or [], 1):
                fields.append((f"vulnerability {index} vulnerable_function {number}", function))
    return [(label, normalize_newlines(value)) for label, value in fields if isinstance(value, str) and value]


def captured_fields(intake: dict[str, Any]) -> list[str]:
    return [value for _, value in labeled_fields(intake)]


def is_exact_quote(text: str, fields: list[str]) -> bool:
    """Exact substring match after line-ending normalization; nothing else is normalized."""
    text = normalize_newlines(text)
    return bool(text) and any(text in field for field in fields)


def effective_status(result: Any, errors: list[str]) -> str:
    if isinstance(result, dict) and result.get("declined_scope"):
        return "REFUSED"
    if isinstance(result, dict) and result.get("status") not in (None, "COMPLETE"):
        return str(result.get("status"))
    return "MALFORMED" if errors else "COMPLETE"


def check_identity(result: dict[str, Any], intake: dict[str, Any], errors: list[str]) -> None:
    if result.get("ghsa_id") != intake.get("advisory", {}).get("ghsa_id"):
        errors.append("result names a different advisory than the intake record")


def command_h1(args: argparse.Namespace) -> dict[str, Any]:
    intake, result = load_json(args.intake), load_json(args.result)
    errors = schema_errors(result, load_schema("intake-h1-claims.schema.json"))
    literal_summary: dict[str, list[str]] = {}
    if not errors:
        fields = captured_fields(intake)
        check_identity(result, intake, errors)
        if not result["claims"]:
            errors.append("H1 returned no claims")
        seen: set[str] = set()
        for claim in result["claims"]:
            if claim["claim_id"] in seen:
                errors.append(f"duplicate claim_id {claim['claim_id']}")
            seen.add(claim["claim_id"])
            if not is_exact_quote(claim["statement_quote"], fields):
                errors.append(f"{claim['claim_id']}: statement_quote is not an exact substring of the captured advisory")
            if claim["entry_point_quote"] and not is_exact_quote(claim["entry_point_quote"], fields):
                errors.append(f"{claim['claim_id']}: entry_point_quote is not an exact substring")
            for kind, values in claim["literals"].items():
                for literal in values:
                    if not is_exact_quote(literal, fields):
                        errors.append(f"{claim['claim_id']}: {kind} literal does not appear verbatim in the advisory")
                        continue  # only checked literals are reported
                    literal_summary.setdefault(kind, [])
                    if literal not in literal_summary[kind]:
                        literal_summary[kind].append(literal)
        for index, text in enumerate(result["versions_quoted"]):
            if not is_exact_quote(text, fields):
                errors.append(f"versions_quoted[{index}] is not an exact substring")
        for index, block in enumerate(result["poc_blocks"]):
            if not is_exact_quote(block["quote"], fields):
                errors.append(f"poc_blocks[{index}] is not an exact substring")
    status = effective_status(result, errors)
    return {
        "check": "h1", "effective_status": status, "errors": errors,
        "declined_scope": result.get("declined_scope", []) if isinstance(result, dict) else [],
        "typed_literals": {kind: sorted(values) for kind, values in sorted(literal_summary.items())},
    }


def command_h2(args: argparse.Namespace) -> dict[str, Any]:
    intake, result = load_json(args.intake), load_json(args.result)
    errors = schema_errors(result, load_schema("intake-h2-completeness.schema.json"))
    if not errors:
        fields = captured_fields(intake)
        check_identity(result, intake, errors)
        for element in ("reproduction_steps", "proof_of_concept"):
            record = result[element]
            if record["present"] and not is_exact_quote(record["quote"], fields):
                errors.append(f"{element}: 'present' requires a non-empty exact quote")
            if not record["present"] and record["quote"]:
                errors.append(f"{element}: absent element must have an empty quote")
    status = effective_status(result, errors)
    neither = status == "COMPLETE" and not result["reproduction_steps"]["present"] and not result["proof_of_concept"]["present"]
    if args.mode == "queue":
        decision = "PAUSE" if status != "COMPLETE" or neither else "PROCEED"
        reason = "H2 did not complete" if status != "COMPLETE" else "neither reproduction steps nor a proof of concept is present" if neither else ""
    else:
        decision = "ANNOTATE"
        reason = "H2 did not complete" if status != "COMPLETE" else "neither element present" if neither else "element present"
    return {"check": "h2", "effective_status": status, "errors": errors, "mode": args.mode,
            "pause_decision": decision, "reason": reason,
            "declined_scope": result.get("declined_scope", []) if isinstance(result, dict) else []}


H4_RECORD_FIELDS = ("record_id", "kind", "answers", "final_status", "fallback_model", "fallback_use_permitted",
                    "normalized_proposition", "proposed_disposition", "values")


def h4_projection(record: dict[str, Any]) -> dict[str, Any]:
    """Only the fields H4 needs: no evidence, variants, locations, or supporting-context material."""
    return {key: record[key] for key in H4_RECORD_FIELDS if key in record}


def value_source(record: dict[str, Any]) -> bool:
    """Field values may come only from verified records, with explicit permission for fallback results."""
    return record.get("final_status") == "CROSS-MODEL VERIFIED" and (
        record.get("fallback_model") is not True or record.get("fallback_use_permitted") is True
    )


def command_h4_packet(args: argparse.Namespace) -> dict[str, Any]:
    intake, claims, records = load_json(args.intake), load_json(args.claims), load_json(args.records)
    advisory = intake["advisory"]["ghsa_id"]
    if claims.get("ghsa_id") != advisory:
        raise UsageError("claims belong to a different advisory")
    claim_ids = {claim["claim_id"] for claim in claims.get("claims", [])}
    allowed = []
    for record in records.get("records", []):
        if record.get("kind") == "relation":
            continue
        answers = record.get("answers", [])
        if answers and all(a.get("ghsa_id") == advisory and a.get("claim_id") in claim_ids for a in answers):
            allowed.append(h4_projection(record))
    packet = {
        "packet_type": "intake_h4",
        "ghsa_id": advisory,
        "intake_record": intake,
        "claims": claims,
        "finding_records": allowed,
    }
    allowed_ids = ["intake:" + advisory] + [f"claim:{claim_id}" for claim_id in sorted(claim_ids)] + [r["record_id"] for r in allowed]
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "h4-packet.json").write_text(json.dumps(packet, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    (out / "h4-allowed-records.json").write_text(json.dumps({"ghsa_id": advisory, "record_ids": allowed_ids, "records": allowed}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {"check": "h4-packet", "effective_status": "COMPLETE", "errors": [], "allowed_record_ids": allowed_ids}


def command_h4(args: argparse.Namespace) -> dict[str, Any]:
    result, allowed = load_json(args.result), load_json(args.allowed_records)
    unpublished = {item.upper() for item in load_json(args.unpublished_ids).get("ghsa_ids", [])}
    errors = schema_errors(result, load_schema("intake-h4-draft.schema.json"))
    highlights: list[dict[str, str]] = []
    mentioned: set[str] = set()
    if not errors:
        advisory = allowed.get("ghsa_id", "")
        if result.get("ghsa_id") != advisory:
            errors.append("draft names a different advisory than its allowed-record set")
        allowed_ids = set(allowed.get("record_ids", []))
        values_by_record = {r["record_id"]: r.get("values", {}) for r in allowed.get("records", [])
                            if "record_id" in r and value_source(r)}

        def scan(text: str, where: str) -> None:
            for token in GHSA_TOKEN.findall(text):
                if token.upper() != advisory.upper() and token.upper() in unpublished:
                    errors.append(f"{where}: names another unpublished advisory")
            lowered = text.lower()
            for phrase in BRIEF_PHRASES:
                if phrase in lowered:
                    highlights.append({"location": where, "phrase": phrase})

        for index, update in enumerate(result["field_updates"]):
            where = f"field_updates[{index}]"
            outside = [ref for ref in update["record_refs"] if ref not in allowed_ids]
            if outside:
                errors.append(f"{where}: cites records outside the advisory's allowed set")
            mentioned.update(update["record_refs"])
            try:
                proposed = json.loads(update["proposed_value_json"])
            except json.JSONDecodeError:
                errors.append(f"{where}: proposed_value_json is not JSON")
                continue
            if update["field"] != "state":
                if proposed is None or not any(
                    update["field"] in values_by_record.get(ref, {}) and values_by_record[ref][update["field"]] == proposed
                    for ref in update["record_refs"]
                ):
                    errors.append(f"{where}: value does not match a cited verified record")
            elif proposed != "draft":
                errors.append(f"{where}: the only state a draft may propose is draft")
            scan(update["proposed_value_json"], where)
        proposed_fields = {update["field"] for update in result["field_updates"]}
        if {"severity", "cvss_vector_string"} <= proposed_fields:
            errors.append("draft proposes both severity and a CVSS vector; GitHub derives severity from the vector")
        for draft in result["comment_drafts"]:
            for index, statement in enumerate(draft["statements"]):
                where = f"{draft['draft_id']}.statements[{index}]"
                outside = [ref for ref in statement["record_refs"] if ref not in allowed_ids]
                if outside:
                    errors.append(f"{where}: cites records outside the advisory's allowed set")
                mentioned.update(statement["record_refs"])
                scan(statement["text"], where)
    status = effective_status(result, errors)
    return {"check": "h4", "effective_status": status, "errors": errors,
            "posting_brief": {"records_mentioned": sorted(mentioned), "highlighted_wording": highlights}}


def command_render(args: argparse.Namespace) -> dict[str, Any]:
    """Render each captured field as raw text, so intake roles see exactly the strings the checks compare."""
    fields = labeled_fields(load_json(args.intake))
    text = "".join(f"<<<FIELD {label}>>>\n{value}\n<<<END {label}>>>\n" for label, value in fields)
    try:
        Path(args.out).write_text(text, encoding="utf-8")
    except OSError as error:
        raise UsageError(f"cannot write {args.out}: {error}") from error
    return {"check": "render", "effective_status": "COMPLETE", "errors": [], "fields": [label for label, _ in fields]}


def normalize_whitespace(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def command_poc_overlap(args: argparse.Namespace) -> dict[str, Any]:
    h1 = load_json(args.h1)
    try:
        test_text = normalize_whitespace(Path(args.test_file).read_text(encoding="utf-8", errors="replace"))
    except OSError as error:
        raise UsageError(f"cannot read test file: {error}") from error
    width = POC_OVERLAP_THRESHOLD
    windows = {test_text[i:i + width] for i in range(0, max(0, len(test_text) - width + 1))}
    overlaps = []
    for index, block in enumerate(h1.get("poc_blocks", [])):
        poc = normalize_whitespace(block.get("quote", ""))
        for start in range(0, max(0, len(poc) - width + 1)):
            if poc[start:start + width] in windows:
                overlaps.append({"poc_block": index, "poc_offset": start, "span_chars": width})
                break
    decision = "REJECT" if overlaps else "ACCEPT"
    return {"check": "poc-overlap", "effective_status": "COMPLETE", "errors": [], "decision": decision,
            "threshold_chars": width, "overlaps": overlaps}


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or ADAPTER_NAME).splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    h1 = sub.add_parser("h1")
    h1.add_argument("--intake", required=True)
    h1.add_argument("--result", required=True)
    h2 = sub.add_parser("h2")
    h2.add_argument("--intake", required=True)
    h2.add_argument("--result", required=True)
    h2.add_argument("--mode", choices=("ghsa", "queue"), required=True)
    packet = sub.add_parser("h4-packet")
    packet.add_argument("--intake", required=True)
    packet.add_argument("--claims", required=True, help="checked H1 claims for the same advisory")
    packet.add_argument("--records", required=True, help="verified report records with 'answers' links")
    packet.add_argument("--out-dir", required=True)
    h4 = sub.add_parser("h4")
    h4.add_argument("--result", required=True)
    h4.add_argument("--allowed-records", required=True)
    h4.add_argument("--unpublished-ids", required=True, help='JSON {"ghsa_ids": [...]} of unpublished advisories')
    overlap = sub.add_parser("poc-overlap")
    overlap.add_argument("--h1", required=True)
    overlap.add_argument("--test-file", required=True)
    render = sub.add_parser("render")
    render.add_argument("--intake", required=True)
    render.add_argument("--out", required=True, help="text file holding the packet's advisory data section")
    args = parser.parse_args()
    handlers = {"h1": command_h1, "h2": command_h2, "h4-packet": command_h4_packet, "h4": command_h4,
                "poc-overlap": command_poc_overlap, "render": command_render}
    try:
        outcome = handlers[args.command](args)
    except (UsageError, KeyError, TypeError) as error:
        print(json.dumps({"status": "USAGE_ERROR", "error": str(error)}), file=sys.stderr)
        return EXIT_USAGE
    outcome.update({"adapter": ADAPTER_NAME, "adapter_version": ADAPTER_VERSION})
    print(json.dumps(outcome, sort_keys=True, ensure_ascii=False))
    rejected = outcome["effective_status"] != "COMPLETE" or outcome.get("decision") == "REJECT"
    return EXIT_REJECTED if rejected else EXIT_PASS


if __name__ == "__main__":
    sys.exit(main())
