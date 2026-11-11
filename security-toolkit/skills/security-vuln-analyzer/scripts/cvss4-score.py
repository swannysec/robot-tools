#!/usr/bin/env python3
"""Deterministic CVSS v4.0 scoring of a role-emitted vector.

Usage: cvss4-score.py score --vector VECTOR

The scorer computes the score of exactly one complete CVSS v4.0 vector. It never chooses, infers, or fills in
a metric: a vector that is incomplete, out of order, or otherwise outside the FIRST v4.0 Table 23 grammar is
refused with exit code 2 and a JSON {"status": "USAGE_ERROR", "error": ...} object on stderr. Argparse usage
errors (a missing subcommand or option) also exit 2, but argparse prints them as plain text.

The lookup, max_composed, and max_severity tables and the scoring algorithm (effective-metric defaults,
macrovector equivalence classes, severity-distance interpolation, and half-up rounding) are ported from the
FIRST CVSS v4.0 calculator (the FIRSTdotorg cvss-v4-calculator repository on GitHub) at commit
c5b0d409ae9f57c44264c6ce5f27d89298e1d32a. Those FIRST-derived tables and that algorithm remain under the
BSD-2-Clause license reproduced below; the rest of this repository is distributed under its own, different
license.

Copyright (c) 2023 FIRST.ORG, Inc., Red Hat, and contributors

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys

ADAPTER_NAME = "cvss4-score.py"
ADAPTER_VERSION = "1.0.0"
FIRST_COMMIT = "c5b0d409ae9f57c44264c6ce5f27d89298e1d32a"
CALCULATOR = f"{ADAPTER_NAME} {ADAPTER_VERSION} (FIRST CVSS v4.0 reference tables, {FIRST_COMMIT})"
EXIT_PASS = 0
EXIT_USAGE = 2

# FIRST v4.0 Table 23 grammar, copied from the repository's acceptance runner
# (`security_cvss_v4_vector_is_complete`): base metrics required in order,
# every optional metric at most once and in order.
BASE_GRAMMAR = (
    ("AV", "[NALP]"), ("AC", "[LH]"), ("AT", "[NP]"), ("PR", "[NLH]"),
    ("UI", "[NPA]"), ("VC", "[HLN]"), ("VI", "[HLN]"), ("VA", "[HLN]"),
    ("SC", "[HLN]"), ("SI", "[HLN]"), ("SA", "[HLN]"),
)
OPTIONAL_GRAMMAR = (
    ("E", "[XAPU]"), ("CR", "[XHML]"), ("IR", "[XHML]"), ("AR", "[XHML]"),
    ("MAV", "[XNALP]"), ("MAC", "[XLH]"), ("MAT", "[XNP]"), ("MPR", "[XNLH]"),
    ("MUI", "[XNPA]"), ("MVC", "[XNLH]"), ("MVI", "[XNLH]"), ("MVA", "[XNLH]"),
    ("MSC", "[XNLH]"), ("MSI", "[XNLHS]"), ("MSA", "[XNLHS]"),
    ("S", "[XNP]"), ("AU", "[XNY]"), ("R", "[XAUI]"), ("V", "[XDC]"),
    ("RE", "[XLMH]"), ("U", "(?:X|Clear|Green|Amber|Red)"),
)
VECTOR_PATTERN = re.compile(
    r"CVSS:4\.0" + "".join(f"/{name}:{values}" for name, values in BASE_GRAMMAR)
    + "".join(f"(?:/{name}:{values})?" for name, values in OPTIONAL_GRAMMAR)
)
ENVIRONMENTAL = ("CR", "IR", "AR", "MAV", "MAC", "MAT", "MPR", "MUI", "MVC", "MVI", "MVA", "MSC", "MSI", "MSA")

# FIRST cvss_lookup.js: macrovector -> score of its highest-severity vector.
LOOKUP: dict[str, float] = {
    "000000": 10.0, "000001": 9.9, "000010": 9.8, "000011": 9.5, "000020": 9.5, "000021": 9.2, "000100": 10.0, "000101": 9.6,
    "000110": 9.3, "000111": 8.7, "000120": 9.1, "000121": 8.1, "000200": 9.3, "000201": 9.0, "000210": 8.9, "000211": 8.0,
    "000220": 8.1, "000221": 6.8, "001000": 9.8, "001001": 9.5, "001010": 9.5, "001011": 9.2, "001020": 9.0, "001021": 8.4,
    "001100": 9.3, "001101": 9.2, "001110": 8.9, "001111": 8.1, "001120": 8.1, "001121": 6.5, "001200": 8.8, "001201": 8.0,
    "001210": 7.8, "001211": 7.0, "001220": 6.9, "001221": 4.8, "002001": 9.2, "002011": 8.2, "002021": 7.2, "002101": 7.9,
    "002111": 6.9, "002121": 5.0, "002201": 6.9, "002211": 5.5, "002221": 2.7, "010000": 9.9, "010001": 9.7, "010010": 9.5,
    "010011": 9.2, "010020": 9.2, "010021": 8.5, "010100": 9.5, "010101": 9.1, "010110": 9.0, "010111": 8.3, "010120": 8.4,
    "010121": 7.1, "010200": 9.2, "010201": 8.1, "010210": 8.2, "010211": 7.1, "010220": 7.2, "010221": 5.3, "011000": 9.5,
    "011001": 9.3, "011010": 9.2, "011011": 8.5, "011020": 8.5, "011021": 7.3, "011100": 9.2, "011101": 8.2, "011110": 8.0,
    "011111": 7.2, "011120": 7.0, "011121": 5.9, "011200": 8.4, "011201": 7.0, "011210": 7.1, "011211": 5.2, "011220": 5.0,
    "011221": 3.0, "012001": 8.6, "012011": 7.5, "012021": 5.2, "012101": 7.1, "012111": 5.2, "012121": 2.9, "012201": 6.3,
    "012211": 2.9, "012221": 1.7, "100000": 9.8, "100001": 9.5, "100010": 9.4, "100011": 8.7, "100020": 9.1, "100021": 8.1,
    "100100": 9.4, "100101": 8.9, "100110": 8.6, "100111": 7.4, "100120": 7.7, "100121": 6.4, "100200": 8.7, "100201": 7.5,
    "100210": 7.4, "100211": 6.3, "100220": 6.3, "100221": 4.9, "101000": 9.4, "101001": 8.9, "101010": 8.8, "101011": 7.7,
    "101020": 7.6, "101021": 6.7, "101100": 8.6, "101101": 7.6, "101110": 7.4, "101111": 5.8, "101120": 5.9, "101121": 5.0,
    "101200": 7.2, "101201": 5.7, "101210": 5.7, "101211": 5.2, "101220": 5.2, "101221": 2.5, "102001": 8.3, "102011": 7.0,
    "102021": 5.4, "102101": 6.5, "102111": 5.8, "102121": 2.6, "102201": 5.3, "102211": 2.1, "102221": 1.3, "110000": 9.5,
    "110001": 9.0, "110010": 8.8, "110011": 7.6, "110020": 7.6, "110021": 7.0, "110100": 9.0, "110101": 7.7, "110110": 7.5,
    "110111": 6.2, "110120": 6.1, "110121": 5.3, "110200": 7.7, "110201": 6.6, "110210": 6.8, "110211": 5.9, "110220": 5.2,
    "110221": 3.0, "111000": 8.9, "111001": 7.8, "111010": 7.6, "111011": 6.7, "111020": 6.2, "111021": 5.8, "111100": 7.4,
    "111101": 5.9, "111110": 5.7, "111111": 5.7, "111120": 4.7, "111121": 2.3, "111200": 6.1, "111201": 5.2, "111210": 5.7,
    "111211": 2.9, "111220": 2.4, "111221": 1.6, "112001": 7.1, "112011": 5.9, "112021": 3.0, "112101": 5.8, "112111": 2.6,
    "112121": 1.5, "112201": 2.3, "112211": 1.3, "112221": 0.6, "200000": 9.3, "200001": 8.7, "200010": 8.6, "200011": 7.2,
    "200020": 7.5, "200021": 5.8, "200100": 8.6, "200101": 7.4, "200110": 7.4, "200111": 6.1, "200120": 5.6, "200121": 3.4,
    "200200": 7.0, "200201": 5.4, "200210": 5.2, "200211": 4.0, "200220": 4.0, "200221": 2.2, "201000": 8.5, "201001": 7.5,
    "201010": 7.4, "201011": 5.5, "201020": 6.2, "201021": 5.1, "201100": 7.2, "201101": 5.7, "201110": 5.5, "201111": 4.1,
    "201120": 4.6, "201121": 1.9, "201200": 5.3, "201201": 3.6, "201210": 3.4, "201211": 1.9, "201220": 1.9, "201221": 0.8,
    "202001": 6.4, "202011": 5.1, "202021": 2.0, "202101": 4.7, "202111": 2.1, "202121": 1.1, "202201": 2.4, "202211": 0.9,
    "202221": 0.4, "210000": 8.8, "210001": 7.5, "210010": 7.3, "210011": 5.3, "210020": 6.0, "210021": 5.0, "210100": 7.3,
    "210101": 5.5, "210110": 5.9, "210111": 4.0, "210120": 4.1, "210121": 2.0, "210200": 5.4, "210201": 4.3, "210210": 4.5,
    "210211": 2.2, "210220": 2.0, "210221": 1.1, "211000": 7.5, "211001": 5.5, "211010": 5.8, "211011": 4.5, "211020": 4.0,
    "211021": 2.1, "211100": 6.1, "211101": 5.1, "211110": 4.8, "211111": 1.8, "211120": 2.0, "211121": 0.9, "211200": 4.6,
    "211201": 1.8, "211210": 1.7, "211211": 0.7, "211220": 0.8, "211221": 0.2, "212001": 5.3, "212011": 2.4, "212021": 1.4,
    "212101": 2.4, "212111": 1.2, "212121": 0.5, "212201": 1.0, "212211": 0.3, "212221": 0.1,
}

# FIRST max_composed.js: highest-severity vector parts per EQ level (EQ3 keyed by EQ6).
MAX_COMPOSED: dict[str, dict[str, list[str]]] = {
    "eq1": {
        "0": ["AV:N/PR:N/UI:N/"],
        "1": ["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"],
        "2": ["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"],
    },
    "eq2": {
        "0": ["AC:L/AT:N/"],
        "1": ["AC:H/AT:N/", "AC:L/AT:P/"],
    },
    "eq4": {
        "0": ["SC:H/SI:S/SA:S/"],
        "1": ["SC:H/SI:H/SA:H/"],
        "2": ["SC:L/SI:L/SA:L/"],
    },
    "eq5": {
        "0": ["E:A/"],
        "1": ["E:P/"],
        "2": ["E:U/"],
    },
}
MAX_COMPOSED_EQ3: dict[str, dict[str, list[str]]] = {
    "0": {"0": ["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"],
          "1": ["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"]},
    "1": {"0": ["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"],
          "1": ["VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/", "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/", "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/",
                "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/", "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/"]},
    "2": {"1": ["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"]},
}

# FIRST max_severity.js: maximal severity distance (+1) per EQ level.
MAX_SEVERITY: dict[str, dict[int, int]] = {
    "eq1": {0: 1, 1: 4, 2: 5},
    "eq2": {0: 1, 1: 2},
    "eq4": {0: 6, 1: 5, 2: 4},
    "eq5": {0: 1, 1: 1, 2: 1},
}
MAX_SEVERITY_EQ3EQ6: dict[int, dict[int, int]] = {0: {0: 7, 1: 6}, 1: {0: 8, 1: 8}, 2: {1: 10}}

# FIRST cvss_score.js: per-metric severity levels used for the severity distance.
LEVELS: dict[str, dict[str, float]] = {
    "AV": {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3},
    "PR": {"N": 0.0, "L": 0.1, "H": 0.2},
    "UI": {"N": 0.0, "P": 0.1, "A": 0.2},
    "AC": {"L": 0.0, "H": 0.1},
    "AT": {"N": 0.0, "P": 0.1},
    "VC": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VI": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VA": {"H": 0.0, "L": 0.1, "N": 0.2},
    "SC": {"H": 0.1, "L": 0.2, "N": 0.3},
    "SI": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "SA": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "CR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "IR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "AR": {"H": 0.0, "M": 0.1, "L": 0.2},
}


class UsageError(ValueError):
    pass


def metric_pairs(text: str) -> dict[str, str]:
    return {name: value for name, _, value in (part.partition(":") for part in text.split("/") if part)}


def parse_vector(vector: str) -> dict[str, str]:
    if VECTOR_PATTERN.fullmatch(vector) is None:
        raise UsageError("not a complete CVSS v4.0 vector in FIRST Table 23 order; no metric is guessed")
    selected = {name: "X" for name, _ in OPTIONAL_GRAMMAR}
    selected.update(metric_pairs(vector.partition("/")[2]))
    return selected


def effective(selected: dict[str, str], metric: str) -> str:
    """The reference m(): E:X is E:A, CR/IR/AR:X is H, and a non-X modified metric overrides its base metric."""
    value = selected[metric]
    if metric == "E" and value == "X":
        return "A"
    if metric in ("CR", "IR", "AR") and value == "X":
        return "H"
    modified = selected.get("M" + metric, "X")
    return modified if modified != "X" else value


def macrovector(selected: dict[str, str]) -> str:
    def m(metric: str) -> str:
        return effective(selected, metric)

    if m("AV") == "N" and m("PR") == "N" and m("UI") == "N":
        eq1 = 0
    elif (m("AV") == "N" or m("PR") == "N" or m("UI") == "N") and m("AV") != "P":
        eq1 = 1
    else:
        eq1 = 2
    eq2 = 0 if m("AC") == "L" and m("AT") == "N" else 1
    if m("VC") == "H" and m("VI") == "H":
        eq3 = 0
    elif m("VC") == "H" or m("VI") == "H" or m("VA") == "H":
        eq3 = 1
    else:
        eq3 = 2
    if m("MSI") == "S" or m("MSA") == "S":
        eq4 = 0
    elif m("SC") == "H" or m("SI") == "H" or m("SA") == "H":
        eq4 = 1
    else:
        eq4 = 2
    eq5 = {"A": 0, "P": 1, "U": 2}[m("E")]
    eq6 = 0 if ((m("CR") == "H" and m("VC") == "H") or (m("IR") == "H" and m("VI") == "H")
                or (m("AR") == "H" and m("VA") == "H")) else 1
    return f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6}"


def round_half_up(value: float) -> int:
    """JavaScript Math.round for a non-negative number: ties go up, unlike Python's round()."""
    whole = math.floor(value)
    return whole + 1 if value - whole >= 0.5 else whole


def score(selected: dict[str, str]) -> float:
    def m(metric: str) -> str:
        return effective(selected, metric)

    # 1. Zero-impact short-circuit: every effective impact metric is N.
    if all(m(metric) == "N" for metric in ("VC", "VI", "VA", "SC", "SI", "SA")):
        return 0.0
    macro = macrovector(selected)
    value = LOOKUP[macro]
    eq1, eq2, eq3, eq4, eq5, eq6 = (int(digit) for digit in macro)

    def lower(*digits: int) -> float:
        return LOOKUP.get("".join(map(str, digits)), math.nan)  # a missing macrovector behaves as NaN

    # 2. Scores of the next-lower macrovector for each EQ (NaN when none exists).
    score_eq1 = lower(eq1 + 1, eq2, eq3, eq4, eq5, eq6)
    score_eq2 = lower(eq1, eq2 + 1, eq3, eq4, eq5, eq6)
    if eq3 == 0 and eq6 == 0:
        left = lower(eq1, eq2, eq3, eq4, eq5, eq6 + 1)
        right = lower(eq1, eq2, eq3 + 1, eq4, eq5, eq6)
        score_eq3eq6 = left if left > right else right  # NaN compares false, as undefined does in the reference
    elif eq3 == 1 and eq6 == 0:
        score_eq3eq6 = lower(eq1, eq2, eq3, eq4, eq5, eq6 + 1)
    elif eq3 in (0, 1):
        score_eq3eq6 = lower(eq1, eq2, eq3 + 1, eq4, eq5, eq6)
    else:
        score_eq3eq6 = lower(eq1, eq2, eq3 + 1, eq4, eq5, eq6 + 1)
    score_eq4 = lower(eq1, eq2, eq3, eq4 + 1, eq5, eq6)
    score_eq5 = lower(eq1, eq2, eq3, eq4, eq5 + 1, eq6)

    # 3. Severity distance of the scored vector from a highest-severity vector of its macrovector.
    max_vectors = [a + b + c + d + e
                   for a in MAX_COMPOSED["eq1"][macro[0]] for b in MAX_COMPOSED["eq2"][macro[1]]
                   for c in MAX_COMPOSED_EQ3[macro[2]][macro[5]] for d in MAX_COMPOSED["eq4"][macro[3]]
                   for e in MAX_COMPOSED["eq5"][macro[4]]]
    distance: dict[str, float] = {}
    for max_vector in max_vectors:  # the first max vector with no negative distance; else the last one tried
        parts = metric_pairs(max_vector)
        distance = {metric: LEVELS[metric][m(metric)] - LEVELS[metric][parts[metric]] for metric in LEVELS}
        if not any(item < 0 for item in distance.values()):
            break

    current_eq1 = distance["AV"] + distance["PR"] + distance["UI"]
    current_eq2 = distance["AC"] + distance["AT"]
    current_eq3eq6 = (distance["VC"] + distance["VI"] + distance["VA"]
                      + distance["CR"] + distance["IR"] + distance["AR"])
    current_eq4 = distance["SC"] + distance["SI"] + distance["SA"]
    # 4. Normalized mean distance, then clamp and round.
    # Float operations and their order mirror cvss_score.js exactly (maxSeverity * step,
    # available * (current / max), Math.round(value * 10) / 10). Reordering them or switching to integer
    # tenths changes results at x.x5 boundaries; re-run the FIRST oracle comparison before refactoring.
    step = 0.1
    steps = [
        (value - score_eq1, current_eq1, MAX_SEVERITY["eq1"][eq1] * step),
        (value - score_eq2, current_eq2, MAX_SEVERITY["eq2"][eq2] * step),
        (value - score_eq3eq6, current_eq3eq6, MAX_SEVERITY_EQ3EQ6[eq3][eq6] * step),
        (value - score_eq4, current_eq4, MAX_SEVERITY["eq4"][eq4] * step),
    ]
    normalized = [0.0, 0.0, 0.0, 0.0, 0.0]
    existing = 0
    for index, (available, current, max_severity) in enumerate(steps):
        if not math.isnan(available):
            existing += 1
            normalized[index] = available * (current / max_severity)
    if not math.isnan(value - score_eq5):
        existing += 1
        normalized[4] = (value - score_eq5) * 0  # the EQ5 proportion is always 0
    mean = 0 if existing == 0 else (normalized[0] + normalized[1] + normalized[2] + normalized[3] + normalized[4]) / existing
    value -= mean
    value = min(max(value, 0.0), 10.0)
    return round_half_up(value * 10) / 10


def severity(value: float) -> str:
    if value == 0:
        return "None"
    if value < 4.0:
        return "Low"
    if value < 7.0:
        return "Medium"
    return "High" if value < 9.0 else "Critical"


def command_score(vectors: list[str]) -> dict[str, object]:
    if len(vectors) != 1:
        raise UsageError("exactly one --vector is required per call")
    vector = vectors[0]
    selected = parse_vector(vector)
    threat = selected["E"] != "X"
    environmental = any(selected[name] != "X" for name in ENVIRONMENTAL)
    value = score(selected)
    return {"status": "COMPLETE", "vector": vector, "score": value,
            "score_type": "CVSS-B" + ("T" if threat else "") + ("E" if environmental else ""),
            "severity": severity(value), "calculator": CALCULATOR}


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or ADAPTER_NAME).splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("score").add_argument("--vector", action="append", required=True)
    args = parser.parse_args()
    try:
        outcome = command_score(args.vector)
    except UsageError as error:
        print(json.dumps({"status": "USAGE_ERROR", "error": str(error)}), file=sys.stderr)
        return EXIT_USAGE
    print(json.dumps(outcome, ensure_ascii=False))
    return EXIT_PASS


if __name__ == "__main__":
    sys.exit(main())
