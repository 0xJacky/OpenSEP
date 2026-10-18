"""Optional interface compatibility check.

Compares the `sep_*` functions OpenSEP defines, and their AArch64 C types,
with a reference list of the ROM interface's entry points kept outside this
repository.  Skipped when OPENSEP_RESEARCH_DIR is not set.
"""

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path


root = Path(__file__).resolve().parents[1]
# The reference list (prototypes, inventory, reference types header) is not
# distributed with this repository.  Point OPENSEP_RESEARCH_DIR at it to run
# the check; without it, skip.
research_env = os.environ.get("OPENSEP_RESEARCH_DIR", "")
research = Path(research_env) if research_env else None
if research is None or not research.is_dir():
    print(
        "coverage: OPENSEP_RESEARCH_DIR not set or absent; "
        "skipping the optional interface compatibility check"
    )
    sys.exit(0)
prototype_path = research / "symbols" / "recovered-function-prototypes.json"
functions_path = research / "evidence" / "functions.json"

prototype_document = json.loads(prototype_path.read_text())
evidence_document = json.loads(functions_path.read_text())
function_name_pattern = re.compile(r"\b(sep_[A-Za-z0-9_]+)\s*\(")
assembly_pattern = re.compile(
    r"\.type\s+(sep_[A-Za-z0-9_]+),@function\s*\n\1:",
)

reference = {
    function_name_pattern.search(item["prototype"]).group(1)
    for item in prototype_document["functions"]
}
defined_occurrences: list[str] = []
c_defined: set[str] = set()
for source_path in sorted((root / "src").rglob("*")):
    if not source_path.is_file():
        continue
    text = source_path.read_text()
    if source_path.suffix == ".c":
        lines = text.splitlines()
        for index, line in enumerate(lines):
            if not line or line[0].isspace():
                continue
            match = function_name_pattern.search(line)
            if match is None:
                continue
            declaration = line
            next_index = index + 1
            while "{" not in declaration and ";" not in declaration:
                declaration += "\n" + lines[next_index]
                next_index += 1
            brace = declaration.find("{")
            semicolon = declaration.find(";")
            if brace >= 0 and (semicolon < 0 or brace < semicolon):
                name = match.group(1)
                defined_occurrences.append(name)
                c_defined.add(name)
    elif source_path.suffix == ".S":
        defined_occurrences.extend(assembly_pattern.findall(text))

defined = set(defined_occurrences)
duplicate_definitions = sorted({
    name for name in defined if defined_occurrences.count(name) > 1
})
project_helpers = {
    "sep_mailbox_load_pair",
    "sep_mailbox_store_pair",
    "sep_protocol_build_response",
    "sep_protocol_dispatch_request",
}
implemented = reference & defined
unexpected = defined - reference - project_helpers
missing = reference - implemented


def collect_function_types(node: object, result: dict[str, set[str]]) -> None:
    if isinstance(node, dict):
        if node.get("kind") == "FunctionDecl" and "name" in node:
            result.setdefault(node["name"], set()).add(node["type"]["qualType"])
        for value in node.values():
            collect_function_types(value, result)
    elif isinstance(node, list):
        for value in node:
            collect_function_types(value, result)


clang = shutil.which("clang")
assert clang is not None
reference_ast = subprocess.run(
    [
        clang,
        "--target=aarch64-none-elf",
        "-std=c17",
        "-fms-extensions",
        "-x",
        "c-header",
        "-Xclang",
        "-ast-dump=json",
        "-fsyntax-only",
        str(research / "include" / "sep_recovered_types.h"),
    ],
    check=True,
    capture_output=True,
    text=True,
).stdout
reference_types: dict[str, set[str]] = {}
collect_function_types(json.loads(reference_ast), reference_types)

implementation_types: dict[str, set[str]] = {}
for source_path in sorted((root / "src").rglob("*.c")):
    implementation_ast = subprocess.run(
        [
            clang,
            "--target=aarch64-none-elf",
            "-std=c17",
            "-I",
            str(root / "include"),
            "-Xclang",
            "-ast-dump=json",
            "-fsyntax-only",
            str(source_path),
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    collect_function_types(json.loads(implementation_ast), implementation_types)

signature_mismatches = {
    name: {
        "expected": sorted(reference_types[name]),
        "actual": sorted(implementation_types.get(name, set())),
    }
    for name in sorted(c_defined & reference)
    if reference_types[name] != implementation_types.get(name, set())
}

report = {
    "schema_version": 1,
    "reference_inventory": (
        len(reference) + evidence_document["machine_atom_count"]
    ),
    "reference_functions": len(reference),
    "implemented_reference_functions": len(implemented),
    "missing_reference_functions": len(missing),
    "implementation_percent": round(len(implemented) * 100 / len(reference), 4),
    "internal_entries": evidence_document["machine_atom_count"],
    "duplicate_definitions": duplicate_definitions,
    "unexpected_sep_definitions": sorted(unexpected),
    "signature_mismatches": signature_mismatches,
    "implemented": sorted(implemented),
    "missing": sorted(missing),
}
(root / "build" / "coverage.json").write_text(
    json.dumps(report, indent=2, sort_keys=True) + "\n"
)

assert len(reference) == 725, len(reference)
assert evidence_document["machine_atom_count"] == 98
assert report["reference_inventory"] == 823
assert not duplicate_definitions, duplicate_definitions
assert not unexpected, unexpected
assert not signature_mismatches, signature_mismatches
assert not missing, missing
print(
    "OpenSEP interface compatibility: "
    f"{len(implemented)}/{len(reference)} entry points ({report['implementation_percent']:.4f}%)"
)
print(f"Reference inventory: {report['reference_inventory']} entries")
