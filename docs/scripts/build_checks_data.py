#!/usr/bin/env python3
"""Build docs/data/checks.json for the vulnerabilities index page.

Sources of truth:
  * categories and order  -> docs/content/vulnerabilities/_index.md (the
    "### Category" headings and their "- [Title](/vulnerabilities/slug/)" lists)
  * title and summary      -> each check's own page (H1 and the first sentence
    of its "## Description" section)
  * severities             -> the backend rules (every severity a rule can emit)

Run after adding or changing a check:

    python3 docs/scripts/build_checks_data.py
"""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VULN_DIR = ROOT / "docs" / "content" / "vulnerabilities"
OUT = ROOT / "docs" / "data" / "checks.json"
RULE_SOURCES = [
    ROOT / "backend" / "rules" / "security.py",
    ROOT / "backend" / "security_auditor.py",
    ROOT / "backend" / "main.py",
]
SEVERITY_ORDER = ["critical", "high", "medium", "low"]

# Severities that are computed at runtime (or emitted under a sibling type)
# and therefore not visible to the literal "type"/"severity" scan below.
DYNAMIC_SEVERITIES = {
    "artifact_exposure_risk": {"critical", "high", "low"},
    "unsafe_checkout": {"high", "medium"},
    "insecure_pull_request_target": {"critical", "high"},
    "long_term_cloud_credentials": {"high"},  # long_term_{aws,azure,gcp}_credentials
    "obfuscation_detection": {"critical", "high", "medium"},
    "trufflehog_secret_detected": {"critical", "high"},
    "untrusted_action_source": {"high", "medium"},
}


def emitted_severities() -> dict:
    found: dict = {}
    pattern = re.compile(r'"type":\s*"([a-z0-9_]+)",\s*\n\s*"severity":\s*"([a-z]+)"')
    for path in RULE_SOURCES:
        for rule_type, severity in pattern.findall(path.read_text()):
            found.setdefault(rule_type, set()).add(severity)
    for rule_type, severities in DYNAMIC_SEVERITIES.items():
        found.setdefault(rule_type, set()).update(severities)
    return found


def plain(text: str) -> str:
    text = re.sub(r"\[\^[^\]]+\]", "", text)                 # footnotes
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)    # links
    text = re.sub(r"[*_`]", "", text)                        # emphasis / code
    return re.sub(r"\s+", " ", text).strip()


def summary(markdown: str) -> str:
    match = re.search(r"^## Description\s*\n+(.+?)(?:\n\n|\n#)", markdown, re.S | re.M)
    if not match:
        # Pages without a Description heading open with an intro paragraph.
        match = re.search(r"^# [^\n]+\n+(?!#|\|)(.+?)(?:\n\n|\n#)", markdown, re.S | re.M)
    paragraph = plain(match.group(1)) if match else ""
    # Split on sentence ends, but not on an ellipsis such as "curl ... | bash".
    sentence = re.split(r"(?<!\.\.)(?<=[.!?])\s+(?=[A-Z])", paragraph)[0] if paragraph else ""
    return sentence if len(sentence) <= 170 else sentence[:167].rsplit(" ", 1)[0] + "…"


def main() -> None:
    severities = emitted_severities()
    index = (VULN_DIR / "_index.md").read_text()

    categories = []
    for block in re.split(r"^### ", index, flags=re.M)[1:]:
        name = block.splitlines()[0].strip()
        checks = []
        for title, slug in re.findall(r"^- \[([^\]]+)\]\(/vulnerabilities/([a-z0-9_]+)/\)", block, re.M):
            page = (VULN_DIR / f"{slug}.md").read_text()
            h1 = re.search(r"^# (.+)$", page, re.M)
            sev = sorted(severities.get(slug, set()), key=SEVERITY_ORDER.index)
            if not sev:
                raise SystemExit(f"No severity found for {slug}; add it to DYNAMIC_SEVERITIES")
            checks.append({
                "slug": slug,
                "title": h1.group(1).strip() if h1 else title,
                "summary": summary(page),
                "severity": sev[0],
                "severities": sev,
            })
        categories.append({
            "name": name,
            "id": re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-"),
            "checks": checks,
        })

    totals = {s: 0 for s in SEVERITY_ORDER}
    for category in categories:
        for check in category["checks"]:
            totals[check["severity"]] += 1

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({
        "total": sum(totals.values()),
        "totals": totals,
        "categories": categories,
    }, indent=2) + "\n")
    print(f"wrote {OUT.relative_to(ROOT)}: {sum(totals.values())} checks, {totals}")


if __name__ == "__main__":
    main()
