#!/usr/bin/env python3
"""Generate Markdown + HTML + CSV reports from Cycode CLI JSON scan output.

Produces up to three output formats from a single `cycode -o json scan` file:

  * Markdown  — short summary suitable for Azure Pipelines' `task.uploadsummary`
                or GitHub Actions' `$GITHUB_STEP_SUMMARY`.
                Written to stdout (or --md FILE).
  * HTML      — rich, self-contained interactive report (filterable, expandable
                descriptions, severity badges). Written to --html FILE.
  * CSV       — flat, Excel-friendly export of every finding with the 7 columns
                requested by customers. Written to --csv FILE.

Usage:
  cycode-summary.py cycode.json                         # Markdown to stdout
  cycode-summary.py cycode.json \
      --md  cycode-summary.md \
      --html cycode-report.html \
      --csv cycode-report.csv

Column mapping (HTML + CSV):
  Issue Name        — detection_details.policy_display_name
  Issue Description — detection_details.description (falls back to top-level message)
  Where             — detection_details.line / start_position
  File              — detection_details.file_path  (agent workspace prefix stripped)
  Metadata          — severity, type, CWE, OWASP, category, language(s)
  Mitigation        — detection_details.remediation_guidelines (Markdown from platform)
  Ref URL           — <console-base>/policies/<detection_rule_id>
                       (override base with CYCODE_CONSOLE_URL env var or --console-url)
"""
from __future__ import annotations

import argparse
import csv
import html
import json
import os
import re
import sys
import urllib.parse
from typing import Any

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info", "Unknown"]

SEVERITY_COLOR = {
    "Critical": "#b71c1c",
    "High":     "#e65100",
    "Medium":   "#f9a825",
    "Low":      "#1565c0",
    "Info":     "#546e7a",
    "Unknown":  "#37474f",
}

# Emoji indicators used in the Markdown summary for the ADO build summary tab.
# ADO's Markdown renderer strips <style>/<script> but renders emoji + basic HTML
# tags (<details>, <summary>, <table>) reliably.
SEVERITY_EMOJI = {
    "Critical": "🔴",
    "High":     "🟠",
    "Medium":   "🟡",
    "Low":      "🔵",
    "Info":     "⚪",
    "Unknown":  "⚫",
}


def extract_detections(data: Any) -> list[dict]:
    detections: list[dict] = []
    if isinstance(data, dict):
        for block in data.get("scan_results") or []:
            detections.extend(block.get("detections") or [])
        detections.extend(data.get("detections") or [])
    elif isinstance(data, list):
        detections = list(data)
    return detections


def normalize_file_path(path: str) -> str:
    """Strip CI agent workspace prefixes so paths read relative to repo root."""
    if not path:
        return ""
    # Normalize backslashes (Windows agents) so a single regex covers all OSes.
    normalized = path.replace("\\", "/")
    # ADO agent layouts:
    #   self-hosted (any OS):              /_work/<n>/s/<rest>
    #   Microsoft-hosted Linux/macOS:      /home/vsts/work/<n>/s/<rest>
    #   Microsoft-hosted Windows:          D:/a/<n>/s/<rest>
    #   Microsoft-hosted Windows (cycode): a/<n>/s/<rest>  — Cycode CLI strips
    #     the drive letter into a separate `commit_id` field on Windows, so
    #     the workspace prefix arrives without a leading slash.
    # `(?:^|/)` matches workspace pattern at string-start OR after a slash.
    m = re.search(r"(?:^|/)(?:_work|a|work)/\d+/s/(.+)$", normalized)
    if m:
        rest = m.group(1)
        # The centralized Cycode scan template checks out the consumer's repo
        # at s/_self (explicit path: modifier to avoid same-repo dedup with the
        # security-templates checkout). Strip that prefix so the displayed path
        # reads as a path inside the consumer's repo.
        if rest.startswith("_self/"):
            rest = rest[len("_self/"):]
        return rest
    # GitHub Actions: /home/runner/work/<repo>/<repo>/<rest>
    m = re.search(r"/runner/work/[^/]+/[^/]+/(.+)$", normalized)
    if m:
        return m.group(1)
    return normalized.lstrip("/")


def _combine_path(file_path: str, file_name: str) -> str:
    """Join file_path + file_name when Cycode splits them across both fields.

    Cycode CLI returns these fields in inconsistent shapes across scan types:
      - Secret (Windows): file_path = "a/1/s/_self/app/",  file_name = "api-tokens.js"
      - SAST (any):       file_path = "<full path>",       file_name = "" (or basename)
      - IaC:              file_path = "<full path>",       file_name = "<full path>"
      - SCA:              file_path = "Users/.../pkg.json", file_name = "/Users/.../pkg.json"
                           (same file, different leading-slash conventions)

    Goal: always emit a single normalized path. Detect when file_name is the
    same file as file_path (ignoring slash conventions) so we don't double it up.
    """
    fp = file_path or ""
    fn = file_name or ""
    if not fn:
        return fp
    if not fp:
        return fn
    # Compare with normalized slashes and no leading separators.
    fp_norm = fp.replace("\\", "/").lstrip("/")
    fn_norm = fn.replace("\\", "/").lstrip("/")
    # Same file (path == path, or path ends with the filename component).
    if fp_norm == fn_norm or fp_norm.endswith("/" + fn_norm):
        return fp
    # Otherwise file_name is just a basename — join with a single separator.
    sep = "" if fp.endswith(("/", "\\")) else "/"
    return f"{fp}{sep}{fn}"


def _extract_sca_fields(d: dict, dd: dict) -> dict:
    """Pull SCA-specific fields out of a Cycode detection.

    SCA detections have a different shape from secret/SAST/IaC: the package,
    version, advisory, and remediation hints live under detection_details.alert
    and at the top of detection_details (vulnerable_component, cvss_score, etc.).
    Returns an empty dict for non-SCA detections.
    """
    alert = dd.get("alert") or {}
    is_sca = (
        d.get("type") == "vulnerable_code_dependency"
        or dd.get("vulnerable_component")
        or alert.get("affected_package_name")
    )
    if not is_sca:
        return {}
    return {
        "package":         dd.get("vulnerable_component") or dd.get("package_name") or alert.get("affected_package_name") or "",
        "version":         dd.get("vulnerable_component_version") or dd.get("package_version") or alert.get("vulnerable_requirements") or "",
        "fixed_version":   alert.get("first_patched_version") or "",
        "summary":         alert.get("summary") or "",
        "cve":             dd.get("vulnerability_id") or alert.get("cve_identifier") or "",
        "ghsa":            alert.get("ghsa_identifier") or "",
        "cvss":            dd.get("cvss_score"),
        "epss":            dd.get("epss"),
        "ecosystem":       dd.get("package_ecosystem") or dd.get("ecosystem") or alert.get("ecosystem") or "",
        "build_tool":      dd.get("build_tool") or "",
        "manifest_file":   normalize_file_path(dd.get("manifest_file_path") or ""),
        "is_direct":       alert.get("is_direct_dependency") if alert.get("is_direct_dependency") is not None else dd.get("is_direct_dependency"),
        "is_dev":          alert.get("is_dev_dependency") if alert.get("is_dev_dependency") is not None else dd.get("is_dev_dependency"),
        "has_fix":         dd.get("has_fix_in_version"),
        "advisory":        (alert.get("description") or "").strip(),
        "dependency_path": dd.get("dependency_paths") or alert.get("dependency_paths") or "",
    }


def _extract_recommendation(advisory: str) -> str:
    """Pull the '## Recommendation' Markdown section out of an SCA advisory."""
    if not advisory:
        return ""
    m = re.search(r"##\s+Recommendation\s*\n+(.*?)(?=\n##\s|\Z)", advisory, re.DOTALL | re.IGNORECASE)
    return m.group(1).strip() if m else ""


def _extract_iac_fields(d: dict, dd: dict) -> dict:
    """Pull IaC-specific fields out of a Cycode detection.

    IaC detections expose platform (Dockerfile / Terraform / Kubernetes / etc.),
    cloud_provider, failure_property_path (which YAML/HCL key failed), and
    current_property_value (the offending value). Returns an empty dict when
    these don't apply.
    """
    platform = dd.get("platform") or dd.get("infra_provider") or ""
    if not platform and not dd.get("failure_property_path"):
        return {}
    return {
        "platform":       platform,
        "cloud_provider": dd.get("cloud_provider") or "",
        "property_path":  dd.get("failure_property_path") or "",
        "current_value":  dd.get("current_property_value"),
    }


def row_from_detection(d: dict) -> dict:
    dd = d.get("detection_details") or {}
    cwe = dd.get("cwe") or []
    owasp = dd.get("owasp") or []
    langs = dd.get("languages") or []
    metadata_parts = []
    if cwe:
        metadata_parts.append("CWE: " + "; ".join(cwe))
    if owasp:
        metadata_parts.append("OWASP: " + "; ".join(owasp))
    if dd.get("category"):
        metadata_parts.append(f"Category: {dd['category']}")
    if langs:
        metadata_parts.append("Languages: " + ", ".join(langs))
    raw_file_path = dd.get("file_path") or d.get("file_path") or ""
    raw_file_name = dd.get("file_name") or ""
    full_path = normalize_file_path(_combine_path(raw_file_path, raw_file_name))
    # Reduce file_name to basename. Some scanners (e.g. IaC) emit the full
    # agent path in file_name; the rendered "File Name" should always be
    # just the filename so it complements "File Path" without duplicating.
    if raw_file_name:
        display_name = raw_file_name.replace("\\", "/").rsplit("/", 1)[-1]
    else:
        display_name = full_path.rsplit("/", 1)[-1] if full_path else ""

    # SCA-specific enrichment.
    sca = _extract_sca_fields(d, dd)
    # IaC-specific enrichment.
    iac = _extract_iac_fields(d, dd)

    # Issue name: SCA findings get a much more useful identifier than the
    # generic policy_display_name.  Prefer "CVE-XXXX — package@version".
    issue_name = dd.get("policy_display_name") or d.get("detection_rule_id") or "Unnamed finding"
    if sca:
        bits = []
        if sca.get("cve"):
            bits.append(sca["cve"])
        elif sca.get("ghsa"):
            bits.append(sca["ghsa"])
        if sca.get("package"):
            pv = sca["package"]
            if sca.get("version"):
                pv += f"@{sca['version']}"
            bits.append(pv)
        if bits:
            issue_name = " — ".join(bits)
        elif sca.get("summary"):
            issue_name = sca["summary"]
        # Add SCA-flavored metadata to the joined metadata string too,
        # so HTML/CSV rendering sees something useful even without
        # SCA-specific columns.
        if sca.get("ecosystem"):
            metadata_parts.append(f"Ecosystem: {sca['ecosystem']}")
        if sca.get("cvss") is not None:
            metadata_parts.append(f"CVSS: {sca['cvss']}")
        if sca.get("is_dev") is True:
            metadata_parts.append("Scope: dev")
        elif sca.get("is_dev") is False:
            metadata_parts.append("Scope: prod")

    # Description: SCA advisory text under alert.description is richer than
    # detection_details.description. Use it when present.
    description = ""
    if sca and sca.get("advisory"):
        description = sca["advisory"]
    else:
        description = (dd.get("description") or d.get("message") or "").strip()

    # Remediation: prefer the standard fields. For SCA, extract the
    # "## Recommendation" Markdown section from the advisory when the
    # explicit fields are absent.
    remediation = (dd.get("remediation_guidelines") or dd.get("custom_remediation_guidelines") or "").strip()
    if not remediation and sca:
        remediation = _extract_recommendation(sca.get("advisory") or "")

    return {
        "severity":         d.get("severity") or "Unknown",
        "type":             d.get("type") or "?",
        "issue_name":       issue_name,
        "description":      description,
        "file":             full_path,
        "file_path":        full_path,
        "file_name":        display_name,
        "line":             dd.get("line") or d.get("line") or "",
        "metadata":         " | ".join(metadata_parts),
        "cwe":              "; ".join(cwe),
        "owasp":            "; ".join(owasp),
        "category":         dd.get("category") or "",
        "languages":        ", ".join(langs),
        "remediation":      remediation,
        "detection_rule_id": dd.get("detection_rule_id") or "",
        "policy_id":        dd.get("policy_id") or "",
        "id":               d.get("id") or "",
        "sca":              sca,  # empty dict for non-SCA detections
        "iac":              iac,  # empty dict for non-IaC detections
    }


def console_url(row: dict, base_url: str) -> str:
    base = base_url.rstrip("/")
    rule_id = row.get("detection_rule_id") or row.get("policy_id")
    if rule_id:
        return f"{base}/policies/{rule_id}"
    return base


def azure_file_url(row: dict, collection_uri: str, project: str, repo: str, ref: str) -> str:
    """Build a link to the file at the specific line in Azure DevOps."""
    file = row.get("file") or row.get("file_path") or ""
    if not (file and project and repo):
        return ""
    file = file.lstrip("/")
    project_path = urllib.parse.quote(project, safe="")
    url = f"{collection_uri.rstrip('/')}/{project_path}/_git/{repo}?path=/{file}"
    if ref:
        url += f"&version=GB{urllib.parse.quote(ref, safe='')}"
    if row.get("line"):
        url += f"&line={row['line']}"
    return url


def github_file_url(row: dict, server_url: str, repo: str, ref: str) -> str:
    """Build a link to the file at the specific line on GitHub.

    `repo` is the full owner/name (e.g. `octocat/Hello-World`); `ref` may be a
    branch name OR a commit SHA — both produce valid blob URLs.
    """
    file = row.get("file") or row.get("file_path") or ""
    if not (file and repo and ref):
        return ""
    file = file.lstrip("/")
    base = (server_url or "https://github.com").rstrip("/")
    url = f"{base}/{repo}/blob/{urllib.parse.quote(ref, safe='/')}/{urllib.parse.quote(file, safe='/')}"
    if row.get("line"):
        url += f"#L{row['line']}"
    return url


def violations_filtered_by_repo_url(repo_name: str, base_url: str) -> str:
    """URL to the Cycode Platform Violations page, filtered to Open status
    for a specific repository. Shared by the CLI summary (when --cycode-report
    is set) and the API-backed summary (always)."""
    base = base_url.rstrip("/")
    params = [
        ("f0", "status"),
        ("f0", "Open"),
        ("f1", "repository_name"),
        ("f1", repo_name),
        ("groupBy", "None"),
    ]
    qs = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
    return f"{base}/violations?{qs}"


def count_by_severity(rows: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["severity"]] = counts.get(r["severity"], 0) + 1
    return counts


def severity_sort_key(row: dict) -> tuple:
    try:
        idx = SEVERITY_ORDER.index(row["severity"])
    except ValueError:
        idx = len(SEVERITY_ORDER)
    return (idx, row["type"], row["file"], row["line"] or 0)


# ----------------------------- Markdown -----------------------------------

def _md_summary_line(r: dict, scan_type: str) -> str:
    """Per-type accordion summary line — concise headline for each finding.

    Note: ADO's Markdown renderer does NOT process ** inside a <summary>
    element (the asterisks render literally). Backticks for inline code
    DO render. So this line uses plain text + inline-code only.
    """
    file_path = r.get("file") or ""
    line = r.get("line") or ""
    loc = (
        f"`{file_path}:{line}`"
        if file_path and line and str(line) not in ("0", "-1")
        else f"`{file_path}`" if file_path else ""
    )
    issue = r.get("issue_name") or "Unknown"
    if scan_type == "sca" and r.get("sca"):
        # issue_name is already "CVE-XXXX — pkg@ver" from row_from_detection
        manifest = r["sca"].get("manifest_file") or file_path
        return f"{issue} — `{manifest}`" if manifest else issue
    if loc:
        return f"{issue} — {loc}"
    return issue


def _md_body_for_type(r: dict, scan_type: str) -> list[str]:
    """Return the body sections (already Markdown) for one finding's
    accordion — ordered to match the HTML column layout for that scan type."""
    sections: list[str] = []
    description = (r.get("description") or "").strip()
    remediation = (r.get("remediation") or "").strip()
    sca = r.get("sca") or {}
    iac = r.get("iac") or {}

    def _file_line() -> str:
        """Single-line **File:** entry. Renders as a labeled hyperlink when
        we have a VCS file URL, otherwise as plain `path:line` code."""
        file = r.get("file") or ""
        line = r.get("line") or ""
        url = r.get("vcs_file_url") or ""
        if not file:
            return ""
        label = f"{file}:{line}" if line and str(line) not in ("0", "-1") else file
        if url:
            return f"**File:** [`{label}`]({url})"
        return f"**File:** `{label}`"

    def _mitigation(label: str = "Mitigation", inline_limit: int = 300) -> str:
        """Render the mitigation text. Long mitigations (SAST guidance, etc.)
        go in a nested <details> so the parent accordion stays scannable."""
        if not remediation:
            return ""
        if len(remediation) <= inline_limit:
            return f"**{label}:**  \n{remediation}"
        # Nested details — blank lines around the content so ADO parses it as
        # Markdown rather than raw HTML.
        return (
            f"<details><summary><strong>{label}</strong> (click to expand)</summary>\n\n"
            f"{remediation}\n\n"
            f"</details>"
        )

    if scan_type == "secret":
        if description:
            sections.append(f"**Description:**  \n{description}")
        fl = _file_line()
        if fl: sections.append(fl)
        mit = _mitigation()
        if mit: sections.append(mit)
        return sections

    if scan_type == "sast":
        if description:
            sections.append(f"**Description:**  \n{description}")
        mit = _mitigation()
        if mit: sections.append(mit)
        fl = _file_line()
        if fl: sections.append(fl)
        # One-line meta — CWE · OWASP · Category · Language
        meta = []
        if r.get("cwe"):       meta.append(f"**CWE:** {r['cwe']}")
        if r.get("owasp"):     meta.append(f"**OWASP:** {r['owasp']}")
        if r.get("category"):  meta.append(f"**Category:** {r['category']}")
        if r.get("languages"): meta.append(f"**Language:** {r['languages']}")
        if meta:
            sections.append(" &middot; ".join(meta))
        return sections

    if scan_type == "sca":
        # SCA advisories include a "## Recommendation" section that we
        # extract separately into `remediation`. Strip it from the
        # description text so the same content doesn't appear twice
        # (once as an h2 inside Description, once labeled Mitigation).
        if description:
            description = re.sub(
                r"\n+##\s+Recommendation\s*\n+.*\Z",
                "",
                description,
                flags=re.DOTALL | re.IGNORECASE,
            ).strip()
        # Package Info block (column 2 in HTML)
        pkg = sca.get("package") or ""
        ver = sca.get("version") or ""
        pkg_lines = []
        if sca.get("ecosystem"):
            pkg_lines.append(f"**Build Tool:** `{sca['ecosystem']}`")
        if pkg:
            pkg_lines.append(
                f"**Vulnerable Package:** `{pkg}`" + (f" `{ver}`" if ver else "")
            )
        if sca.get("fixed_version"):
            pkg_lines.append(f"**Fixed Version:** `{sca['fixed_version']}`")
        elif sca.get("has_fix") is False:
            pkg_lines.append("**Fixed Version:** _no fix available_")
        if sca.get("is_direct") is True:    pkg_lines.append("**Dependency Type:** Direct")
        elif sca.get("is_direct") is False: pkg_lines.append("**Dependency Type:** Transitive")
        if sca.get("is_dev") is True:       pkg_lines.append("**Scope:** Dev")
        elif sca.get("is_dev") is False:    pkg_lines.append("**Scope:** Production")
        if sca.get("cve"):  pkg_lines.append(f"**CVE:** `{sca['cve']}`")
        if sca.get("ghsa"): pkg_lines.append(f"**GHSA:** `{sca['ghsa']}`")
        if sca.get("cvss") is not None: pkg_lines.append(f"**CVSS:** `{sca['cvss']}`")
        if sca.get("epss") is not None: pkg_lines.append(f"**EPSS:** `{sca['epss']*100:.2f}%`")
        if pkg_lines:
            sections.append("  \n".join(pkg_lines))
        # Dependency Path (column 3) — truncate to first 3
        if sca.get("dependency_path"):
            paths = [p.strip() for p in sca["dependency_path"].split(",") if p.strip()]
            head = paths[:3]
            line = "; ".join(f"`{p}`" for p in head)
            if len(paths) > 3:
                line += f" _(+{len(paths)-3} more)_"
            sections.append(f"**Dependency Path:** {line}")
        # Manifest (column 4)
        if sca.get("manifest_file"):
            sections.append(f"**Manifest File:** `{sca['manifest_file']}`")
        # Remediation (column 5): summary, then advisory + recommendation
        rem_parts: list[str] = []
        if sca.get("summary"):
            rem_parts.append(f"**Summary:** {sca['summary']}")
        if description and description != remediation:
            rem_parts.append(f"**Description:**  \n{description}")
        mit = _mitigation()
        if mit:
            rem_parts.append(mit)
        if rem_parts:
            sections.append("\n\n".join(rem_parts))
        return sections

    if scan_type == "iac":
        if description:
            sections.append(f"**Description:**  \n{description}")
        mit = _mitigation()
        if mit: sections.append(mit)
        fl = _file_line()
        if fl: sections.append(fl)
        # One-line references — Provider · Cloud · Property · Current Value · CWE · OWASP
        refs = []
        if iac.get("platform"):
            refs.append(f"**Provider:** `{iac['platform']}`")
        if iac.get("cloud_provider") and iac["cloud_provider"] != "common":
            refs.append(f"**Cloud:** `{iac['cloud_provider']}`")
        if iac.get("property_path"):
            refs.append(f"**Property:** `{iac['property_path']}`")
        if iac.get("current_value") is not None:
            refs.append(f"**Current Value:** `{iac['current_value']}`")
        if r.get("cwe"):   refs.append(f"**CWE:** {r['cwe']}")
        if r.get("owasp"): refs.append(f"**OWASP:** {r['owasp']}")
        if refs:
            sections.append(" &middot; ".join(refs))
        return sections

    # mixed / fallback — use the generic layout
    if description:
        sections.append(f"**Description:**  \n{description}")
    fl = _file_line()
    if fl: sections.append(fl)
    mit = _mitigation()
    if mit: sections.append(mit)
    return sections


_SCAN_TYPE_DISPLAY = {
    "secret": "Secret",
    "sast":   "SAST",
    "sca":    "SCA",
    "iac":    "IaC",
}


def render_markdown(
    rows: list[dict],
    base_url: str,
    artifact_hint: str = "",
    title: str = "",
    expand_limit: int = 100,
    repo_name: str = "",
    branch: str = "",
    scan_type_name: str = "",
    scan_mode: str = "",
    base_commit: str = "",
    include_title: bool = True,
) -> str:
    """Rich Markdown: header metadata, severity roll-up, per-finding accordion.

    Each finding's body is laid out per-scan-type to mirror the HTML report's
    column structure (Secret: Type+File+Description; SAST: Rule+Desc+Mit+File+CWE;
    SCA: Package Info + Dependency Path + Manifest + Remediation; IaC: Rule +
    File + Desc+Mit + References)."""
    counts = count_by_severity(rows)
    lines: list[str] = []
    scan_type = _detect_scan_type(rows)

    # Type-specific title — Cycode Secret Scan / SAST Scan / SCA Scan / IaC Scan.
    # Suppressed in the pipeline (via include_title=False) because ADO already
    # derives a section heading from the uploaded summary's file name.
    if include_title:
        if not title:
            display_name = _SCAN_TYPE_DISPLAY.get(scan_type) or _SCAN_TYPE_DISPLAY.get(scan_type_name)
            title = f"Cycode {display_name} Scan" if display_name else "Cycode Scan Summary"
        lines.append(f"## {title}")
        lines.append("")

    # Metadata header — Repo / Branch / Scan Type / Scan Mode so reviewers
    # know the context without leaving the build summary tab.
    meta_bits: list[str] = []
    if repo_name:
        meta_bits.append(f"**Repo:** `{repo_name}`")
    if branch:
        meta_bits.append(f"**Branch:** `{branch}`")
    if scan_type_name:
        meta_bits.append(f"**Scan Type:** `{scan_type_name}`")
    if scan_mode:
        mode_display = scan_mode
        if scan_mode == "diff":
            mode_display = "diff" + (f" (since `{base_commit[:7]}`)" if base_commit else "")
        elif scan_mode == "full":
            mode_display = "full (entire repository tree)"
        meta_bits.append(f"**Scan Mode:** {mode_display}")
    if meta_bits:
        lines.append(" &middot; ".join(meta_bits))
        lines.append("")

    # Single-line summary: Total + per-severity counts on one row.
    present_sevs = [s for s in SEVERITY_ORDER if counts.get(s)]
    summary_parts = [f"**Total findings:** {len(rows)}"]
    if present_sevs:
        summary_parts.extend(
            f"{SEVERITY_EMOJI[s]} **{s}:** {counts[s]}" for s in present_sevs
        )
    lines.append(" &middot; ".join(summary_parts))
    lines.append("")

    if not rows:
        return "\n".join(lines)

    lines.append("## Findings")
    lines.append("")

    shown = 0
    truncated = False
    for sev in SEVERITY_ORDER:
        group = [r for r in rows if r["severity"] == sev]
        if not group:
            continue
        lines.append(f"### {SEVERITY_EMOJI.get(sev, '')} {sev} ({len(group)})")
        lines.append("")
        for r in group:
            if shown >= expand_limit:
                truncated = True
                break
            shown += 1

            summary_line = _md_summary_line(r, scan_type)
            body_sections = _md_body_for_type(r, scan_type)

            lines.append(f"<details><summary>{summary_line}</summary>")
            lines.append("")
            lines.append("\n\n".join(body_sections))
            lines.append("")
            lines.append("</details>")
            lines.append("")
        if shown >= expand_limit:
            break

    if truncated:
        lines.append(
            f"_Showing first {expand_limit} of {len(rows)} findings. "
            f"See the full report in the **{artifact_hint or 'build'}** artifact._"
        )
        lines.append("")

    return "\n".join(lines)


# ------------------------------- HTML -------------------------------------

# ----- HTML rendering helpers (per-scan-type column layouts) ----------------
#
# Each Cycode scan type carries a different field shape. The HTML report
# mirrors the layout used by the Cycode ADO marketplace extension so that
# customers see consistent column sets regardless of which surface produced
# the report.
#
# Secret  : Severity | Secret Type | File & Line | Description
# SAST    : Severity | Rule / Policy | Description & Mitigation | File & Line | CWE / Language
# SCA     : Severity | Package Info | Dependency Path | Manifest File | Remediation
# IaC     : Severity | Rule / CVE | File | Description & Mitigation | References

CSS_BLOCK = """
  :root{--bg:#f7f8fa;--fg:#212121;--muted:#546e7a;--card:#fff;--border:#e0e3e7;--accent:#1565c0}
  *{box-sizing:border-box}
  body{margin:0;padding:24px;background:var(--bg);color:var(--fg);
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    font-size:14px;line-height:1.45}
  h1{margin:0 0 8px;font-size:22px}
  .meta{color:var(--muted);margin-bottom:20px}
  .summary-grid{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:0}
  .summary-section{margin-bottom:16px}
  .summary-section>summary{cursor:pointer;font-size:12px;font-weight:600;text-transform:uppercase;
    letter-spacing:.5px;color:var(--muted);list-style:none;user-select:none;padding:4px 0;
    display:inline-flex;align-items:center;gap:4px}
  .summary-section>summary::-webkit-details-marker{display:none}
  .summary-section>summary::before{content:"\\25B8";font-size:10px}
  .summary-section[open]>summary::before{content:"\\25BE"}
  .summary-section>summary~*{margin-top:8px}
  .summary-card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:12px 16px;min-width:110px}
  .summary-card .label{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.4px}
  .summary-card .value{font-size:22px;font-weight:600;margin-top:2px}
  .controls{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px;align-items:center}
  .controls input,.controls select{padding:7px 10px;border:1px solid var(--border);border-radius:6px;font-size:13px;background:#fff}
  .controls input{flex:1;min-width:200px}
  .findings{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--border);border-radius:8px;overflow:hidden}
  .findings thead th{text-align:left;padding:10px 12px;font-size:12px;text-transform:uppercase;letter-spacing:.4px;color:var(--muted);background:#eceff1;border-bottom:1px solid var(--border)}
  .findings tbody td{padding:12px;vertical-align:top;border-bottom:1px solid var(--border)}
  .findings tbody tr:last-child td{border-bottom:none}
  .findings tbody tr.hidden{display:none}
  .sev{display:inline-block;padding:2px 10px;border-radius:10px;color:#fff;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.4px;white-space:nowrap}
  .file{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;word-break:break-all}
  .line{color:var(--muted)}
  .meta-col{color:var(--muted);font-size:12.5px}
  details{margin-top:6px}
  details summary{cursor:pointer;color:var(--accent);font-size:12.5px;user-select:none;list-style:none}
  details summary::-webkit-details-marker{display:none}
  details summary::before{content:"\\25B8 ";color:var(--accent)}
  details[open] summary::before{content:"\\25BE "}
  details .content{margin-top:6px;padding:10px 12px;background:#fafbfc;border-left:3px solid var(--accent);border-radius:4px;font-size:13px;white-space:pre-wrap}
  .empty{text-align:center;padding:40px;color:var(--muted)}
  .sortable{cursor:pointer;user-select:none}
  .sortable:hover{background:#dde0e4!important}
  .sort-icon{display:inline-block;margin-left:4px;font-size:10px;color:#b0bec5}
  .sortable.sort-asc .sort-icon::after{content:"\\25B2";color:var(--accent)}
  .sortable.sort-desc .sort-icon::after{content:"\\25BC";color:var(--accent)}
  .sortable:not(.sort-asc):not(.sort-desc) .sort-icon::after{content:"\\2195"}
  .pkg-block div{margin-bottom:2px}
  footer{margin-top:20px;color:var(--muted);font-size:12px}
  footer a{color:var(--accent)}
"""


def _detect_scan_type(rows: list[dict]) -> str:
    """Detect the primary scan type from the rows.

    Returns one of 'secret', 'sast', 'sca', 'iac', or 'mixed'. The pipeline
    template generates one report per scan type so a single dominant type is
    the common case; 'mixed' falls back to a generic column layout if a
    report somehow contains multiple types.
    """
    types = set()
    for r in rows:
        if r.get("sca"):
            types.add("sca")
            continue
        if r.get("iac"):
            types.add("iac")
            continue
        # Heuristic: detection top-level `type` field.
        t = (r.get("type") or "").lower()
        if t == "sast":
            types.add("sast")
        elif t in ("vulnerable_code_dependency",) or "license" in t:
            types.add("sca")
        elif r.get("file_path", "").endswith((".tf", ".yaml", ".yml", "Dockerfile")) and r.get("category"):
            # Best-effort hint when iac dict isn't populated.
            types.add("iac")
        else:
            # Cycode secret detections have type strings like "stripe-api-key",
            # "aws-access-key-id", etc. — many distinct values.
            types.add("secret")
    if len(types) == 1:
        return next(iter(types))
    return "mixed"


def _headers_for_type(scan_type: str) -> str:
    """Return the table column <th>s for the given scan type."""
    si = '<span class="sort-icon"></span>'
    th = lambda idx, text, width=None: (
        f'<th data-col-idx="{idx}" class="sortable"'
        + (f' style="width:{width}px"' if width else "")
        + f'>{text}{si}</th>'
    )
    if scan_type == "secret":
        return (
            th(0, "Severity", 110)
            + th(1, "Secret Type", 200)
            + th(2, "File &amp; Line", 280)
            + th(3, "Description")
        )
    if scan_type == "sast":
        return (
            th(0, "Severity", 110)
            + th(1, "Rule / Policy")
            + th(2, "Description &amp; Mitigation")
            + th(3, "File &amp; Line", 260)
            + th(4, "CWE / Language", 200)
        )
    if scan_type == "sca":
        return (
            th(0, "Severity", 110)
            + th(1, "Package Info", 250)
            + th(2, "Dependency Path", 360)
            + th(3, "Manifest File", 220)
            + th(4, "Remediation")
        )
    if scan_type == "iac":
        return (
            th(0, "Severity", 110)
            + th(1, "Rule / CVE")
            + th(2, "File", 240)
            + th(3, "Description &amp; Mitigation")
            + th(4, "References", 180)
        )
    # mixed / fallback
    return (
        th(0, "Severity", 110)
        + th(1, "Issue")
        + th(2, "Description")
        + th(3, "File &amp; Line", 260)
        + th(4, "Details", 220)
    )


def _row_for_type(r: dict, scan_type: str) -> str:
    """Render one finding row in the column layout for `scan_type`."""
    sev = r.get("severity") or "Unknown"
    sev_color = SEVERITY_COLOR.get(sev, "#546e7a")
    sev_rank = SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else len(SEVERITY_ORDER)
    sev_cell = f'<td><span class="sev" style="background:{sev_color};">{html.escape(sev)}</span></td>'

    file_path = r.get("file") or r.get("file_path") or ""
    line = r.get("line") or ""
    line_html = (
        f'<div class="line">Line {html.escape(str(line))}</div>'
        if line and str(line) not in ("0", "-1") else ""
    )
    file_link = r.get("vcs_file_url") or ""
    file_inner = (
        f'<a href="{html.escape(file_link)}" target="_blank">{html.escape(file_path)}</a>'
        if file_link and file_path else html.escape(file_path or "unknown")
    )
    file_cell = f'<td><div class="file">{file_inner}</div>{line_html}</td>'

    description = r.get("description") or ""
    remediation = r.get("remediation") or ""

    def desc_with_full(short_limit: int = 200, mit_limit: int = 180) -> str:
        parts = []
        short = description[:short_limit] + ("…" if len(description) > short_limit else "")
        parts.append(f'<div>{html.escape(short)}</div>')
        if description and len(description) > short_limit:
            parts.append(
                f'<details><summary>Full description</summary>'
                f'<div class="content">{html.escape(description)}</div></details>'
            )
        if remediation:
            rem_short = remediation[:mit_limit] + ("…" if len(remediation) > mit_limit else "")
            parts.append(f'<div style="margin-top:4px;color:var(--muted);font-size:12px">{html.escape(rem_short)}</div>')
            if len(remediation) > mit_limit:
                parts.append(
                    f'<details><summary>Mitigation guidance</summary>'
                    f'<div class="content">{html.escape(remediation)}</div></details>'
                )
        return "".join(parts)

    # Searchable haystack — populated with the per-type fields so the search
    # box can match package/CVE/platform/etc.
    haystack_parts = [
        sev, r.get("type", ""), r.get("issue_name", ""), description,
        file_path, str(line), r.get("cwe", ""), r.get("owasp", ""),
        r.get("category", ""), r.get("languages", ""), remediation,
    ]
    sca = r.get("sca") or {}
    iac = r.get("iac") or {}
    if sca:
        haystack_parts += [
            sca.get("package", ""), sca.get("version", ""),
            sca.get("fixed_version", ""), sca.get("cve", ""),
            sca.get("ghsa", ""), sca.get("ecosystem", ""),
            sca.get("summary", ""), sca.get("dependency_path", ""),
        ]
    if iac:
        haystack_parts += [
            iac.get("platform", ""), iac.get("cloud_provider", ""),
            iac.get("property_path", ""), str(iac.get("current_value") or ""),
        ]
    haystack = " ".join(str(x) for x in haystack_parts).lower()

    # Per-type data-attributes for filter dropdowns.
    direct_attr = ""
    dev_attr = ""
    if sca:
        if sca.get("is_direct") is True:   direct_attr = "direct"
        elif sca.get("is_direct") is False: direct_attr = "indirect"
        if sca.get("is_dev") is True:       dev_attr = "yes"
        elif sca.get("is_dev") is False:    dev_attr = "no"

    tr_attrs = (
        f'data-severity="{html.escape(sev)}" data-sev-rank="{sev_rank}" '
        f'data-type="{html.escape(r.get("type") or "")}" '
        f'data-direct="{direct_attr}" data-dev="{dev_attr}" '
        f'data-search="{html.escape(haystack)}"'
    )

    if scan_type == "secret":
        secret_type = r.get("issue_name") or "Unknown"
        return (
            f'<tr {tr_attrs}>{sev_cell}'
            f'<td><strong>{html.escape(secret_type)}</strong></td>'
            f'{file_cell}'
            f'<td>{desc_with_full(200, 180)}</td>'
            '</tr>'
        )
    if scan_type == "sast":
        rule = r.get("issue_name") or "Unknown"
        cwe = r.get("cwe") or ""
        owasp = r.get("owasp") or ""
        langs = r.get("languages") or ""
        meta = []
        if cwe:   meta.append(f"<div><strong>CWE:</strong> {html.escape(cwe)}</div>")
        if owasp: meta.append(f"<div><strong>OWASP:</strong> {html.escape(owasp)}</div>")
        if langs: meta.append(f"<div><strong>Lang:</strong> {html.escape(langs)}</div>")
        meta_html = "".join(meta) or '<span style="color:var(--muted)">—</span>'
        return (
            f'<tr {tr_attrs}>{sev_cell}'
            f'<td><strong>{html.escape(rule)}</strong></td>'
            f'<td>{desc_with_full(200, 180)}</td>'
            f'{file_cell}'
            f'<td class="meta-col">{meta_html}</td>'
            '</tr>'
        )
    if scan_type == "sca":
        pkg = sca.get("package") or ""
        ver = sca.get("version") or ""
        fixed = sca.get("fixed_version") or ""
        pkg_disp = f"{pkg}@{ver}" if pkg and ver else (pkg or "Unknown")
        eco = sca.get("ecosystem") or ""
        cve = sca.get("cve") or ""
        ghsa = sca.get("ghsa") or ""
        cvss = sca.get("cvss")
        epss = sca.get("epss")
        is_direct = sca.get("is_direct")
        is_dev = sca.get("is_dev")
        pkg_block = ['<div class="pkg-block">']
        if eco:        pkg_block.append(f"<div><strong>Build Tool:</strong> {html.escape(eco)}</div>")
        pkg_block.append(f"<div><strong>Package:</strong> <code>{html.escape(pkg_disp)}</code></div>")
        if is_direct is True:   pkg_block.append("<div><strong>Direct:</strong> Yes</div>")
        elif is_direct is False: pkg_block.append("<div><strong>Direct:</strong> No</div>")
        if is_dev is True:       pkg_block.append("<div><strong>Dev:</strong> Yes</div>")
        elif is_dev is False:    pkg_block.append("<div><strong>Dev:</strong> No</div>")
        if cve:        pkg_block.append(f"<div><strong>CVE:</strong> <code>{html.escape(cve)}</code></div>")
        if ghsa:       pkg_block.append(f"<div><strong>GHSA:</strong> <code>{html.escape(ghsa)}</code></div>")
        if cvss is not None:  pkg_block.append(f"<div><strong>CVSS:</strong> {html.escape(str(cvss))}</div>")
        if epss is not None:  pkg_block.append(f"<div><strong>EPSS:</strong> {epss*100:.2f}%</div>")
        pkg_block.append("</div>")
        pkg_html = "".join(pkg_block)

        dep = sca.get("dependency_path") or ""
        if dep:
            paths = [p.strip() for p in dep.split(",") if p.strip()]
            head = paths[:5]
            dep_lines = "".join(f'<div class="file" style="font-size:11.5px">{html.escape(p)}</div>' for p in head)
            if len(paths) > 5:
                dep_lines += f'<div style="color:var(--muted);font-size:11.5px">…+{len(paths)-5} more paths</div>'
            dep_html = dep_lines
        else:
            dep_html = '<span style="color:var(--muted)">—</span>'

        manifest = sca.get("manifest_file") or ""
        manifest_cell = (
            f'<td><div class="file">{html.escape(manifest)}</div></td>'
            if manifest else '<td><span style="color:var(--muted)">—</span></td>'
        )

        summary_text = sca.get("summary") or ""
        rem_parts = []
        if summary_text:
            rem_parts.append(f'<div style="margin-bottom:6px"><strong>{html.escape(summary_text)}</strong></div>')
        if remediation:
            rem_short = remediation[:200] + ("…" if len(remediation) > 200 else "")
            rem_parts.append(f"<div>{html.escape(rem_short)}</div>")
            if len(remediation) > 200:
                rem_parts.append(
                    f'<details><summary>Full guidance</summary>'
                    f'<div class="content">{html.escape(remediation)}</div></details>'
                )
        if description and (not remediation or remediation != description):
            desc_short = description[:200] + ("…" if len(description) > 200 else "")
            rem_parts.append(f'<div style="margin-top:4px;color:var(--muted);font-size:12px">{html.escape(desc_short)}</div>')
            if len(description) > 200:
                rem_parts.append(
                    f'<details><summary>Full description</summary>'
                    f'<div class="content">{html.escape(description)}</div></details>'
                )
        if not rem_parts:
            rem_parts.append('<span style="color:var(--muted)">—</span>')

        return (
            f'<tr {tr_attrs}>{sev_cell}'
            f'<td>{pkg_html}</td>'
            f'<td>{dep_html}</td>'
            f'{manifest_cell}'
            f'<td>{"".join(rem_parts)}</td>'
            '</tr>'
        )
    if scan_type == "iac":
        rule = r.get("issue_name") or "Unknown"
        refs = []
        if iac.get("platform"):    refs.append(f"<div><strong>Provider:</strong> {html.escape(str(iac['platform']))}</div>")
        if iac.get("cloud_provider") and iac["cloud_provider"] != "common":
            refs.append(f"<div><strong>Cloud:</strong> {html.escape(str(iac['cloud_provider']))}</div>")
        if iac.get("property_path"): refs.append(f"<div><strong>Property:</strong> <code>{html.escape(str(iac['property_path']))}</code></div>")
        if iac.get("current_value") is not None:
            refs.append(f"<div><strong>Current:</strong> <code>{html.escape(str(iac['current_value']))}</code></div>")
        if r.get("cwe"):   refs.append(f"<div><strong>CWE:</strong> {html.escape(r['cwe'])}</div>")
        if r.get("owasp"): refs.append(f"<div><strong>OWASP:</strong> {html.escape(r['owasp'])}</div>")
        refs_html = "".join(refs) or '<span style="color:var(--muted)">—</span>'
        return (
            f'<tr {tr_attrs}>{sev_cell}'
            f'<td><strong>{html.escape(rule)}</strong></td>'
            f'{file_cell}'
            f'<td>{desc_with_full(200, 180)}</td>'
            f'<td class="meta-col">{refs_html}</td>'
            '</tr>'
        )
    # mixed fallback
    return (
        f'<tr {tr_attrs}>{sev_cell}'
        f'<td><strong>{html.escape(r.get("issue_name") or "")}</strong></td>'
        f'<td>{desc_with_full(200, 180)}</td>'
        f'{file_cell}'
        f'<td class="meta-col"><span style="color:var(--muted)">—</span></td>'
        '</tr>'
    )


def render_html(
    rows: list[dict],
    base_url: str,
    scan_types: list[str],
    repo_name: str = "",
    branch: str = "",
    commit: str = "",
    scan_path: str = "",
) -> str:
    """Render the HTML report in the customer-facing layout used by the
    Cycode ADO marketplace extension. Per-type column structure, summary
    cards, sortable headers, severity badges, and a client-side filter bar.
    """
    import datetime

    scan_type = _detect_scan_type(rows)

    counts = count_by_severity(rows)
    present_sevs = [s for s in SEVERITY_ORDER if counts.get(s)]

    # Overall summary cards
    summary_cards = [
        f'<div class="summary-card"><div class="label">Total</div>'
        f'<div class="value">{len(rows)}</div></div>'
    ]
    for sev in present_sevs:
        color = SEVERITY_COLOR.get(sev, "#000")
        summary_cards.append(
            f'<div class="summary-card"><div class="label">{html.escape(sev)}</div>'
            f'<div class="value" style="color:{color};">{counts[sev]}</div></div>'
        )

    # Severity filter options
    severity_options = "\n    ".join(
        f'<option value="{html.escape(s)}">{html.escape(s)}</option>' for s in present_sevs
    )

    # SCA-specific filters (only shown for SCA reports)
    sca_filters = ""
    if scan_type == "sca":
        sca_filters = (
            '<select id="direct-filter">'
            '<option value="">Direct &amp; Indirect</option>'
            '<option value="direct">Direct only</option>'
            '<option value="indirect">Indirect only</option>'
            '</select>'
            '<select id="dev-filter">'
            '<option value="">All (incl. dev)</option>'
            '<option value="no">Non-dev only</option>'
            '<option value="yes">Dev only</option>'
            '</select>'
        )

    # Build header + rows in the per-type column layout
    headers = _headers_for_type(scan_type)
    row_html_parts = [_row_for_type(r, scan_type) for r in rows]
    if not row_html_parts:
        row_html_parts.append('<tr><td colspan="10" class="empty">No findings.</td></tr>')

    # Meta line below the title
    meta_line1_parts: list[str] = []
    if repo_name:   meta_line1_parts.append(f"Repo: <strong>{html.escape(repo_name)}</strong>")
    if branch:      meta_line1_parts.append(f"Branch: <strong>{html.escape(branch)}</strong>")
    if commit:      meta_line1_parts.append(f"Commit: <code>{html.escape(commit[:7])}</code>")
    meta_line1 = " &middot; ".join(meta_line1_parts)
    meta_line2_parts: list[str] = []
    if scan_path:   meta_line2_parts.append(f"Scan path: <code>{html.escape(scan_path)}</code>")
    if scan_types:  meta_line2_parts.append(f"Scan type(s): <strong>{html.escape(', '.join(scan_types))}</strong>")
    meta_line2 = " &middot; ".join(meta_line2_parts)

    generated_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Cycode Security Scan Results</title>
<style>{CSS_BLOCK}</style>
</head>
<body>
<h1>Cycode Security Scan Results</h1>
<div class="meta">
  {meta_line1}{'<br>' if meta_line1 and meta_line2 else ''}{meta_line2}
</div>

<details class="summary-section" open>
  <summary>Overall Summary</summary>
  <div class="summary-grid">
    {chr(10).join(summary_cards)}
  </div>
</details>

<div class="controls">
  <input id="search" type="search" placeholder="Search findings…">
  <select id="severity-filter">
    <option value="">All severities</option>
    {severity_options}
  </select>
  {sca_filters}
  <span id="shown-count" style="color:var(--muted);font-size:12px"></span>
</div>

<table class="findings">
  <thead><tr>{headers}</tr></thead>
  <tbody>
    {chr(10).join(row_html_parts)}
  </tbody>
</table>

<footer>
  Generated {generated_at} from <code>cycode -o json scan</code> output.
  Console base: <a href="{html.escape(base_url)}">{html.escape(base_url)}</a>.
</footer>

<script>
(function() {{
  var rows = document.querySelectorAll('.findings tbody tr[data-severity]');
  var search = document.getElementById('search');
  var sevFilter = document.getElementById('severity-filter');
  var directFilter = document.getElementById('direct-filter');
  var devFilter = document.getElementById('dev-filter');
  var shownCount = document.getElementById('shown-count');

  function apply() {{
    var q = (search && search.value || '').trim().toLowerCase();
    var sev = sevFilter ? sevFilter.value : '';
    var direct = directFilter ? directFilter.value : '';
    var dev = devFilter ? devFilter.value : '';
    var shown = 0;
    rows.forEach(function(tr) {{
      var hs = tr.getAttribute('data-search') || '';
      var rSev = tr.getAttribute('data-severity') || '';
      var rDirect = tr.getAttribute('data-direct') || '';
      var rDev = tr.getAttribute('data-dev') || '';
      var match =
        (!q || hs.indexOf(q) !== -1) &&
        (!sev || rSev === sev) &&
        (!direct || rDirect === direct) &&
        (!dev || rDev === dev);
      tr.classList.toggle('hidden', !match);
      if (match) shown++;
    }});
    if (shownCount) shownCount.textContent = 'Showing ' + shown + ' of ' + rows.length;
  }}
  if (search) search.addEventListener('input', apply);
  if (sevFilter) sevFilter.addEventListener('change', apply);
  if (directFilter) directFilter.addEventListener('change', apply);
  if (devFilter) devFilter.addEventListener('change', apply);
  apply();

  // Sortable column headers
  var table = document.querySelector('.findings');
  var tbody = table ? table.querySelector('tbody') : null;
  if (tbody) {{
    var headers = table.querySelectorAll('thead th[data-col-idx]');
    var sortCol = 0, sortDir = 1;
    function doSort() {{
      var rs = Array.prototype.slice.call(tbody.querySelectorAll('tr[data-severity]'));
      rs.sort(function(a, b) {{
        var av, bv;
        if (sortCol === 0) {{
          av = parseInt(a.getAttribute('data-sev-rank') || '99', 10);
          bv = parseInt(b.getAttribute('data-sev-rank') || '99', 10);
          return sortDir * (av - bv);
        }}
        var ac = a.cells[sortCol], bc = b.cells[sortCol];
        av = (ac ? (ac.textContent || '') : '').trim().toLowerCase();
        bv = (bc ? (bc.textContent || '') : '').trim().toLowerCase();
        return sortDir * (av < bv ? -1 : av > bv ? 1 : 0);
      }});
      rs.forEach(function(r) {{ tbody.appendChild(r); }});
      headers.forEach(function(th) {{
        th.classList.remove('sort-asc', 'sort-desc');
        if (parseInt(th.getAttribute('data-col-idx'), 10) === sortCol) {{
          th.classList.add(sortDir === 1 ? 'sort-asc' : 'sort-desc');
        }}
      }});
    }}
    headers.forEach(function(th) {{
      th.addEventListener('click', function() {{
        var col = parseInt(th.getAttribute('data-col-idx'), 10);
        sortDir = sortCol === col ? -sortDir : 1;
        sortCol = col;
        doSort();
      }});
    }});
    doSort();
  }}
}})();
</script>
</body>
</html>
"""


# -------------------------------- CSV -------------------------------------

CSV_COLUMNS = [
    "severity",
    "type",
    "issue_name",
    "description",
    "file",
    "line",
    "cwe",
    "owasp",
    "category",
    "languages",
    "mitigation",
    "console_url",
    "detection_rule_id",
    "policy_id",
    "detection_id",
]


def write_csv(rows: list[dict], path: str, base_url: str) -> None:
    """Write a single-sheet CSV of all findings.

    The schema is intentionally a superset across scan types — SCA columns
    are empty for non-SCA rows, and vice versa for IaC. Customers filtering
    in Excel can ignore the columns they don't need; columns that always
    have data for some type are the customer-facing payoff.
    """
    def _yn(v):
        if v is True: return "Yes"
        if v is False: return "No"
        return ""

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
        writer.writerow([
            "Severity", "Type", "Issue Name", "Issue Description",
            "File", "Line",
            # Common metadata
            "CWE", "OWASP", "Category", "Languages",
            # SCA-specific
            "Package", "Version", "Fixed Version", "Ecosystem",
            "CVE", "GHSA", "CVSS", "EPSS",
            "Direct Dependency", "Dev Dependency", "Manifest",
            "Dependency Path", "Summary",
            # IaC-specific
            "Platform", "Cloud Provider", "Property Path", "Current Value",
            # Tail
            "Mitigation", "Console URL",
            "Detection Rule ID", "Policy ID", "Detection ID",
        ])
        for r in rows:
            sca = r.get("sca") or {}
            iac = r.get("iac") or {}
            writer.writerow([
                r["severity"], r["type"], r["issue_name"], r["description"],
                r["file"], r["line"],
                r["cwe"], r["owasp"], r["category"], r["languages"],
                # SCA
                sca.get("package", ""),
                sca.get("version", ""),
                sca.get("fixed_version", ""),
                sca.get("ecosystem", ""),
                sca.get("cve", ""),
                sca.get("ghsa", ""),
                "" if sca.get("cvss") is None else sca["cvss"],
                "" if sca.get("epss") is None else sca["epss"],
                _yn(sca.get("is_direct")),
                _yn(sca.get("is_dev")),
                sca.get("manifest_file", ""),
                sca.get("dependency_path", ""),
                sca.get("summary", ""),
                # IaC
                iac.get("platform", ""),
                iac.get("cloud_provider", ""),
                iac.get("property_path", ""),
                "" if iac.get("current_value") is None else iac["current_value"],
                # Tail
                r["remediation"], console_url(r, base_url),
                r["detection_rule_id"], r["policy_id"], r["id"],
            ])


# ------------------------------- main -------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("input_json")
    parser.add_argument("--md", help="Write Markdown here (default: stdout)")
    parser.add_argument("--html", help="Write HTML report here")
    parser.add_argument("--csv", help="Write CSV export here")
    parser.add_argument(
        "--console-url",
        default=os.environ.get("CYCODE_CONSOLE_URL", "https://app.cycode.com"),
        help="Base URL of the Cycode console (default: $CYCODE_CONSOLE_URL or https://app.cycode.com)",
    )
    parser.add_argument(
        "--artifact-hint",
        default=os.environ.get("CYCODE_ARTIFACT_NAME", "cycode-report"),
        help="Artifact name to reference in the Markdown summary (default: $CYCODE_ARTIFACT_NAME or cycode-report)",
    )
    parser.add_argument(
        "--cycode-report",
        default=os.environ.get("REPO_NAME"),
        metavar="REPO_NAME",
        help="Bare repo name as stored in Cycode's RIG. When set, the Markdown summary includes "
             "a prominent link to the Cycode Console Violations view pre-filtered to this repo "
             "(default: $REPO_NAME if set)",
    )
    parser.add_argument(
        "--no-title",
        action="store_true",
        default=os.environ.get("CYCODE_NO_TITLE") == "1",
        help="Suppress the H2 title at the top of the Markdown report. Use when ADO "
             "is auto-deriving a section heading from the file name to avoid duplication.",
    )
    args = parser.parse_args()

    # Explicit UTF-8 — Windows Python defaults to cp1252 and chokes on
    # non-Latin-1 bytes in Cycode JSON output (file paths, messages, etc.).
    with open(args.input_json, encoding="utf-8") as f:
        raw = f.read().strip()
    if not raw:
        # Empty input — treat as "no findings". This happens when an upstream
        # cycode scan step writes nothing to stdout (e.g. diff scan over an
        # empty commit range, or CLI shortcut paths). Render an empty report
        # rather than crashing the build.
        data = {"scan_results": []}
    else:
        data = json.loads(raw)

    detections = extract_detections(data)
    rows = [row_from_detection(d) for d in detections]
    rows.sort(key=severity_sort_key)

    # Populate per-row VCS file URL if provider env vars are available.
    # GitHub Actions sets GITHUB_ACTIONS=true; Azure Pipelines passes
    # ADO_COLLECTION_URI/ADO_PROJECT/ADO_REPO/ADO_REF from the template.
    if os.environ.get("GITHUB_ACTIONS") == "true":
        gh_server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
        gh_repo = os.environ.get("GITHUB_REPOSITORY", "")
        # Prefer the resolved commit SHA so links stay stable across force-pushes.
        gh_ref = os.environ.get("GITHUB_SHA") or os.environ.get("GITHUB_REF_NAME", "")
        if gh_repo and gh_ref:
            for r in rows:
                r["vcs_file_url"] = github_file_url(r, gh_server, gh_repo, gh_ref)
    else:
        collection_uri = os.environ.get("ADO_COLLECTION_URI", "")
        project = os.environ.get("ADO_PROJECT", "")
        repo = os.environ.get("ADO_REPO", "")
        ref = os.environ.get("ADO_REF", "")
        if collection_uri and project and repo and ref:
            for r in rows:
                r["vcs_file_url"] = azure_file_url(r, collection_uri, project, repo, ref)

    # Display name for the HTML header's "Scan type(s)" field. Prefer the
    # template-provided CYCODE_SCAN_TYPE (one of secret/sast/sca/iac) so the
    # rendered name matches Cycode's standard taxonomy. Fall back to the
    # per-detection `type` values only when the env var isn't set (e.g.
    # standalone script use).
    env_scan_type = os.environ.get("CYCODE_SCAN_TYPE", "")
    if env_scan_type:
        scan_types = [_SCAN_TYPE_DISPLAY.get(env_scan_type.lower(), env_scan_type)]
    else:
        scan_types = sorted({r["type"] for r in rows if r.get("type")})

    # Build metadata header from env vars set by the pipeline template.
    # Prefer GitHub Actions env vars when present; fall back to ADO equivalents.
    if os.environ.get("GITHUB_ACTIONS") == "true":
        md_repo_name = args.cycode_report or os.environ.get("GITHUB_REPOSITORY", "")
        md_branch = os.environ.get("GITHUB_REF_NAME", "")
    else:
        md_repo_name = args.cycode_report or os.environ.get("ADO_REPO", "")
        md_branch = os.environ.get("ADO_REF", "")
    md_scan_type_name = os.environ.get("CYCODE_SCAN_TYPE", "")
    md_scan_mode = os.environ.get("CYCODE_SCAN_MODE", "")
    md_base_commit = os.environ.get("CYCODE_BASE_COMMIT", "")

    md = render_markdown(
        rows,
        args.console_url,
        args.artifact_hint if (args.html or args.csv) else "",
        repo_name=md_repo_name,
        branch=md_branch,
        scan_type_name=md_scan_type_name,
        scan_mode=md_scan_mode,
        base_commit=md_base_commit,
        include_title=not args.no_title,
    )
    if args.md:
        with open(args.md, "w", encoding="utf-8") as f:
            f.write(md)
    else:
        print(md)

    if args.html:
        # Pull build context so the HTML header shows Repo / Branch / Commit
        # / Scan path inline. Same provider-detection as the Markdown summary.
        if os.environ.get("GITHUB_ACTIONS") == "true":
            repo_name = args.cycode_report or os.environ.get("GITHUB_REPOSITORY", "")
            branch = os.environ.get("GITHUB_REF_NAME", "")
            commit = os.environ.get("GITHUB_SHA", "")
        else:
            repo_name = args.cycode_report or os.environ.get("ADO_REPO", "")
            branch = os.environ.get("ADO_REF", "")
            commit = os.environ.get("BUILD_SOURCEVERSION") or os.environ.get("ADO_COMMIT", "")
        scan_path = os.environ.get("CYCODE_SCAN_PATH", "")
        with open(args.html, "w", encoding="utf-8") as f:
            f.write(render_html(
                rows, args.console_url, scan_types,
                repo_name=repo_name, branch=branch, commit=commit, scan_path=scan_path,
            ))

    if args.csv:
        write_csv(rows, args.csv, args.console_url)

    return 0


if __name__ == "__main__":
    sys.exit(main())
