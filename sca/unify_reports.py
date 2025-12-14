#!/usr/bin/env python3
import argparse
import csv
import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple


def safe_load_json(path: str) -> Optional[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except json.JSONDecodeError:
        return None


def norm_severity(tool: str, s: Optional[str]) -> str:
    if not s:
        return "UNKNOWN"
    t = s.strip().upper()

    # Semgrep: INFO/WARNING/ERROR, sometimes "critical/high/medium/low" via metadata
    if tool == "semgrep":
        mapping = {
            "INFO": "LOW",
            "WARNING": "MEDIUM",
            "ERROR": "HIGH",
            "CRITICAL": "CRITICAL",
            "HIGH": "HIGH",
            "MEDIUM": "MEDIUM",
            "LOW": "LOW",
        }
        return mapping.get(t, t)

    # Checkov: LOW/MEDIUM/HIGH/CRITICAL (часто), иногда "ERROR"
    if tool == "checkov":
        mapping = {
            "ERROR": "HIGH",
            "WARNING": "MEDIUM",
            "INFO": "LOW",
        }
        return mapping.get(t, t)

    # Dependency-Check: LOW/MEDIUM/HIGH/CRITICAL
    if tool == "dependency-check":
        return t

    return t


def parse_semgrep(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    results = data.get("results", []) or []
    for r in results:
        check_id = r.get("check_id", "")
        path = r.get("path", "")
        start = r.get("start", {}) or {}
        end = r.get("end", {}) or {}
        line = start.get("line")
        msg = (r.get("extra", {}) or {}).get("message", "") or r.get("message", "")
        sev = (r.get("extra", {}) or {}).get("severity")
        metadata = (r.get("extra", {}) or {}).get("metadata", {}) or {}
        cwe = metadata.get("cwe")
        owasp = metadata.get("owasp")
        rows.append({
            "tool": "semgrep",
            "rule_id": check_id,
            "severity": norm_severity("semgrep", sev),
            "title": msg.split("\n")[0][:180] if msg else check_id,
            "file": path,
            "line": line,
            "cve": "",
            "cwe": ",".join(cwe) if isinstance(cwe, list) else (cwe or ""),
            "owasp": ",".join(owasp) if isinstance(owasp, list) else (owasp or ""),
            "details": msg[:5000],
        })
    return rows


def parse_checkov(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    # Форматы Checkov отличаются в зависимости от версии/вывода.
    # Самый частый: data["results"]["failed_checks"] + passed_checks
    results = data.get("results", {}) or {}
    failed = results.get("failed_checks", []) or []
    for f in failed:
        rid = f.get("check_id", "") or f.get("checkId", "")
        name = f.get("check_name", "") or f.get("checkName", "")
        file_path = f.get("file_path", "") or f.get("filePath", "")
        line = None
        if isinstance(f.get("file_line_range"), list) and f["file_line_range"]:
            line = f["file_line_range"][0]
        sev = f.get("severity") or f.get("severity_level") or "UNKNOWN"
        guideline = f.get("guideline") or ""
        rows.append({
            "tool": "checkov",
            "rule_id": rid,
            "severity": norm_severity("checkov", str(sev)),
            "title": name[:180] if name else rid,
            "file": file_path,
            "line": line,
            "cve": "",
            "cwe": "",
            "owasp": "",
            "details": (guideline or name or "")[:5000],
        })
    return rows


def parse_dependency_check(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    deps = data.get("dependencies", []) or []
    for d in deps:
        pkg_ids = []
        for p in d.get("packages", []) or []:
            pid = p.get("id")
            if pid:
                pkg_ids.append(pid)

        file_path = d.get("filePath", "") or ""
        file_name = d.get("fileName", "") or ""
        vulns = d.get("vulnerabilities", []) or []
        # Если у зависимости нет vulns — не добавляем строку (обычно в unified-репорт включают только findings)
        for v in vulns:
            cve = v.get("name", "") or ""
            sev = v.get("severity", "") or "UNKNOWN"
            cwes = v.get("cwes", []) or []
            desc = v.get("description", "") or ""
            rows.append({
                "tool": "dependency-check",
                "rule_id": ",".join(pkg_ids) if pkg_ids else file_name,
                "severity": norm_severity("dependency-check", str(sev)),
                "title": cve,
                "file": file_path,
                "line": "",
                "cve": cve,
                "cwe": ",".join(cwes) if isinstance(cwes, list) else (cwes or ""),
                "owasp": "",
                "details": desc[:5000],
            })
    return rows


def write_json(path: str, payload: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def write_csv(path: str, rows: List[Dict[str, Any]]) -> None:
    fields = ["tool", "severity", "rule_id", "title", "file", "line", "cve", "cwe", "owasp", "details"]
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fields})


def write_html(path: str, meta: Dict[str, Any], rows: List[Dict[str, Any]]) -> None:
    # простая HTML-таблица без внешних зависимостей
    def esc(s: Any) -> str:
        if s is None:
            return ""
        s = str(s)
        return (s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;"))

    # сортировка по severity (условная)
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    rows_sorted = sorted(rows, key=lambda r: (order.get(r["severity"], 9), r["tool"], r["rule_id"]))

    summary = meta.get("summary", {})
    html = []
    html.append("<!doctype html><html><head><meta charset='utf-8'>")
    html.append("<title>Unified Security Report</title>")
    html.append("<style>body{font-family:system-ui,Arial,sans-serif;margin:24px;} table{border-collapse:collapse;width:100%;} th,td{border:1px solid #ddd;padding:8px;vertical-align:top;} th{background:#f6f6f6;text-align:left;} .tag{display:inline-block;padding:2px 8px;border-radius:999px;border:1px solid #ccc;font-size:12px;} </style>")
    html.append("</head><body>")
    html.append("<h1>Unified Security Report</h1>")
    html.append(f"<p><b>Generated:</b> {esc(meta.get('generated_at'))}</p>")
    html.append("<h2>Summary</h2>")
    html.append("<ul>")
    html.append(f"<li><b>Total findings:</b> {esc(summary.get('total_findings', 0))}</li>")
    html.append(f"<li><b>By tool:</b> {esc(summary.get('by_tool', {}))}</li>")
    html.append(f"<li><b>By severity:</b> {esc(summary.get('by_severity', {}))}</li>")
    html.append("</ul>")

    html.append("<h2>Findings</h2>")
    html.append("<table>")
    html.append("<tr><th>Tool</th><th>Severity</th><th>Rule/CVE</th><th>Title</th><th>File</th><th>Line</th><th>Details</th></tr>")
    for r in rows_sorted:
        html.append("<tr>")
        html.append(f"<td>{esc(r['tool'])}</td>")
        html.append(f"<td><span class='tag'>{esc(r['severity'])}</span></td>")
        html.append(f"<td>{esc(r['cve'] or r['rule_id'])}</td>")
        html.append(f"<td>{esc(r['title'])}</td>")
        html.append(f"<td>{esc(r['file'])}</td>")
        html.append(f"<td>{esc(r['line'])}</td>")
        html.append(f"<td>{esc(r['details'])}</td>")
        html.append("</tr>")
    html.append("</table>")
    html.append("</body></html>")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(html))


def count_by(rows: List[Dict[str, Any]], key: str) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for r in rows:
        v = r.get(key) or "UNKNOWN"
        out[v] = out.get(v, 0) + 1
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--semgrep", required=True)
    ap.add_argument("--checkov", required=True)
    ap.add_argument("--dependency-check", required=True)
    ap.add_argument("--outdir", required=True)
    args = ap.parse_args()

    rows: List[Dict[str, Any]] = []

    sem = safe_load_json(args.semgrep)
    if sem:
        rows += parse_semgrep(sem)

    chk = safe_load_json(args.checkov)
    if chk:
        rows += parse_checkov(chk)

    dc = safe_load_json(args.dependency_check)
    if dc:
        rows += parse_dependency_check(dc)

    meta = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "inputs": {
            "semgrep": args.semgrep if sem else None,
            "checkov": args.checkov if chk else None,
            "dependency_check": args.dependency_check if dc else None,
        },
        "summary": {
            "total_findings": len(rows),
            "by_tool": count_by(rows, "tool"),
            "by_severity": count_by(rows, "severity"),
        },
        "findings": rows,
    }

    os.makedirs(args.outdir, exist_ok=True)
    write_json(os.path.join(args.outdir, "unified-report.json"), meta)
    write_csv(os.path.join(args.outdir, "unified-report.csv"), rows)
    write_html(os.path.join(args.outdir, "unified-report.html"), meta, rows)


if __name__ == "__main__":
    main()
