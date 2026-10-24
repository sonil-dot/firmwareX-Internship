"""
Day 2 wrap-up: normalize hardening_matrix.json + secrets.json +
symbolic_finding.json into the PRD's Appendix-A finding schema, then
render a static HTML report (file-tree-lite, mitigation table, findings list).

Run with: python3 normalize_and_report.py
"""
import json
import uuid
import html
from datetime import datetime, timezone

REPORTS_DIR = "reports"
FIRMWARE_ID = str(uuid.uuid4())
NOW = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_hardening(matrix: list) -> list:
    findings = []
    for b in matrix:
        missing = []
        if not b["stack_canary"]:
            missing.append("stack_canary")
        if not b["nx"]:
            missing.append("nx")
        if b["relro"] == "none":
            missing.append("relro")
        if not b["pie"]:
            missing.append("pie")
        if not missing:
            continue
        findings.append({
            "vulnerability_id": str(uuid.uuid4()),
            "firmware_id": FIRMWARE_ID,
            "binary": b["path"],
            "architecture": (
   	    "ARM32" if b["architecture"] == "ARM" and b.get("bits") == 32
            else "ARM64" if b["architecture"] == "ARM" and b.get("bits") == 64
            else b["architecture"]
            ),
            "category": "missing_mitigation",
            "cwe": None,  # Missing hardening is an observed property, not automatically a CWE
            "address": None, "sink": None, "source": None, "tainted_path": [],
            "crash_state": {
   	    "fault_address": None,
  	    "registers": None,
 	    "overflow_offset": None,
 	    "stack_hash": None,
	    }, 
            "risk_rating": "medium" if len(missing) >= 3 else "low",
            "confidence": "confirmed",  # static ELF header read, not heuristic
            "evidence_ref": f"hardening_matrix:{b['path']}",
            "redacted": False,
            "status": "new",
            "detected_at": NOW,
            "detail": f"Missing: {', '.join(missing)}",
        })
    return findings


def normalize_secrets(secrets: list) -> list:
    findings = []
    for s in secrets:
        cwe = "CWE-798" if "password" in s["pattern"] or "aws" in s["pattern"] else \
              "CWE-321" if "private_key" in s["pattern"] else "CWE-200"
        findings.append({
            "vulnerability_id": str(uuid.uuid4()),
            "firmware_id": FIRMWARE_ID,
            "binary": s["path"],
            "architecture": "ARM32",
            "category": "hardcoded_secret",
            "cwe": cwe,
            "address": hex(s["offset"]), "sink": None, "source": None, "tainted_path": [],
            "crash_state": {
   	    "fault_address": None,
   	    "registers": None,
 	    "overflow_offset": None,
 	    "stack_hash": None,
	     },
            "risk_rating": "medium" if s["confidence"] == "heuristic" else ("high" if cwe in ("CWE-798", 			    "CWE-321") else "low"),
	    "detail": s.get("note", s.get("pattern", "Secret-pattern match; validation required")),
            "confidence": s["confidence"],
            "evidence_ref": f"secrets:{s['fingerprint_sha256'][:16]}",
            "redacted": True,
            "status": "new",
            "detected_at": NOW,
            "detail": s.get("note") or f"pattern: {s['pattern']}",
        })
    return findings


def normalize_symbolic(sym: dict) -> list:
    if not sym.get("path_found"):
        return []
    return [{
        "vulnerability_id": str(uuid.uuid4()),
        "firmware_id": FIRMWARE_ID,
        "binary": sym["binary"],
        "architecture": "ARM32",
        "category": "memory_corruption",
        "cwe": "CWE-134" if sym["sink_function"] == "sprintf" else "CWE-120",
        "address": sym["sink_addr"], "sink": sym["sink_function"],
        "source": "function_argument (modeled as attacker-controlled)",
        "tainted_path": sym["tainted_path"],
        "crash_state": {
        "fault_address": None,
        "registers": None,
        "overflow_offset": None,
        "stack_hash": None,
        },
        "risk_rating": "high",
        "confidence": "probable",  # intra-procedural, not full network taint -- see note
        "evidence_ref": "symbolic_finding.json",
        "redacted": False,
        "status": "new",
        "detected_at": NOW,
        "detail": sym["note"],
    }]


def render_html(all_findings: list, hardening_matrix: list) -> str:
    risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(all_findings, key=lambda f: risk_order.get(f["risk_rating"], 5))

    rows = ""
    for f in sorted_findings:
        rows += f"""<tr class="risk-{f['risk_rating']}">
          <td>{f['risk_rating'].upper()}</td>
          <td>{html.escape(str(f['cwe'] or 'N/A'))}</td>
          <td>{html.escape(f['category'])}</td>
          <td>{html.escape(f['binary'] or '')}</td>
          <td>{f['confidence']}</td>
          <td>{html.escape(f.get('detail',''))}</td>
        </tr>"""

    mit_rows = ""
    for b in hardening_matrix[:30]:  # first 30 for brevity in the static report
        mit_rows += f"""<tr>
          <td>{html.escape(b['path'].split('/')[-1])}</td>
          <td>{b['architecture']}</td>
          <td>{'✓' if b['nx'] else '✗'}</td>
          <td>{'✓' if b['pie'] else '✗'}</td>
          <td>{b['relro']}</td>
          <td>{'✓' if b['stack_canary'] else '✗'}</td>
          <td>{'✓' if b['stripped'] else '✗'}</td>
        </tr>"""

    summary = {}
    for f in all_findings:
        summary[f["risk_rating"]] = summary.get(f["risk_rating"], 0) + 1

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>FirmwareX Report - IoTGoat</title>
<style>
  body {{ font-family: -apple-system, sans-serif; max-width: 1100px; margin: 40px auto; padding: 0 20px; color: #1a1a1a; }}
  h1 {{ border-bottom: 3px solid #2a2a2a; padding-bottom: 10px; }}
  table {{ border-collapse: collapse; width: 100%; margin: 20px 0; font-size: 14px; }}
  th, td {{ border: 1px solid #ddd; padding: 8px 10px; text-align: left; }}
  th {{ background: #2a2a2a; color: white; }}
  .risk-critical {{ background: #ffcdd2; }}
  .risk-high {{ background: #ffe0b2; }}
  .risk-medium {{ background: #fff9c4; }}
  .risk-low {{ background: #f1f8e9; }}
  .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
  .stat {{ background: #f5f5f5; padding: 15px 25px; border-radius: 8px; text-align: center; }}
  .stat .num {{ font-size: 28px; font-weight: bold; }}
  .note {{ background: #e3f2fd; padding: 12px; border-radius: 6px; font-size: 14px; margin: 15px 0; }}
</style></head>
<body>
<h1>FirmwareX Detection Report — IoTGoat-raspberry-pi2</h1>
<p>Firmware ID: <code>{FIRMWARE_ID}</code> · Generated: {NOW}</p>

<div class="summary">
  <div class="stat"><div class="num">{len(all_findings)}</div>Total Findings</div>
  <div class="stat"><div class="num">{len(hardening_matrix)}</div>Binaries Audited</div>
  <div class="stat"><div class="num">{summary.get('high',0)+summary.get('critical',0)}</div>High/Critical</div>
</div>

<div class="note">
<b>Scope note:</b> This is a 2-day bounded prototype. Static hardening audit and
secret/entropy scanning cover 100% of extracted binaries. Symbolic execution is
intra-procedural and bounded (300 steps / 60s per function) on one binary
(uhttpd) as a proof of technique — full-system QEMU emulation, whole-binary
taint from network sockets, and fuzzing were descoped for time. See
known-limitations in the README for the full list.
</div>

<h2>Findings ({len(all_findings)})</h2>
<table>
<tr><th>Risk</th><th>CWE</th><th>Category</th><th>Binary</th><th>Confidence</th><th>Detail</th></tr>
{rows}
</table>

<h2>Binary Hardening Matrix (sample, first 30 of {len(hardening_matrix)})</h2>
<table>
<tr><th>Binary</th><th>Arch</th><th>NX</th><th>PIE</th><th>RELRO</th><th>Canary</th><th>Stripped</th></tr>
{mit_rows}
</table>

</body></html>"""


if __name__ == "__main__":
    hardening = json.load(open(f"{REPORTS_DIR}/hardening_matrix.json"))
    secrets = json.load(open(f"{REPORTS_DIR}/secrets.json"))
    symbolic = json.load(open(f"{REPORTS_DIR}/symbolic_finding.json"))

    all_findings = normalize_hardening(hardening) + normalize_secrets(secrets) + normalize_symbolic(symbolic)

    with open(f"{REPORTS_DIR}/normalized_findings.json", "w") as f:
        json.dump(all_findings, f, indent=2)

    html_report = render_html(all_findings, hardening)
    with open(f"{REPORTS_DIR}/report.html", "w", encoding="utf-8") as f:
        f.write(html_report)

    print(f"[+] {len(all_findings)} normalized findings written to normalized_findings.json")
    print(f"[+] HTML report written to report.html")
