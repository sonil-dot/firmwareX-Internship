"""
Falcon... FirmwareX — Secret & Credential Scanner
Satisfies the secret-scanning half of Week 3, and SC-3.1/3.2 (redaction):
raw secret VALUES are never stored — only a sha256 fingerprint plus enough
context (file, line, matched pattern) to triage the finding.

Run with: python3 secret_scanner.py <rootfs_dir> > secrets.json
"""

import os
import re
import sys
import json
import math
import hashlib

SKIP_DIRS = {"dev", "proc", "sys"}
MAX_FILE_SIZE = 5 * 1024 * 1024  # don't try to regex-scan huge binaries line by line

PATTERNS = {
    "private_key_header": re.compile(rb"-----BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----"),
    "aws_access_key": re.compile(rb"AKIA[0-9A-Z]{16}"),
    "generic_password_assignment": re.compile(rb"(?i)(passwd|password|pwd)\s*=\s*['\"][^'\"\s]{4,}['\"]"),
    "generic_api_key_assignment": re.compile(rb"(?i)(api[_-]?key|secret[_-]?key|token)\s*[:=]\s*['\"][A-Za-z0-9_\-]{12,}['\"]"),
    "basic_auth_url": re.compile(rb"https?://[^/\s:]+:[^/\s@]+@"),
}


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def fingerprint(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


# confidence calibration: some patterns are reliable, some need human review.
# known library test-fixture files are flagged so their "private key" hits
# aren't presented with false certainty.
CONFIDENCE = {
    "private_key_header": "probable",
    "aws_access_key": "probable",
    "generic_password_assignment": "heuristic",
    "generic_api_key_assignment": "heuristic",
    "basic_auth_url": "probable",
    "high_entropy_string": "heuristic",
}
# crypto libraries commonly embed test/example PEM material as literal
# strings for their own self-tests — downgrade confidence further there
KNOWN_TEST_FIXTURE_HINTS = ("mbedcrypto", "mbedtls", "openssl", "libssl", "libcrypto")


def is_elf_file(content: bytes) -> bool:
    return content[:4] == b"\x7fELF"


def scan_file(path: str) -> list:
    findings = []
    try:
        if os.path.getsize(path) > MAX_FILE_SIZE:
            return findings
        with open(path, "rb") as f:
            content = f.read()
    except (OSError, PermissionError):
        return findings

    elf = is_elf_file(content)
    likely_test_fixture = any(hint in path.lower() for hint in KNOWN_TEST_FIXTURE_HINTS)

    for pattern_name, regex in PATTERNS.items():
        for match in regex.finditer(content):
            value = match.group(0)
            confidence = CONFIDENCE[pattern_name]
            if likely_test_fixture and pattern_name == "private_key_header":
                confidence = "heuristic"  # likely a crypto lib's own test cert, not a device secret
            findings.append({
                "path": path,
                "pattern": pattern_name,
                "offset": match.start(),
                "fingerprint_sha256": fingerprint(value),
                "length": len(value),
                "confidence": confidence,
                "note": "matches known crypto-library test-fixture path" if likely_test_fixture and pattern_name == "private_key_header" else None,
                "redacted": True,
                "category": "hardcoded_secret",
            })

    # entropy pass: skip ELF binaries entirely — compiled code/data sections
    # are naturally high-entropy and this produces near-pure noise there.
    # Only scan text/config/script files, where a high-entropy token really
    # is unusual and worth a human's attention.
    if not elf:
        for m in re.finditer(rb"[A-Za-z0-9+/_\-]{20,64}", content):
            token = m.group(0)
            ent = shannon_entropy(token)
            if ent >= 4.3:
                findings.append({
                    "path": path,
                    "pattern": "high_entropy_string",
                    "offset": m.start(),
                    "fingerprint_sha256": fingerprint(token),
                    "length": len(token),
                    "entropy": round(ent, 2),
                    "confidence": CONFIDENCE["high_entropy_string"],
                    "note": None,
                    "redacted": True,
                    "category": "hardcoded_secret",
                })

    return findings


def scan_tree(rootfs: str) -> list:
    all_findings = []
    for dirpath, dirnames, filenames in os.walk(rootfs):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            if os.path.islink(full) or not os.path.isfile(full):
                continue
            all_findings.extend(scan_file(full))
    return all_findings


if __name__ == "__main__":
    rootfs = sys.argv[1] if len(sys.argv) > 1 else "."
    findings = scan_tree(rootfs)
    print(f"[+] {len(findings)} potential secret findings", file=sys.stderr)
    by_pattern = {}
    for f in findings:
        by_pattern[f["pattern"]] = by_pattern.get(f["pattern"], 0) + 1
    for k, v in by_pattern.items():
        print(f"    {k}: {v}", file=sys.stderr)

    print(json.dumps(findings, indent=2))
