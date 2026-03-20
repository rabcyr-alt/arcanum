#!/usr/bin/env python3
"""Arcanum OCR detector plugin — uses Tesseract CLI."""
import json, sys, re, subprocess, csv, io

data   = json.loads(sys.stdin.readline())
fpath  = data.get("file", "")
cfg    = data.get("config", {})
langs  = "+".join(cfg.get("ocr_languages", ["eng"]))
minconf = int(cfg.get("ocr_confidence_threshold", 60))
timeout = int(cfg.get("ocr_timeout", 120))

def emit(findings):
    print(json.dumps({"findings": findings}), flush=True)

if not fpath:
    emit([]); sys.exit(0)

# Run tesseract with TSV output for per-word confidence filtering
try:
    r = subprocess.run(
        ["tesseract", fpath, "stdout", "-l", langs, "--psm", "3", "tsv"],
        capture_output=True, text=True, timeout=timeout,
    )
except FileNotFoundError:
    sys.stderr.write("ocr_tesseract: tesseract not found in PATH\n")
    emit([]); sys.exit(0)
except subprocess.TimeoutExpired:
    sys.stderr.write(f"ocr_tesseract: tesseract timed out on {fpath}\n")
    emit([]); sys.exit(0)

# Parse TSV, collect words above confidence threshold
words = []
try:
    for row in csv.DictReader(io.StringIO(r.stdout), delimiter="\t"):
        try:
            if int(row.get("conf", -1)) >= minconf:
                w = (row.get("text") or "").strip()
                if w:
                    words.append(w)
        except (ValueError, TypeError):
            pass
except Exception:
    pass

text = " ".join(words)
if not text.strip():
    emit([]); sys.exit(0)

# PII detection via regex
findings = []

def finding(t, v, sev, conf, tags):
    return {"type": t, "value": v, "severity": sev,
            "confidence": conf, "framework_tags": tags}

for m in re.finditer(r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b', text):
    findings.append(finding("email", m.group(), "medium", 0.85, ["gdpr"]))

for m in re.finditer(r'\b(?!000|666|9\d{2})\d{3}[-\s]\d{2}[-\s]\d{4}\b', text):
    findings.append(finding("ssn", m.group(), "critical", 0.80, ["gdpr", "hipaa"]))

for m in re.finditer(r'(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b', text):
    findings.append(finding("phone", m.group(), "medium", 0.70, ["gdpr"]))

for m in re.finditer(r'\b(?:\d{4}[-\s]){3}\d{4}\b', text):
    findings.append(finding("credit_card", m.group(), "high", 0.75, ["pci_dss"]))

emit(findings)
