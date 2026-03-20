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

# Parse TSV, collect words above confidence threshold with spatial data
words_data = []   # list of [text, left, top, width, height]
try:
    for row in csv.DictReader(io.StringIO(r.stdout), delimiter="\t"):
        try:
            if int(row.get("conf", -1)) >= minconf:
                t = (row.get("text") or "").strip()
                if t:
                    words_data.append([
                        t,
                        int(row.get("left",   0)),
                        int(row.get("top",    0)),
                        int(row.get("width",  0)),
                        int(row.get("height", 0)),
                    ])
        except (ValueError, TypeError):
            pass
except Exception:
    pass

if not words_data:
    emit([]); sys.exit(0)

# Build flat text + per-word start-offset index
offsets = []
pos = 0
for wd in words_data:
    offsets.append(pos)
    pos += len(wd[0]) + 1   # +1 for joining space
text = " ".join(wd[0] for wd in words_data)

if not text.strip():
    emit([]); sys.exit(0)

def bbox_for_match(m):
    """Union bounding box of every word that overlaps with the match span."""
    start, end = m.start(), m.end()
    spanned = []
    for i, wd in enumerate(words_data):
        wstart = offsets[i]
        wend   = wstart + len(wd[0])
        if wend > start and wstart < end:
            spanned.append(wd)
    if not spanned:
        return None
    l = min(s[1] for s in spanned)
    t = min(s[2] for s in spanned)
    r = max(s[1] + s[3] for s in spanned)
    b = max(s[2] + s[4] for s in spanned)
    return {"left": l, "top": t, "width": r - l, "height": b - t}

# PII detection via regex
findings = []

def finding(tp, v, sev, conf, tags, bbox):
    f = {"type": tp, "value": v, "severity": sev,
         "confidence": conf, "framework_tags": tags}
    if bbox:
        f["bbox"] = bbox
    return f

for m in re.finditer(r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b', text):
    findings.append(finding("email", m.group(), "medium", 0.85, ["gdpr"],
                             bbox_for_match(m)))

for m in re.finditer(r'\b(?!000|666|9\d{2})\d{3}[-\s]\d{2}[-\s]\d{4}\b', text):
    findings.append(finding("ssn", m.group(), "critical", 0.80, ["gdpr", "hipaa"],
                             bbox_for_match(m)))

for m in re.finditer(r'(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b', text):
    findings.append(finding("phone", m.group(), "medium", 0.70, ["gdpr"],
                             bbox_for_match(m)))

for m in re.finditer(r'\b(?:\d{4}[-\s]){3}\d{4}\b', text):
    findings.append(finding("credit_card", m.group(), "high", 0.75, ["pci_dss"],
                             bbox_for_match(m)))

emit(findings)
