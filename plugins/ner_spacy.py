#!/usr/bin/env python3
"""
pii-guardian plugin: ner_spacy
NER-based PII detection using spaCy.

Reads one JSON object from stdin (pii-guardian plugin contract),
runs spaCy named-entity recognition over each text segment, and
writes one JSON object with findings to stdout.

Requires: pip install spacy && python -m spacy download en_core_web_sm
          (or en_core_web_md / en_core_web_lg for higher accuracy)

Config block (under detectors.ner_spacy in pii-guardian config):

    {
      "enabled": true,
      "model":   "en_core_web_sm",   // spaCy model to load
      "timeout": 30,
      "min_confidence": 0.0,         // all spaCy entities pass (no score)
      "entity_map": {                // override NER label → finding type
        "PERSON":  "name",
        "ORG":     null,             // null = skip this entity type
        "GPE":     "physical_address",
        "LOC":     "physical_address",
        "DATE":    "date_of_birth",  // only in PII-context; risky — tune carefully
        "CARDINAL": null
      }
    }

Exit codes:
  0  success
  1  spaCy not installed
  2  model not found
  3  JSON parse error on input
  4  unexpected error
"""

import sys
import json

# ── NER label → pii-guardian finding type mapping ─────────────────────────────
# Labels: https://spacy.io/api/annotation#named-entities
# Set a label to None to discard that entity type entirely.

DEFAULT_ENTITY_MAP = {
    "PERSON":     "name",
    "ORG":        None,          # organisations are not PII by themselves
    "GPE":        "physical_address",   # geo-political entity (city, country)
    "LOC":        "physical_address",
    "FAC":        None,          # facilities
    "DATE":       None,          # dates are very common; disable by default
    "TIME":       None,
    "MONEY":      None,
    "QUANTITY":   None,
    "ORDINAL":    None,
    "CARDINAL":   None,
    "NORP":       None,          # nationalities / religious groups
    "PRODUCT":    None,
    "EVENT":      None,
    "WORK_OF_ART": None,
    "LAW":        None,
    "LANGUAGE":   None,
}

# Severity by finding type
SEVERITY_MAP = {
    "name":             "medium",
    "physical_address": "medium",
    "date_of_birth":    "medium",
}


def load_model(model_name):
    try:
        import spacy  # noqa: F401
    except ImportError:
        print(
            json.dumps({"error": "spacy not installed; run: pip install spacy"}),
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        import spacy as sp
        return sp.load(model_name)
    except OSError:
        print(
            json.dumps({"error": f"spaCy model '{model_name}' not found; "
                        f"run: python -m spacy download {model_name}"}),
            file=sys.stderr,
        )
        sys.exit(2)


def process(nlp, request, entity_map, min_confidence):
    findings = []
    segments = request.get("segments", [])

    for seg in segments:
        seg_id = seg.get("id", "seg-?")
        text   = seg.get("text", "")
        if not text:
            continue

        doc = nlp(text)
        for ent in doc.ents:
            pii_type = entity_map.get(ent.label_)
            if pii_type is None:
                continue

            # spaCy doesn't expose per-entity confidence scores for the built-in
            # pipelines; use 0.75 as a conservative default.  Models that expose
            # kb_id or scorer data can be adapted here.
            confidence = 0.75

            findings.append({
                "segment_id": seg_id,
                "type":       pii_type,
                "value":      ent.text,
                "confidence": confidence,
                "start":      ent.start_char,
                "end":        ent.end_char,
                "ner_label":  ent.label_,
            })

    return {"findings": findings}


def main():
    try:
        raw = sys.stdin.read()
    except Exception as exc:
        print(json.dumps({"error": f"stdin read error: {exc}"}), file=sys.stderr)
        sys.exit(4)

    try:
        request = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(json.dumps({"error": f"JSON parse error: {exc}"}), file=sys.stderr)
        sys.exit(3)

    cfg          = request.get("config", {})
    model_name   = cfg.get("model", "en_core_web_sm")
    min_conf     = float(cfg.get("min_confidence", 0.0))

    # Merge default entity map with per-config overrides
    entity_map = dict(DEFAULT_ENTITY_MAP)
    for label, pii_type in (cfg.get("entity_map") or {}).items():
        entity_map[label.upper()] = pii_type  # None is valid (skip)

    action = request.get("action", "detect")
    if action == "ping":
        # Health-check action: load model and confirm ready
        load_model(model_name)
        print(json.dumps({"status": "ok", "model": model_name}))
        return

    nlp    = load_model(model_name)
    result = process(nlp, request, entity_map, min_conf)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
