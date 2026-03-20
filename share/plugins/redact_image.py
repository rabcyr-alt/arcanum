#!/usr/bin/env python3
"""Arcanum image redaction plugin — uses Pillow to paint over OCR bbox findings."""
import json, sys

import pillow_heif
pillow_heif.register_heif_opener()

from PIL import Image, ImageDraw


def emit_ok():
    print(json.dumps({"ok": True}), flush=True)

def emit_error(msg):
    print(json.dumps({"ok": False, "error": msg}), flush=True)
    sys.exit(1)


try:
    req = json.load(sys.stdin)
except Exception as exc:
    emit_error(f"JSON parse error: {exc}")

path       = req.get("path", "")
bboxes     = req.get("bboxes", [])
fill_color = req.get("fill_color", [0, 0, 0])
padding    = int(req.get("padding", 2))

if not path:
    emit_error("missing 'path' field in request")
if not bboxes:
    emit_error("no bboxes provided")

# Parse fill_color: [r,g,b] list or "#rrggbb" hex string
if isinstance(fill_color, list):
    try:
        color = tuple(int(c) for c in fill_color[:3])
    except (TypeError, ValueError) as exc:
        emit_error(f"invalid fill_color list: {exc}")
elif isinstance(fill_color, str) and fill_color.startswith("#"):
    hx = fill_color.lstrip("#")
    if len(hx) != 6:
        emit_error(f"invalid hex fill_color: {fill_color!r}")
    try:
        color = tuple(int(hx[i:i+2], 16) for i in (0, 2, 4))
    except ValueError as exc:
        emit_error(f"invalid hex fill_color: {exc}")
else:
    emit_error(f"fill_color must be [r,g,b] or '#rrggbb', got {fill_color!r}")

try:
    img = Image.open(path)
except Exception as exc:
    emit_error(f"cannot open '{path}': {exc}")

original_format = img.format
if img.mode not in ("RGB", "RGBA"):
    img = img.convert("RGBA" if "A" in img.mode else "RGB")

draw = ImageDraw.Draw(img)
for b in bboxes:
    try:
        x0 = int(b["left"])  - padding
        y0 = int(b["top"])   - padding
        x1 = int(b["left"])  + int(b["width"])  + padding - 1
        y1 = int(b["top"])   + int(b["height"]) + padding - 1
    except (KeyError, TypeError, ValueError) as exc:
        emit_error(f"malformed bbox {b!r}: {exc}")
    fill = color + (255,) if img.mode == "RGBA" else color
    draw.rectangle([x0, y0, x1, y1], fill=fill)

try:
    fmt = original_format
    if fmt is None:
        ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
        fmt = {"jpg":"JPEG","jpeg":"JPEG","png":"PNG","gif":"GIF",
               "bmp":"BMP","tiff":"TIFF","tif":"TIFF","webp":"WEBP"}.get(ext, "PNG")
    if fmt in ("JPEG", "JPG") and img.mode == "RGBA":
        img = img.convert("RGB")
    img.save(path, format=fmt)
except Exception as exc:
    emit_error(f"cannot save '{path}': {exc}")

emit_ok()
