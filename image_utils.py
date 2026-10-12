"""Turn uploaded screenshots into compact base64 text for Firestore.

A Firestore document can hold at most 1 MiB, so screenshots are resized and
re-encoded as JPEG until the base64 string fits within ``MAX_BASE64_CHARS``.
"""
from __future__ import annotations

import base64
import io

from PIL import Image, ImageOps

# Leaves room for the email text and other fields in the same 1 MiB document.
MAX_BASE64_CHARS = 700_000
MAX_DIMENSION = 1600
MIN_DIMENSION = 320
QUALITIES = (85, 75, 65, 55, 45, 35)


def _to_rgb(image):
    image = ImageOps.exif_transpose(image)
    if image.mode in ("RGBA", "LA") or (image.mode == "P" and "transparency" in image.info):
        rgba = image.convert("RGBA")
        background = Image.new("RGB", rgba.size, (255, 255, 255))
        background.paste(rgba, mask=rgba.split()[-1])
        return background
    return image.convert("RGB")


def image_to_base64(image, max_chars=MAX_BASE64_CHARS):
    """Return (base64_text, "image/jpeg") small enough to store in Firestore."""
    img = _to_rgb(image)
    img.thumbnail((MAX_DIMENSION, MAX_DIMENSION), Image.LANCZOS)

    while True:
        for quality in QUALITIES:
            buffer = io.BytesIO()
            img.save(buffer, format="JPEG", quality=quality, optimize=True)
            encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
            if len(encoded) <= max_chars:
                return encoded, "image/jpeg"
        if max(img.size) <= MIN_DIMENSION:
            raise ValueError("Screenshot is too large to store even after compression.")
        new_size = (max(1, int(img.width * 0.75)), max(1, int(img.height * 0.75)))
        img = img.resize(new_size, Image.LANCZOS)


def base64_to_bytes(text):
    return base64.b64decode(text)
