from __future__ import annotations

from pathlib import Path

import qrcode


def save_qr_png(data: str, out_path: str | Path) -> Path:
    path = Path(out_path)
    img = qrcode.make(data)
    img.save(path)
    return path
