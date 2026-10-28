from __future__ import annotations

import json
import os

from models import ScanResult
from report.scoring import summarize


def write_json(result: ScanResult, path: str) -> str:
    data = result.to_dict()
    data["schema_version"] = 1
    data["summary"] = summarize(result)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str, ensure_ascii=False)
    return os.path.abspath(path)
