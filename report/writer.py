"""One place that writes every report format, isolating failures so one bad format never loses the others."""
from __future__ import annotations

import logging
import os
import traceback
from typing import Dict, List, Tuple

from models import ScanResult

log = logging.getLogger("vulnscan")
FORMATS = ("json", "html", "pdf", "docx")


def write_reports(result: ScanResult, outdir: str, fmts: List[str]) -> Tuple[Dict[str, str], List[str]]:
    """Returns ({format: path}, [warnings/errors])."""
    os.makedirs(outdir, exist_ok=True)
    base = os.path.join(outdir, "report_%s" % result.scan_id)
    written: Dict[str, str] = {}
    notes: List[str] = []
    for fmt in fmts:
        try:
            if fmt == "json":
                from report.json_export import write_json
                written["json"] = write_json(result, base + ".json")
            elif fmt == "html":
                from report.html_report import write_html
                written["html"] = write_html(result, base + ".html")
            elif fmt == "docx":
                from report.docx_report import write_docx
                written["docx"] = write_docx(result, base + ".docx")
            elif fmt == "pdf":
                try:
                    from report.pdf_report import write_pdf
                except ImportError:
                    notes.append("reportlab not installed -> PDF skipped (py -m pip install reportlab). DOCX/HTML are unaffected.")
                    if "html" not in written and "html" not in fmts:
                        from report.html_report import write_html
                        written["html"] = write_html(result, base + ".html")
                    continue
                written["pdf"] = write_pdf(result, base + ".pdf")
        except Exception as e:
            notes.append("Could not write %s report: %s: %s" % (fmt, type(e).__name__, e))
            log.error("report %s failed\n%s", fmt, traceback.format_exc())
    return written, notes
