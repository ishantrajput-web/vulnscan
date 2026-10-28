"""Console UI: colours (Windows-safe), phases, throttled progress bar. ASCII only."""
from __future__ import annotations

import os
import sys
import time


def _enable_vt() -> bool:
    if os.name != "nt":
        return True
    try:
        import ctypes
        k = ctypes.windll.kernel32  # type: ignore[attr-defined]
        h = k.GetStdHandle(-11)
        mode = ctypes.c_ulong()
        if k.GetConsoleMode(h, ctypes.byref(mode)):
            k.SetConsoleMode(h, mode.value | 0x0004)
            return True
    except Exception:
        pass
    return False


def _safe_reconfigure() -> None:
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(errors="replace")  # type: ignore[attr-defined]
        except Exception:
            pass


_safe_reconfigure()
try:
    _TTY = sys.stdout.isatty()
except Exception:
    _TTY = False
COLOR = _TTY and _enable_vt() and not os.environ.get("NO_COLOR")

_C = {"red": "31", "green": "32", "yellow": "33", "blue": "34", "magenta": "35",
      "cyan": "36", "bold": "1", "dim": "2"}


def c(text: str, color: str) -> str:
    if not COLOR:
        return text
    return "\033[%sm%s\033[0m" % (_C.get(color, "0"), text)


SEV_COLOR = {"critical": "magenta", "high": "red", "medium": "yellow",
             "low": "cyan", "info": "dim"}


class UI:
    def __init__(self, quiet: bool = False):
        self.quiet = quiet
        self._last = 0.0
        self._pct_printed = -1
        self._in_progress = False

    def _p(self, msg: str = "") -> None:
        if self.quiet:
            return
        self.progress_end()
        try:
            print(msg, flush=True)
        except Exception:
            print(msg.encode("ascii", "replace").decode("ascii"), flush=True)

    def banner(self, version: str) -> None:
        art = r"""
  __   __     _     ____
  \ \ / /   _| |_ _/ ___|  ___ __ _ _ __
   \ V / | | | | '_ \___ \ / __/ _` | '_ \
    | || |_| | | | | |__) | (_| (_| | | | |
    |_| \__,_|_|_| |_|____/ \___\__,_|_| |_|
"""
        self._p(c(art, "cyan") + c("  Network Vulnerability Scanner v%s" % version, "bold"))
        self._p(c("  Authorized security assessments only.\n", "dim"))

    def phase(self, i: int, n: int, name: str) -> None:
        self._p(c("[%d/%d] %s" % (i, n, name), "bold"))

    def info(self, msg: str) -> None:
        self._p(c("[*] ", "blue") + msg)

    def ok(self, msg: str) -> None:
        self._p(c("[+] ", "green") + msg)

    def warn(self, msg: str) -> None:
        self._p(c("[!] ", "yellow") + msg)

    def err(self, msg: str) -> None:
        self.progress_end()
        try:
            print(c("[x] ", "red") + msg, file=sys.stderr, flush=True)
        except Exception:
            pass

    def progress(self, done: int, total: int, label: str = "") -> None:
        if self.quiet or total <= 0:
            return
        now = time.time()
        finished = done >= total
        if not finished and now - self._last < 0.15:
            return
        self._last = now
        pct = int(done * 100 / total)
        if _TTY:
            width = 28
            filled = int(width * pct / 100)
            bar = "#" * filled + "-" * (width - filled)
            sys.stdout.write("\r    [%s] %3d%% %s " % (bar, pct, label))
            sys.stdout.flush()
            self._in_progress = True
            if finished:
                self.progress_end()
        else:
            if pct // 25 != self._pct_printed // 25 or finished:
                self._pct_printed = pct
                print("    %d%% %s" % (pct, label), flush=True)

    def progress_end(self) -> None:
        if self._in_progress:
            sys.stdout.write("\n")
            sys.stdout.flush()
            self._in_progress = False
        self._pct_printed = -1
