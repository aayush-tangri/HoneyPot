from __future__ import annotations

import sys
from datetime import datetime

if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m"


RISK_COLOUR = {"HIGH": "91", "MEDIUM": "93", "LOW": "92"}

ATTACK_COLOUR = {
    "Brute Force":        "91",
    "Credential Stuffing":"91",
    "IDOR":               "95",
    "API Abuse":          "93",
    "Path Traversal":     "93",
    "Scanner":            "96",
}


def print_request(ip: str, method: str, endpoint: str, status: int, ms: int) -> None:
    def status_col(s: int, t: str) -> str:
        if s >= 500: return _c(t, "91")
        if s >= 400: return _c(t, "93")
        return _c(t, "92")

    ts   = _c(datetime.now().strftime("%H:%M:%S"), "90")
    meth = _c(f"{method:<6}", "96")
    ep   = _c(f"{endpoint:<35}", "97")
    st   = status_col(status, str(status))
    ip_s = _c(f"{ip:<15}", "33")
    print(f"  {ts}  {ip_s}  {meth}  {ep}  {st}  {_c(str(ms)+'ms', '90')}", flush=True)


def print_attack(ip: str, attack_type: str, endpoint: str, risk: str, source: str, conf: float | None) -> None:
    colour   = ATTACK_COLOUR.get(attack_type, "97")
    risk_col = RISK_COLOUR.get(risk, "97")
    src_tag  = _c(f"[{source.upper()}]", "96" if source == "ml" else "90")
    conf_tag = _c(f" {conf:.0%}", "96") if conf is not None else ""
    print(
        f"\n  {_c('⚠  ATTACK DETECTED', '1;' + colour)}"
        f"  {_c(attack_type, '1;' + colour)}"
        f"  {src_tag}{conf_tag}"
        f"\n  {'IP:':<6} {_c(ip, '33')}   {'Endpoint:':<10} {_c(endpoint, '97')}"
        f"   Risk: {_c(risk, '1;' + risk_col)}\n",
        flush=True,
    )
