from __future__ import annotations

import json
import os
import re
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Deque, Dict, Iterable, List, Optional, Tuple


# Frontend expects these enums (from mockData.ts)
AttackType = str
RiskLevel = str  # "LOW" | "MEDIUM" | "HIGH"
AttackerClassification = str  # "Scanner" | "Brute-forcer" | "Manual Attacker"


def _utc_now() -> datetime:
    return datetime.now()


def _parse_ts(s: Optional[str]) -> datetime:
    if not s:
        return _utc_now()
    try:
        return datetime.fromisoformat(s)
    except Exception:
        return _utc_now()


def _risk_level(score: int) -> RiskLevel:
    if score >= 80:
        return "HIGH"
    if score >= 50:
        return "MEDIUM"
    return "LOW"


_RE_USER_ID = re.compile(r"^/api/users/(\d+)$")


@dataclass
class AttackerState:
    ip: str
    first_seen: datetime
    last_seen: datetime
    total_requests: int = 0

    # Rolling windows (timestamps in epoch seconds).
    recent_requests_s: Deque[float] = field(default_factory=lambda: deque(maxlen=5000))
    recent_failed_logins_s: Deque[float] = field(default_factory=lambda: deque(maxlen=5000))

    # IDOR enumeration tracking.
    last_user_id: Optional[int] = None
    sequential_id_hits: int = 0

    endpoint_counts: Counter = field(default_factory=Counter)

    risk_score: int = 10
    behavior_counts: Counter = field(default_factory=Counter)
    recon_hits: int = 0
    brute_force_emits: int = 0
    recent_attack_types: Deque[Tuple[float, str]] = field(default_factory=lambda: deque(maxlen=2000))


class DetectionEngine:
    """
    Rule-first behavior detector with ML classifier fallback.

    Rules run first — they are fast and explainable.
    If a request doesn't match any rule, the ML classifier
    gets a chance to label it based on the full feature vector.
    """

    def __init__(self) -> None:
        self._attack_events: Deque[Dict[str, Any]] = deque(maxlen=500)
        self._attackers: Dict[str, AttackerState] = {}
        self._file_pos: int = 0
        self._last_tail_ts: float = 0.0

        # ── ML classifier (lazy init so startup never blocks) ──────────────
        self._classifier = None
        self._classifier_ready = False
        self._init_classifier()

    def _init_classifier(self) -> None:
        """
        Train the ML classifier at startup.
        Wrapped in try/except so if scikit-learn is missing,
        the honeypot still works using rules only.
        """
        try:
            from app.services.attack_classifier import AttackClassifier
            self._classifier = AttackClassifier()
            self._classifier_ready = True
        except Exception as e:
            # Graceful degradation: rules still work without ML.
            print(f"[DetectionEngine] ML classifier unavailable: {e}")
            self._classifier_ready = False

    # -------------------------
    # Public API used by routes
    # -------------------------

    def get_recent_attacks(self, limit: int = 50) -> List[Dict[str, Any]]:
        items = list(self._attack_events)
        return list(reversed(items[-max(1, limit):]))

    def get_attacker_profile(self, ip: str) -> Dict[str, Any]:
        st = self._attackers.get(ip)
        now = _utc_now()
        if not st:
            return {
                "ip": ip,
                "riskScore": 0,
                "classification": "Scanner",
                "firstSeen": now.isoformat(),
                "lastSeen": now.isoformat(),
                "totalRequests": 0,
                "requestsPerMinute": [0] * 60,
                "attackTimeline": [],
                "targetedEndpoints": [],
                "country": "Unknown",
                "isp": "Unknown",
            }

        classification = self._classify(st)
        rpm = self._requests_per_minute(st, now)
        timeline = self._timeline_for_ip(ip, limit=20)
        targeted = [
            {"endpoint": ep, "count": count}
            for ep, count in st.endpoint_counts.most_common()
        ]

        return {
            "ip": ip,
            "riskScore": max(0, min(100, st.risk_score)),
            "classification": classification,
            "firstSeen": st.first_seen.isoformat(),
            "lastSeen": st.last_seen.isoformat(),
            "totalRequests": st.total_requests,
            "requestsPerMinute": rpm,
            "attackTimeline": timeline,
            "targetedEndpoints": targeted,
            "country": "Unknown",
            "isp": "Unknown",
        }

    def get_analytics(self) -> Dict[str, Any]:
        dist = Counter()
        ep_counts = Counter()
        hourly = {h: 0 for h in range(24)}

        for ev in self._attack_events:
            dist[ev.get("attackType", "API Abuse")] += 1
            ep_counts[ev.get("targetEndpoint", "")] += 1
            ts = _parse_ts(ev.get("timestamp"))
            hourly[ts.hour] = hourly.get(ts.hour, 0) + 1

        return {
            "attackTypeDistribution": [
                {"name": k, "value": v} for k, v in dist.most_common()
            ],
            "topEndpoints": [
                {"endpoint": k, "attacks": v} for k, v in ep_counts.most_common(5)
            ],
            "hourlyAttackVolume": [
                {"hour": f"{h:02d}:00", "attacks": hourly.get(h, 0)} for h in range(24)
            ],
        }

    # -------------------------
    # Tailing / ingestion
    # -------------------------

    def tail_once(self, log_path: str) -> int:
        if not os.path.exists(log_path):
            return 0

        processed = 0
        with open(log_path, "r", encoding="utf-8") as f:
            f.seek(self._file_pos)
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except Exception:
                    continue
                self.process_request_event(event)
                processed += 1
            self._file_pos = f.tell()
        self._last_tail_ts = time.time()
        return processed

    def process_request_event(self, e: Dict[str, Any]) -> None:
        ip = str(e.get("ip") or "unknown")
        endpoint = str(e.get("endpoint") or "")
        ts = _parse_ts(e.get("timestamp"))
        ts_s = ts.timestamp()

        st = self._attackers.get(ip)
        if not st:
            st = AttackerState(ip=ip, first_seen=ts, last_seen=ts)
            self._attackers[ip] = st

        st.last_seen = ts
        st.total_requests += 1
        st.recent_requests_s.append(ts_s)
        st.endpoint_counts[endpoint] += 1

        status = int(e.get("status_code") or 200)
        auth_success = e.get("auth_success", None)

        # ── Prune windows before reading lengths ──────────────────────────
        self._prune_older_than(st.recent_requests_s, ts_s - 60)
        self._prune_older_than(st.recent_failed_logins_s, ts_s - 60)

        # ── RULES (always run first) ───────────────────────────────────────

        # Rule 1: Recon / path traversal
        if endpoint in ("/.env", "/wp-admin/admin-ajax.php", "/wp-admin") or ".." in endpoint:
            st.recon_hits += 1
            self._recompute_risk(st, ts_s)
            self._emit(st, e, attack_type="Path Traversal", source="rule")
            return

        # Rule 2: Brute force (failed login tracking)
        if endpoint == "/login" and auth_success is False:
            st.recent_failed_logins_s.append(ts_s)
            self._prune_older_than(st.recent_failed_logins_s, ts_s - 60)
            self._recompute_risk(st, ts_s)
            if len(st.recent_failed_logins_s) >= 10:
                st.brute_force_emits += 1
                if st.brute_force_emits % 3 == 0:
                    self._emit(st, e, attack_type="Brute Force", source="rule")
                return
            self._emit(st, e, attack_type="Credential Stuffing", source="rule")
            return

        # Rule 3: IDOR enumeration
        m = _RE_USER_ID.match(endpoint)
        if m:
            user_id = int(m.group(1))
            if st.last_user_id is not None and user_id == st.last_user_id + 1:
                st.sequential_id_hits += 1
            else:
                st.sequential_id_hits = 0
            st.last_user_id = user_id
            self._recompute_risk(st, ts_s)
            if st.sequential_id_hits >= 1:
                self._emit(st, e, attack_type="IDOR", source="rule")
                return

        # Rule 4: High-frequency API abuse
        self._recompute_risk(st, ts_s)
        if len(st.recent_requests_s) > 120:
            self._emit(st, e, attack_type="API Abuse", source="rule")
            return

        # ── ML CLASSIFIER (runs when no rule matched confidently) ─────────
        # Builds the same feature vector attack_classifier.py expects.
        if self._classifier_ready and self._classifier is not None:
            features = {
                "endpoint": endpoint,
                "method": e.get("method", "GET"),
                "status_code": status,
                "payload_size": int(e.get("payload_size") or 0),
                "requests_in_60s": len(st.recent_requests_s),
                "failed_logins_60s": len(st.recent_failed_logins_s),
                "sequential_id_hits": st.sequential_id_hits,
            }
            ml_label, confidence = self._classifier.classify(features)

            if self._classifier.is_confident(confidence) and status >= 400:
                # Only emit if the ML label is suspicious AND the request
                # actually got an error response (reduces false positives).
                self._emit(st, e, attack_type=ml_label, source="ml", confidence=confidence)
                return

        # ── Catch-all: plain 4xx with no rule or ML match ─────────────────
        if status >= 400:
            self._emit(st, e, attack_type="Scanner", source="rule")
            return

        # Non-suspicious requests are not emitted (reduces noise).

    # -------------------------
    # Helpers
    # -------------------------

    def _emit(
        self,
        st: AttackerState,
        e: Dict[str, Any],
        attack_type: AttackType,
        source: str = "rule",         # "rule" or "ml"
        confidence: float = 1.0,      # ML confidence (1.0 for rules)
    ) -> None:
        st.behavior_counts[attack_type] += 1
        risk = _risk_level(st.risk_score)

        # ── Live terminal alert ────────────────────────────────────────────────
        try:
            from app.core.terminal import print_attack
            print_attack(
                ip=st.ip,
                attack_type=attack_type,
                endpoint=str(e.get("endpoint", "")),
                risk=risk,
                source=source,
                conf=confidence if source == "ml" else None,
            )
        except Exception:
            pass

        ts = _parse_ts(e.get("timestamp")).timestamp()
        st.recent_attack_types.append((ts, attack_type))
        self._prune_recent_attack_types(st, ts - 600)

        self._attack_events.append(
            {
                "id": e.get("request_id") or f"{st.ip}-{int(time.time()*1000)}",
                "timestamp": e.get("timestamp"),
                "attackerIP": st.ip,
                "targetEndpoint": e.get("endpoint"),
                "attackType": attack_type,
                "riskLevel": risk,
                "userAgent": e.get("user_agent", ""),
                "payload": None,
                "detectionSource": source,        # NEW: visible in frontend
                "mlConfidence": round(confidence, 3) if source == "ml" else None,
            }
        )

    def _prune_older_than(self, dq: Deque[float], threshold: float) -> None:
        while dq and dq[0] < threshold:
            dq.popleft()

    def _recompute_risk(self, st: AttackerState, now_s: float) -> None:
        self._prune_older_than(st.recent_failed_logins_s, now_s - 60)
        self._prune_older_than(st.recent_requests_s, now_s - 60)

        failed_60s = len(st.recent_failed_logins_s)
        rpm = len(st.recent_requests_s)
        seq = st.sequential_id_hits

        score = 10
        score += min(40, failed_60s * 4)
        score += min(24, seq * 6)
        score += min(20, max(0, rpm - 80) // 8)
        score += min(15, st.recon_hits * 3)

        st.risk_score = max(0, min(100, score))

    def _classify(self, st: AttackerState) -> AttackerClassification:
        now_s = _utc_now().timestamp()
        self._prune_recent_attack_types(st, now_s - 600)

        counts = Counter(t for _, t in st.recent_attack_types)
        brute = counts.get("Brute Force", 0) + counts.get("Credential Stuffing", 0)
        idor = counts.get("IDOR", 0)
        recon = counts.get("Path Traversal", 0) + counts.get("Scanner", 0)
        abuse = counts.get("API Abuse", 0)

        if (len(st.recent_failed_logins_s) >= 10) or (brute >= 3 and brute >= max(idor, abuse, recon)):
            return "Brute-forcer"
        if idor >= 3 and idor >= max(brute, abuse, recon):
            return "Manual Attacker"
        return "Scanner"

    def _prune_recent_attack_types(self, st: AttackerState, threshold: float) -> None:
        while st.recent_attack_types and st.recent_attack_types[0][0] < threshold:
            st.recent_attack_types.popleft()

    def _requests_per_minute(self, st: AttackerState, now: datetime) -> List[int]:
        now_s = now.timestamp()
        buckets = [0] * 60
        for ts_s in st.recent_requests_s:
            delta_min = int((now_s - ts_s) // 60)
            if 0 <= delta_min < 60:
                buckets[59 - delta_min] += 1
        return buckets

    def _timeline_for_ip(self, ip: str, limit: int = 20) -> List[Dict[str, Any]]:
        out = []
        for ev in reversed(self._attack_events):
            if ev.get("attackerIP") == ip:
                out.append(ev)
                if len(out) >= limit:
                    break
        return list(reversed(out))