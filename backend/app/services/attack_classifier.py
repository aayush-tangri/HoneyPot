from __future__ import annotations

"""
attack_classifier.py
--------------------
ML-based attack classifier using a Random Forest trained on synthetic data.

How it works:
1. We generate synthetic training data based on known attack patterns.
2. A Random Forest is trained on that data at startup (takes ~1 second).
3. DetectionEngine calls `classify(features)` to get a predicted attack type
   + a confidence score for each request event.

Feature vector (7 features):
    [0] endpoint_id         - integer-encoded endpoint category
    [1] method_id           - integer-encoded HTTP method
    [2] status_code         - raw HTTP status code (e.g. 200, 404)
    [3] payload_size        - request body size in bytes
    [4] requests_in_60s     - how many requests this IP made in last 60s
    [5] failed_logins_60s   - failed login attempts in last 60s
    [6] sequential_id_hits  - count of sequential /api/users/{id} hits
"""

import random
from typing import Dict, List, Tuple

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

# ──────────────────────────────────────────────
# Label definitions
# ──────────────────────────────────────────────

ATTACK_LABELS = [
    "Brute Force",
    "Credential Stuffing",
    "IDOR",
    "API Abuse",
    "Path Traversal",
    "Scanner",
]

# ──────────────────────────────────────────────
# Endpoint encoding
# Endpoints are bucketed into semantic categories
# so the model generalises beyond exact strings.
# ──────────────────────────────────────────────

def _encode_endpoint(endpoint: str) -> int:
    """
    Map an endpoint string to an integer category.

    Categories:
        0 - login / auth
        1 - user lookup  (/api/users/*)
        2 - admin        (/api/admin/*)
        3 - upload       (/api/upload*)
        4 - recon/traversal (.env, wp-admin, ..)
        5 - other
    """
    ep = endpoint.lower()
    if "/login" in ep or "/auth" in ep:
        return 0
    if "/api/users" in ep:
        return 1
    if "/admin" in ep:
        return 2
    if "/upload" in ep:
        return 3
    if ".env" in ep or "wp-admin" in ep or ".." in ep:
        return 4
    return 5


def _encode_method(method: str) -> int:
    """GET=0, POST=1, PUT=2, DELETE=3, other=4"""
    return {"GET": 0, "POST": 1, "PUT": 2, "DELETE": 3}.get(method.upper(), 4)


# ──────────────────────────────────────────────
# Synthetic data generation
# ──────────────────────────────────────────────

def _make_sample(
    label: str,
    rng: random.Random,
) -> List[float]:
    """
    Generate ONE synthetic feature vector that is realistic for the given
    attack label. Values are intentionally noisy so the model doesn't overfit.
    """

    def jitter(base: float, spread: float) -> float:
        return max(0.0, base + rng.gauss(0, spread))

    if label == "Brute Force":
        # Repeated POSTs to /login, lots of failed logins, low payload variance.
        return [
            0,                              # endpoint: login
            1,                              # method: POST
            rng.choice([200, 401, 403]),    # status
            jitter(150, 30),                # payload_size (small form body)
            jitter(90, 20),                 # requests_in_60s (high rate)
            jitter(25, 8),                  # failed_logins_60s (key signal)
            0,                              # sequential_id_hits
        ]

    if label == "Credential Stuffing":
        # Similar to brute force but slower, fewer failures per window.
        return [
            0,
            1,
            rng.choice([200, 401]),
            jitter(150, 40),
            jitter(20, 10),                 # lower rate than pure brute force
            jitter(5, 3),                   # fewer failures per window
            0,
        ]

    if label == "IDOR":
        # Sequential GETs to /api/users/{id}, low rate, 200/404 mix.
        return [
            1,                              # endpoint: user lookup
            0,                              # method: GET
            rng.choice([200, 404]),
            0,                              # no body
            jitter(15, 5),                  # moderate rate
            0,
            jitter(8, 3),                   # sequential_id_hits (key signal)
        ]

    if label == "API Abuse":
        # Very high request rate to any endpoint.
        return [
            rng.randint(0, 5),              # any endpoint
            rng.choice([0, 1]),
            rng.choice([200, 404, 429]),
            jitter(200, 100),
            jitter(180, 40),                # very high rate (key signal)
            0,
            0,
        ]

    if label == "Path Traversal":
        # GETs to recon endpoints (.env, wp-admin, ..).
        return [
            4,                              # endpoint: recon
            0,                              # method: GET
            rng.choice([200, 403, 404]),
            0,
            jitter(10, 5),
            0,
            0,
        ]

    # Scanner (default / catch-all)
    return [
        rng.randint(0, 5),
        rng.choice([0, 1, 4]),
        rng.choice([400, 404, 403, 200]),
        jitter(50, 50),
        jitter(20, 10),
        0,
        0,
    ]


def _build_training_data(
    samples_per_class: int = 400,
    seed: int = 42,
) -> Tuple[np.ndarray, np.ndarray]:
    """
    Build a balanced synthetic training dataset.
    Returns X (n_samples, 7) and y (n_samples,) as numpy arrays.
    """
    rng = random.Random(seed)
    X_rows: List[List[float]] = []
    y_rows: List[str] = []

    for label in ATTACK_LABELS:
        for _ in range(samples_per_class):
            X_rows.append(_make_sample(label, rng))
            y_rows.append(label)

    return np.array(X_rows, dtype=np.float32), np.array(y_rows)


# ──────────────────────────────────────────────
# Classifier
# ──────────────────────────────────────────────

class AttackClassifier:
    """
    Thin wrapper around a scikit-learn RandomForestClassifier.

    Usage (inside DetectionEngine):
        classifier = AttackClassifier()   # trains immediately on init
        label, confidence = classifier.classify(features)
    """

    # Minimum confidence required before we trust the ML label over the rules.
    CONFIDENCE_THRESHOLD = 0.55

    def __init__(self, samples_per_class: int = 400, seed: int = 42) -> None:
        self._le = LabelEncoder()
        self._model = RandomForestClassifier(
            n_estimators=100,       # 100 decision trees
            max_depth=10,           # prevent overfitting
            random_state=seed,
            n_jobs=-1,              # use all CPU cores
        )
        self._train(samples_per_class, seed)

    # ── public API ────────────────────────────

    def classify(self, features: Dict) -> Tuple[str, float]:
        """
        Predict the attack type for a single request event.

        Args:
            features: dict with keys matching what DetectionEngine tracks:
                - endpoint       (str)
                - method         (str)
                - status_code    (int)
                - payload_size   (int)
                - requests_in_60s      (int)
                - failed_logins_60s    (int)
                - sequential_id_hits   (int)

        Returns:
            (predicted_label, confidence)  e.g. ("Brute Force", 0.87)
        """
        x = self._featurize(features)
        proba = self._model.predict_proba(x)[0]
        idx = int(np.argmax(proba))
        label = self._le.inverse_transform([idx])[0]
        confidence = float(proba[idx])
        return label, confidence

    def is_confident(self, confidence: float) -> bool:
        """Returns True if confidence clears the threshold."""
        return confidence >= self.CONFIDENCE_THRESHOLD

    # ── private ───────────────────────────────

    def _train(self, samples_per_class: int, seed: int) -> None:
        X, y_str = _build_training_data(samples_per_class, seed)
        y = self._le.fit_transform(y_str)
        self._model.fit(X, y)

    def _featurize(self, f: Dict) -> np.ndarray:
        """Convert a feature dict to a (1, 7) numpy array."""
        row = [
            _encode_endpoint(str(f.get("endpoint", ""))),
            _encode_method(str(f.get("method", "GET"))),
            float(f.get("status_code", 200)),
            float(f.get("payload_size", 0)),
            float(f.get("requests_in_60s", 0)),
            float(f.get("failed_logins_60s", 0)),
            float(f.get("sequential_id_hits", 0)),
        ]
        return np.array([row], dtype=np.float32)