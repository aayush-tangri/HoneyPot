"""
ml_simulation.py
----------------
Simulates attack requests and runs them through the ML classifier.
Run this from the backend folder:
    python ml_simulation.py

No backend server needed — this is a standalone script.
"""

import random
import sys
import os

# Fix Unicode output on Windows terminals
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# Make sure Python can find the app module
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.services.attack_classifier import AttackClassifier

# ── Colour helpers for terminal output ────────────────────────────────────────
def col(text, code):
    return f"\033[{code}m{text}\033[0m"

RED    = lambda t: col(t, "91")
GREEN  = lambda t: col(t, "92")
YELLOW = lambda t: col(t, "93")
CYAN   = lambda t: col(t, "96")
BOLD   = lambda t: col(t, "1")

# ── Mock request generator ─────────────────────────────────────────────────────

SCENARIOS = [
    {
        "label": "Brute Force",
        "description": "Attacker hammering /login with wrong passwords",
        "requests": [
            {
                "endpoint": "/login",
                "method": "POST",
                "status_code": 401,
                "payload_size": 140,
                "requests_in_60s": random.randint(80, 120),
                "failed_logins_60s": random.randint(15, 30),
                "sequential_id_hits": 0,
            }
            for _ in range(5)
        ],
    },
    {
        "label": "Credential Stuffing",
        "description": "Slower login attempts with a list of known passwords",
        "requests": [
            {
                "endpoint": "/login",
                "method": "POST",
                "status_code": 401,
                "payload_size": 150,
                "requests_in_60s": random.randint(10, 25),
                "failed_logins_60s": random.randint(3, 7),
                "sequential_id_hits": 0,
            }
            for _ in range(5)
        ],
    },
    {
        "label": "IDOR",
        "description": "Attacker enumerating /api/users/1, /2, /3...",
        "requests": [
            {
                "endpoint": f"/api/users/{i}",
                "method": "GET",
                "status_code": 200 if i <= 3 else 404,
                "payload_size": 0,
                "requests_in_60s": random.randint(10, 20),
                "failed_logins_60s": 0,
                "sequential_id_hits": i,
            }
            for i in range(1, 6)
        ],
    },
    {
        "label": "API Abuse",
        "description": "Extremely high request rate to any endpoint",
        "requests": [
            {
                "endpoint": "/api/admin/stats",
                "method": "GET",
                "status_code": 200,
                "payload_size": 0,
                "requests_in_60s": random.randint(150, 200),
                "failed_logins_60s": 0,
                "sequential_id_hits": 0,
            }
            for _ in range(5)
        ],
    },
    {
        "label": "Path Traversal",
        "description": "Attacker probing for sensitive files",
        "requests": [
            {
                "endpoint": ep,
                "method": "GET",
                "status_code": 403,
                "payload_size": 0,
                "requests_in_60s": random.randint(5, 15),
                "failed_logins_60s": 0,
                "sequential_id_hits": 0,
            }
            for ep in ["/.env", "/wp-admin", "/wp-admin/admin-ajax.php", "/../etc/passwd", "/.env"]
        ],
    },
    {
        "label": "Scanner",
        "description": "Bot probing random endpoints looking for vulnerabilities",
        "requests": [
            {
                "endpoint": ep,
                "method": "GET",
                "status_code": 404,
                "payload_size": 0,
                "requests_in_60s": random.randint(15, 30),
                "failed_logins_60s": 0,
                "sequential_id_hits": 0,
            }
            for ep in ["/phpmyadmin", "/admin", "/config.php", "/backup.zip", "/api/v2/users"]
        ],
    },
]

# ── Main ───────────────────────────────────────────────────────────────────────

def risk_colour(confidence: float) -> str:
    if confidence >= 0.80:
        return RED(f"{confidence:.0%}")
    if confidence >= 0.55:
        return YELLOW(f"{confidence:.0%}")
    return GREEN(f"{confidence:.0%}")


def run_simulation():
    print(BOLD("\n╔══════════════════════════════════════════════════════╗"))
    print(BOLD("║        HoneyGuard — ML Classifier Simulation        ║"))
    print(BOLD("╚══════════════════════════════════════════════════════╝\n"))

    print("Training ML classifier on synthetic data...")
    classifier = AttackClassifier()
    print(GREEN("✓ Classifier ready!\n"))

    total = 0
    correct = 0

    for scenario in SCENARIOS:
        true_label = scenario["label"]
        print(BOLD(f"━━━ Scenario: {true_label} ━━━"))
        print(CYAN(f"    {scenario['description']}"))
        print()

        scenario_correct = 0
        for i, req in enumerate(scenario["requests"]):
            predicted, confidence = classifier.classify(req)
            is_correct = predicted == true_label
            if is_correct:
                correct += 1
                scenario_correct += 1
            total += 1

            tick = GREEN("✓") if is_correct else RED("✗")
            conf_str = risk_colour(confidence)

            print(
                f"  {tick} Request {i+1} "
                f"| endpoint: {req['endpoint']:<35} "
                f"| predicted: {predicted:<22} "
                f"| confidence: {conf_str}"
            )

        scenario_acc = scenario_correct / len(scenario["requests"]) * 100
        print(f"\n  Scenario accuracy: {scenario_correct}/{len(scenario['requests'])} ({scenario_acc:.0f}%)\n")

    # ── Summary ──────────────────────────────────────────────────────────────
    overall = correct / total * 100
    print(BOLD("╔══════════════════════════════════════════════════════╗"))
    print(BOLD(f"║  Overall accuracy: {correct}/{total} requests ({overall:.0f}%)".ljust(53) + "║"))
    print(BOLD("╚══════════════════════════════════════════════════════╝\n"))

    if overall >= 80:
        print(GREEN("✓ ML classifier is performing well!"))
    elif overall >= 60:
        print(YELLOW("~ ML classifier is okay but could be improved."))
    else:
        print(RED("✗ ML classifier needs improvement."))
    print()


if __name__ == "__main__":
    run_simulation()