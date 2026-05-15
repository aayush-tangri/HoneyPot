# Intelligent Honeypot System with Real-Time Attack Detection

A full-stack cybersecurity honeypot that simulates a vulnerable web server, detects attacks in real time using a rule-based engine and ML classifier, and visualises threat activity on a live dashboard.

---

## Overview

A honeypot is a deliberately vulnerable system designed to attract attackers. Instead of blocking them, it logs and analyses everything they do. This project combines a fake vulnerable API, a real-time detection engine, and a machine learning classifier to identify and categorise attack patterns as they happen.

---

## Features

- **Intentionally vulnerable REST API** simulating real-world attack surfaces
- **Real-time detection engine** that classifies attacks and computes per-IP risk scores
- **ML-based attack classifier** using a Random Forest model to predict attack types
- **Live dashboard** with attack feeds, analytics charts, and per-attacker profiling
- **Structured request logging** — every request is recorded as JSON for analysis

---

## Architecture

```
Attacker sends request
        ↓
FastAPI backend receives it
        ↓
Middleware logs request to requests.jsonl
        ↓
Detection Engine processes it in real time
        ↓
Rules run first → if match → emit attack event
        ↓
If no rule matches → ML classifier runs
        ↓
Frontend polls /api/attacks every 5 seconds
        ↓
Dashboard updates live
```

---

## Vulnerabilities (Intentional)

| Endpoint | Vulnerability | Description |
|---|---|---|
| `POST /login` | No rate limiting | Allows unlimited brute force attempts |
| `GET /api/users/{id}` | IDOR | No ownership check — any user ID accessible |
| `POST /api/upload` | Weak validation | Accepts any file type |
| `GET /api/admin/stats` | Broken RBAC | No authorisation check on admin endpoint |

---

## Detection Engine

The rule-based engine tracks per-IP behaviour using rolling time windows and detects:

- **Brute Force** — 10+ failed logins within 60 seconds
- **Credential Stuffing** — slower, deliberate failed login attempts
- **IDOR** — sequential user ID enumeration
- **API Abuse** — over 120 requests per minute
- **Path Traversal** — requests to `.env`, `wp-admin`, or paths containing `..`
- **Scanner** — general 4xx probing behaviour

Each IP gets a dynamic risk score (0–100) based on recent behaviour, and is classified as a **Scanner**, **Brute-forcer**, or **Manual Attacker**.

---

## ML Classifier

A scikit-learn Random Forest classifier runs as a fallback when no rule matches. It takes 7 features per request:

| Feature | Description |
|---|---|
| `endpoint_id` | Encoded endpoint category |
| `method_id` | HTTP method (GET, POST, etc.) |
| `status_code` | HTTP response code |
| `payload_size` | Request body size in bytes |
| `requests_in_60s` | Request rate in last 60 seconds |
| `failed_logins_60s` | Failed login count in last 60 seconds |
| `sequential_id_hits` | Sequential user ID enumeration count |

Trained on synthetic data (400 samples per class) with ~90% accuracy across 6 attack categories. The model only fires when confidence exceeds 55% and the request received an error response, minimising false positives.

---

## Dashboard

Three pages built with React, TypeScript, and Tailwind CSS:

- **Live Attack Feed** — real-time table of detected attacks, updating every 5 seconds
- **Analytics** — attack type distribution, top targeted endpoints, hourly volume chart
- **Attacker Profile** — per-IP risk score, classification, request rate chart, and full attack timeline

---

## Tech Stack

**Backend:** Python, FastAPI, scikit-learn, NumPy, Uvicorn

**Frontend:** React, TypeScript, Tailwind CSS, Vite, shadcn/ui

---

## Running Locally

### Backend
```bash
cd backend
python -m venv venv
venv\Scripts\activate        # Windows
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8001
```

### Frontend
```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:8080` in your browser.

### Simulate Attacks
```bash
cd backend
python simulate.py
```

---

## Project Structure

```
├── backend/
│   ├── app/
│   │   ├── main.py                  # FastAPI app, vulnerable endpoints, middleware
│   │   ├── core/
│   │   │   ├── log_writer.py        # Async JSONL log writer
│   │   │   └── logging_middleware.py
│   │   └── services/
│   │       ├── detection_engine.py  # Rule-based detection, risk scoring
│   │       └── attack_classifier.py # ML Random Forest classifier
│   ├── logs/                        # Request logs (auto-generated)
│   └── requirements.txt
├── frontend/
│   └── src/
│       ├── pages/                   # Dashboard, Analytics, AttackerProfile
│       ├── components/              # UI components and charts
│       ├── lib/api.ts               # Backend API calls
│       └── data/mockData.ts         # Fallback mock data
└── simulate.py                      # Attack simulation script
```
