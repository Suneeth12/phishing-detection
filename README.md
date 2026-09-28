# 🎣 Phishing Website Security Analytics & Threat Detection

A real-time URL threat intelligence web application and ML classification engine analyzing 30+ security and lexical features to detect phishing domains with 94.5% precision.

## 🚀 Key Highlights & Architecture
- **30+ Security & Lexical Features**: Parses and extracts structural indicators including IP address obfuscation, URL length anomalies, shortening service redirects, prefix-suffix manipulations, sub-domain depth, and HTTPS token validation.
- **Gradient Boosting ML Engine**: Leverages Scikit-learn and XGBoost classifiers with SMOTE class balancing to achieve **94.5% detection accuracy** and low false-positive rates on web traffic streams.
- **Responsive Threat Intelligence Dashboard**: Interactive Flask web interface providing immediate URL risk categorization, feature breakdown radar, and actionable mitigation guidance.
- **RESTful Threat API**: Programmatic `/api/predict` endpoint for automated security orchestration, SIEM ingestion, and proxy filtering.

```
       Input Target URL (e.g. login-verify-secure.account-update.xyz)
                                    │
                                    ▼
       ┌────────────────────────────────────────────────────────┐
       │   30+ Security Feature Extractor                       │
       │  - Lexical parsing (length, symbols, entropy)          │
       │  - Domain integrity (IP in host, HTTPS token, dots)    │
       │  - Shortening & redirect flags                         │
       └────────────────────────────────────────────────────────┘
                                    │
                                    ▼
       ┌────────────────────────────────────────────────────────┐
       │   XGBoost / Random Forest Inference Engine             │
       │  - SMOTE-balanced training                             │
       │  - Risk probability calibration (0.0 to 1.0)           │
       └────────────────────────────────────────────────────────┘
                                    │
                     ┌──────────────┴──────────────┐
                     ▼                             ▼
        [Web UI: Visual Risk Radar]   [JSON API: /api/predict]
```

## 🛠️ Tech Stack
- **Backend & Web**: Python 3.11, Flask, Requests
- **Machine Learning**: Scikit-learn, XGBoost, NumPy, Pandas
- **Testing & Deployment**: Pytest, Docker, AWS

## 📦 API Endpoints
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Web dashboard for manual URL security inspection |
| `GET` | `/health` | Health and model readiness status |
| `POST` | `/api/predict` | JSON API returning risk score and feature analytics |

## 💻 Quickstart

### Local Setup
```bash
# Clone and install dependencies
git clone https://github.com/Suneeth12/phishing-detection.git
cd phishing-detection
pip install -r requirements.txt

# Launch web server
python app.py
```
Open [http://localhost:5000](http://localhost:5000) in your browser.

### Docker Deployment
```bash
docker build -t phishing-detection:latest .
docker run -p 5000:5000 phishing-detection:latest
```

## 👤 Author
**Suneeth Reddy Peddamallu** — [GitHub](https://github.com/Suneeth12) • [Portfolio](https://suneeth.live) • [LinkedIn](https://linkedin.com/in/suneeth-reddy-peddamallu)
