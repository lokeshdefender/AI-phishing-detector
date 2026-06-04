# Phishing Analyzer MVP

A FastAPI-based web service to analyze email text for phishing indicators and threats.

## Features

- **Email Analysis**: Paste email text and receive a phishing risk score (0-100)
- **Indicators**: Detects suspicious keywords, urgency language, credential harvesting attempts, brand impersonation, and more
- **Domain Intelligence**: WHOIS domain age lookup, DNS record validation, suspicious TLD detection
- **Explanations**: Clear, actionable recommendations for each detected indicator
- **Web UI**: Clean, modern interface for easy email analysis
- **Tests**: Comprehensive pytest suite with automated test reporting

## Quick Start

### Local Setup

1. **Install dependencies**:
   ```bash
   python -m pip install -r requirements.txt
   ```

2. **Run the app**:
   ```bash
   python run.py
   ```
   or
   ```bash
   uvicorn app.main:app --reload
   ```

3. **Open browser**: http://127.0.0.1:8000

### Docker Setup

1. **Build and run with docker-compose**:
   ```bash
   docker-compose up
   ```

2. **Open browser**: http://127.0.0.1:8000

3. **Stop**: `docker-compose down`

## API Endpoint

### POST /analyze

Analyze email text for phishing indicators.

**Request**:
```json
{
  "email_text": "From: Unknown <user@example.com>\nPlease verify your password at https://example.com/login immediately!"
}
```

**Response**:
```json
{
  "urls": ["https://example.com/login"],
  "score": 65,
  "confidence": 80,
  "sender": "user@example.com",
  "indicators": [
    {
      "indicator": "credential_harvest",
      "reason": "Credentials or sensitive info requested: password",
      "weight": 25
    },
    {
      "indicator": "urgency",
      "reason": "Urgent language detected (1 hits)",
      "weight": 6
    }
  ],
  "explanation": "..."
}
```

## Detection Signals

The analyzer evaluates:

- **Content**: Suspicious keywords, urgency language, credential requests
- **URLs**: IP addresses, shorteners, suspicious endpoints, brand impersonation
- **Sender**: Free email providers, sender-brand mismatch
- **Domain**: WHOIS age, DNS records, suspicious TLDs, registration history

## Running Tests

```bash
python -m pytest -v
```

Test results are saved to `tests/report.json`.

## Project Structure

```
.
├── app/
│   ├── __init__.py
│   ├── main.py           # FastAPI app and routes
│   ├── analyzer.py       # Core phishing detection logic
│   ├── utils.py          # URL extraction, WHOIS, DNS helpers
│   ├── models.py         # Pydantic response models
│   └── static/
│       ├── index.html    # Web UI
│       ├── styles.css    # Styling
│       └── app.js        # Frontend logic
├── tests/
│   ├── conftest.py       # Pytest configuration and reporting
│   ├── test_analyzer.py  # Unit tests
│   └── test_phishing_cases.py  # Integration test cases
├── requirements.txt      # Python dependencies
├── Dockerfile            # Docker image definition
├── docker-compose.yml    # Multi-container setup
├── README.md             # This file
└── run.py                # Development server launcher
```

## Dependencies

- `fastapi`: Web framework
- `uvicorn`: ASGI server
- `pydantic`: Data validation
- `python-whois`: WHOIS lookups
- `dnspython`: DNS resolution
- `pytest`: Testing framework

## GitHub Actions CI

Automated tests run on every push to `main` and `develop` branches. Test reports are uploaded as artifacts.

See `.github/workflows/tests.yml` for details.

## Notes

- This is an MVP; do not rely solely on it for security decisions
- Network-dependent checks (WHOIS, DNS) may be slow on first run
- Timeouts are in place for external lookups to prevent hanging

## License

MIT
