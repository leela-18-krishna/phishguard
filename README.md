
# 🛡️ PhishGuard — AI-Powered Phishing & Social Engineering Detector

PhishGuard is a full-stack security application that uses machine learning to detect phishing emails in real time, explains *why* an email looks suspicious, and gives every user a personal, authenticated dashboard with scan history.

**Live demo:** https://phishguard-app-coral.vercel.app
**Live API docs:** https://phishguard-three.vercel.app/docs

---

## Why this project

Phishing remains one of the most common entry points for real-world cyberattacks — a large majority of breaches still start with a deceptive email. Most beginner phishing-detection projects stop at "train a classifier on a dataset." PhishGuard goes further: it's a deployed, authenticated, multi-user web application with a real database, real email delivery, and an explainability layer so the output is actually useful to a person deciding whether to trust an email.

## Features

- **ML-based phishing classifier** — Random Forest model trained on 18,000+ labeled emails, ~96% accuracy
- **Explainability layer** — flags *why* an email was classified as suspicious (urgency language, embedded links, requests for credentials, reward/prize bait), not just a label
- **Full authentication system** — signup, login by username, JWT-based sessions, bcrypt password hashing
- **Gmail-restricted signup** with server-side validation
- **Password reset via real email** — a 6-digit verification code is emailed through Gmail SMTP, with a masked-email confirmation step so users never have to retype their address
- **Per-user scan history** stored in MongoDB, with single-scan delete and clear-all
- **Soft-delete architecture** — deleted accounts and scan history are moved to separate `deleted_users` / `deleted_scans` collections rather than being destroyed, preserving an audit trail
- **Dark mode** with a custom neon-blue security-themed background in dark mode
- **Mobile-responsive UI**
- **Stats dashboard** — total scans, phishing vs. safe breakdown

## Tech stack

**Backend:** Python, FastAPI, Pydantic, PyMongo, python-jose (JWT), Passlib + bcrypt, scikit-learn, joblib
**Frontend:** Vanilla HTML/CSS/JavaScript (no framework — deliberately lightweight)
**Database:** MongoDB Atlas
**Auth:** JWT bearer tokens, bcrypt-hashed passwords
**Email:** Gmail SMTP (smtplib) for password-reset codes
**Deployment:** Vercel (both the FastAPI backend, running as a Python serverless function, and the static frontend)

## Architecture
┌─────────────────┐         ┌──────────────────────┐         ┌─────────────────┐
│   Frontend       │  HTTPS  │   FastAPI Backend     │  PyMongo │   MongoDB Atlas  │
│   (Vercel)       │ ──────► │   (Vercel serverless) │ ───────► │                  │
│   index.html     │ ◄────── │   api/index.py        │ ◄─────── │  users, scans,   │
└─────────────────┘         │                        │         │  password_resets,│
│  - JWT auth            │         │  deleted_users,  │
│  - Random Forest model │         │  deleted_scans   │
│  - Gmail SMTP          │         └─────────────────┘
└──────────────────────┘
## Machine learning model

- **Dataset:** ~18,000 labeled emails (phishing / safe)
- **Preprocessing:** cleaned missing values, converted text to numerical features using TF-IDF (5,000-word vocabulary, English stop words removed)
- **Model:** Random Forest Classifier (100 estimators)
- **Results:** 96% accuracy, 97% recall on the phishing class (prioritizing catching real phishing attempts over minimizing false positives, which matters more for a security tool)

Training notebook: [`PhishGuard_model_training.ipynb`](./PhishGuard_model_training.ipynb)

## API endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/signup` | Create an account (Gmail-only email, unique username) |
| POST | `/login` | Log in with username + password, returns a JWT |
| GET | `/me` | Get the logged-in user's profile |
| POST | `/forgot-password` | Look up account by username, returns a masked email for confirmation |
| POST | `/forgot-password/send` | Sends a 6-digit reset code to the registered email |
| POST | `/reset-password` | Reset password using the emailed code |
| POST | `/predict` | Analyze an email, returns prediction + confidence + red flags (auth required) |
| GET | `/history` | Get the logged-in user's scan history (auth required) |
| DELETE | `/history` | Clear all scan history (soft-deleted) |
| DELETE | `/history/{scan_id}` | Delete a single scan (soft-deleted) |
| DELETE | `/account` | Delete account and all data (soft-deleted) |

## Running locally

```bash
# Clone the repo
git clone https://github.com/leela-18-krishna/phishguard.git
cd phishguard

# Set up a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create a .env file with:
# MONGO_URI=your_mongodb_connection_string
# JWT_SECRET=your_random_secret
# EMAIL_USER=your_gmail_address
# EMAIL_PASSWORD=your_gmail_app_password

# Run the backend
uvicorn api.index:app --reload

# Serve the frontend (in a separate terminal)
python3 -m http.server 5500
```

Then open `http://localhost:5500/index.html` (make sure `API_BASE` in `index.html` points to `http://127.0.0.1:8000` for local testing).

## Security notes

- Passwords are never stored in plain text — bcrypt hashing only
- JWT tokens expire after 24 hours
- Gmail-only signup restriction ensures every account has a real, reachable email for password recovery
- Deleted data is soft-deleted (moved to separate collections) rather than destroyed, which is a deliberate design choice for auditability

## Future improvements

- Deepfake voice/video detection module (planned)
- Rate limiting on auth endpoints
- Email verification at signup (currently only Gmail format is validated, not deliverability)

---
Built as a hands-on project to explore applied ML, authentication systems, and full-stack deployment.
