# AI Email Phishing Analyzer

A full-stack SOC-style triage tool that analyzes emails for phishing indicators using a **hybrid scoring engine** — rule-based heuristics, live threat intelligence, and an LLM-based analysis layer — and produces an auditable verdict with a downloadable incident report.

Built to mirror how a real Tier-1 SOC analyst actually triages a suspicious email: check authentication headers, check the URLs/domains against threat feeds, read the content for social-engineering patterns, and reach a documented verdict — not a black-box "AI says phishing" button.

---

## Why this project exists

Most phishing-detection demos are either (a) a single regex list pretending to be a product, or (b) a thin wrapper around one LLM call with no fallback and no way to explain *why* it flagged something. This project is built the way a security tool actually needs to work in production:

- **Every external dependency degrades gracefully.** No API key, no network, a rate-limited provider, an unparseable model response — none of it crashes the app or produces a silently wrong verdict.
- **The verdict is explainable, not just a number.** Every triggered rule is named. Every score component is broken down. A PDF report exists because a real SOC analyst needs something to attach to a ticket.
- **The AI layer is one input among several, not the whole system.** It's weighted at 40% specifically so a hallucinating or unavailable model can't singlehandedly mis-verdict an email — the rule-based engine and threat intel still carry the analysis.

---

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌───────────────────┐
│  parser.py  │ --> │ heuristics.py│ --> │                    │
│ (.eml/text) │     │ (rule engine)│     │                    │
└─────────────┘     └──────────────┘     │                    │
                                          │   scoring.py       │ --> verdict
┌─────────────────┐                      │ (weighted blend +  │     + report.py
│ threat_intel.py │ -------------------> │  graceful degrade) │     (PDF export)
│ (VirusTotal/WHOIS)│                    │                    │
└─────────────────┘                      │                    │
                                          │                    │
┌─────────────────┐                      │                    │
│  ai_analysis.py │ -------------------> │                    │
│ (Ollama/Groq)   │                      └───────────────────-┘
└─────────────────┘
                                                  |
                                                  v
                                          database.py (SQLite)
                                          -> history, filters, stats
```

Every module in the pipeline has a single, testable responsibility, and every module that touches an external system (`threat_intel.py`, `ai_analysis.py`) returns a result dict with an `available`/`ran` flag rather than raising — so `scoring.py` always knows exactly how much confidence to place in each input.

---

## Tech stack

| Layer | Technology | Why |
|---|---|---|
| Backend | Flask 3.0, Python 3.13 | Lightweight, explicit routing, no framework magic to obscure the security logic |
| Database | SQLite | Zero-config for a portfolio deploy; schema is simple enough not to need an ORM |
| Email parsing | Python's `email` stdlib + regex | Full MIME/header parsing for `.eml`, best-effort regex fallback for pasted text |
| Threat intel | VirusTotal API v3, `python-whois` | Live URL/IP reputation + domain-age lookup |
| AI analysis | Ollama (local, `llama3.2:1b`) / Groq (hosted, `llama-3.3-70b-versatile`) | Dual-provider — free local inference for development, free hosted inference for deployment |
| PDF generation | ReportLab (Platypus) | Structured multi-section document, not raw canvas drawing |
| Testing | pytest, unittest.mock | 52 tests, external calls mocked — no live API calls in CI |
| Deployment | Render (`render.yaml` Blueprint), Gunicorn | Free-tier-compatible, one-click Blueprint deploy |

---

## The scoring engine — how a verdict is actually reached

This is the core design decision of the project, so it's worth explaining in detail.

### 1. Heuristic engine (`heuristics.py`) — offline, zero-cost, zero-latency
Five rule-based checks run on every email with no external calls:

| Check | Weight | What it catches |
|---|---|---|
| SPF/DKIM/DMARC failure | 35 | Spoofed sender domain (`.eml` uploads only — pasted text has no auth headers, so this check is skipped rather than guessed) |
| Urgency/threat language | 20 | "Account suspended", "verify immediately", "24 hours" — classic social engineering |
| Display name vs. domain mismatch | 15 | "PayPal Support" sending from `secure-login-update.com` |
| IP-literal URL | 15 | Links like `http://185.23.44.1/login` instead of a domain |
| Risky/macro-enabled attachment | 15 | `.exe`, `.scr`, `.js`, `.docm` and similar |

### 2. Threat intelligence enrichment (`threat_intel.py`) — live, but optional
If `VIRUSTOTAL_API_KEY` is set, every extracted URL/IP is checked against VirusTotal's reputation database, and the sending domain's registration age is pulled via WHOIS (domains younger than 30 days are a strong phishing signal — attackers register-and-burn). If enrichment ran, it's blended with the offline heuristic score at **70/30** (heuristic/enrichment). If it didn't run (no key, network down, rate-limited), the app silently falls back to the pure offline heuristic score — no crash, no missing verdict.

### 3. AI analysis layer (`ai_analysis.py`) — the LLM opinion, weighted deliberately low
A structured prompt asks the model to act as a SOC analyst and return a JSON score + explanation. This layer is intentionally **provider-agnostic and always optional**:

- `AI_PROVIDER=ollama` (local dev) — runs against a local `llama3.2:1b` model. Free, private, works offline.
- `AI_PROVIDER=groq` (production) — hosted, OpenAI-compatible API on Groq's genuinely free tier (no credit card). Chosen after evaluating current free-LLM options because Render's free web tier has no persistent daemon or RAM to host Ollama.

### 4. Final blend (`scoring.py`) — the part most portfolio projects get wrong
Naively, you'd blend heuristic and AI scores 60/40 always. **The bug with that**: if the AI layer is disabled or unreachable, its score defaults to 0 — and blending a fake 0 at 40% weight silently drags *every* verdict toward CLEAN, regardless of how malicious the email actually is (a heuristic score of 80 would incorrectly become 48 = SUSPICIOUS instead of 80 = MALICIOUS).

The fix: every AI-layer result carries an explicit `available: bool`. When `False`, the heuristic+enrichment score carries **100%** of the verdict instead of being diluted — and the UI and PDF report both explicitly disclose "AI layer did not run" rather than hiding the reduced confidence. This is tested directly (`test_ai_unavailable_uses_full_heuristic_weight`).

---

## Features

- **Dual input**: paste raw email text, or upload a real `.eml` file (full header/MIME parsing)
- **Explainable verdict**: MALICIOUS / SUSPICIOUS / CLEAN with a numeric score and every triggered rule named
- **History dashboard**: filter by verdict, search sender/subject, running stats bar (total/malicious/suspicious/clean)
- **PDF incident report**: one-click download of a formatted SOC report — verdict banner, score breakdown table, triggered indicators, and an explicit degraded-mode disclosure when the AI layer didn't run
- **Graceful degradation everywhere**: missing API key, network failure, rate limit (Groq 429), unparseable model output — every failure mode returns a usable result instead of a 500 error

---

## Testing

52 automated tests across 6 modules, run with `pytest`. External services (VirusTotal, WHOIS, Ollama, Groq) are mocked with `unittest.mock` so the suite runs fully offline and deterministically — no live API calls, no flaky network-dependent tests.

```bash
python3 -m pytest tests/ -v
```

Notable test coverage:
- Every heuristic rule individually (clean email, each indicator triggered in isolation, score cap at 100)
- Threat intel: malicious/clean VirusTotal responses, young/old domain WHOIS, missing-key graceful fallback
- AI analysis: successful parse, markdown-wrapped JSON, out-of-range score clamping, connection error, timeout, unparseable response — for **both** Ollama and Groq providers, plus rate-limit (429) and auth-failure (401) handling
- Scoring: the `ai_available` reweighting fix, specifically verified so it can't regress
- PDF report: valid PDF bytes generated, no broken glyphs (a real bug caught during development — Unicode bullet/warning characters aren't in ReportLab's base Helvetica font and rendered as garbage), degraded-mode warning renders correctly, missing/null fields don't crash generation

---

## Project structure

```
ai-email-phishing-analyzer/
├── app.py                   # Flask routes: /, /history, /report/<id>
├── database.py               # SQLite schema, CRUD, filtered history queries
├── analyzer/
│   ├── parser.py             # .eml + pasted-text email parsing
│   ├── heuristics.py         # 5-rule offline scoring engine
│   ├── threat_intel.py       # VirusTotal + WHOIS enrichment
│   ├── ai_analysis.py        # Ollama/Groq dual-provider AI layer
│   ├── scoring.py            # Weighted blend + degraded-mode reweighting
│   └── report.py             # ReportLab PDF incident report generator
├── templates/                 # index.html, history.html (Jinja2)
├── static/style.css
├── tests/                     # 52 tests, 6 files, sample .eml fixtures
├── render.yaml                 # Render Blueprint deployment config
├── setup.sh                    # One-shot local setup (venv, deps, secret key, Ollama check)
└── requirements.txt
```

---

## Local setup

```bash
git clone <your-repo-url>
cd ai-email-phishing-analyzer
chmod +x setup.sh
./setup.sh
```

`setup.sh` creates the venv, installs dependencies, generates a real `FLASK_SECRET_KEY` (not a placeholder), checks for Ollama, and starts the app. Or do it manually:

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env      # fill in VIRUSTOTAL_API_KEY (optional), AI provider settings
python3 app.py            # visit http://127.0.0.1:5000
```

---

## Deployment (Render)

The included `render.yaml` Blueprint deploys directly with `AI_PROVIDER=groq` set, so the full 60/40 heuristic+AI verdict works in production — not a degraded demo. Env vars (`VIRUSTOTAL_API_KEY`, `FLASK_SECRET_KEY`, `GROQ_API_KEY`) are entered through Render's encrypted dashboard, never committed to the repo (`.gitignore` enforces this for local `.env` too).

---

## Design decisions worth asking me about

- Why 60/40 heuristic/AI split, and why it's *not* fixed when AI is unavailable
- Why VirusTotal enrichment is 70/30 blended into the heuristic score rather than a separate weighted category
- Why pasted-text emails skip the SPF/DKIM/DMARC check entirely instead of scoring it as "pass"
- Why the AI provider is swappable (Ollama vs Groq) instead of hardcoding one
- The ReportLab glyph bug and how it was caught (rendering the PDF to an image and extracting text, not just "it compiled")
