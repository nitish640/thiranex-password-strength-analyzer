# Thiranex Cyber Security — Task 1: Password Strength Analyzer

> Thiranex dashboard: Task 1, due 30 Jun 2026 (overdue at build time, 13 Nov 2026).
> Develop a tool that evaluates the strength of user-entered passwords.

## What it does

- **Scores any password 0–100** — Weak (0–39), Fair (40–59), Good (60–79), Strong (80–100)
- **Checks length, complexity, and uniqueness:**
  - Length (up to 30 pts) — under 8 characters can never score above Weak (capped at 39)
  - Complexity (up to 30 pts) — lowercase, uppercase, digits, symbols (7.5 pts each)
  - Entropy (up to 20 pts) — `length × log₂(pool size)`, where the pool depends on which character classes are present
  - Uniqueness (up to 20 pts) — penalises common passwords (built-in list of ~70 well-known ones), sequential/keyboard patterns (`abc`, `123`, `qwerty`), and repeated characters (`aaa`)
- **Explains itself:** every check is listed as ✓ / ! / ✗ with a plain-language reason, plus a per-category breakdown (Length / Complexity / Entropy / Uniqueness)
- **Crack-time estimate:** `2^entropy ÷ 10 billion guesses/second` (offline attack), shown in seconds → years
- **Strong-password generator:** 16 characters by default, all four classes, no sequential/repeated patterns; Python uses `secrets`, the web UI uses `crypto.getRandomValues` (both cryptographically secure)
- **Reuse prevention (optional, implemented):** SQLite store that keeps **only SHA-256 hashes, never plaintext**. `--check-reuse` warns on a hash match; `--save` stores the hash. The web UI has a browser-local equivalent (SHA-256 in `localStorage`, checkbox-gated).

## Files

| File | What it is |
|---|---|
| `index.html` | Web UI — single file, no build step, no server, no dependencies. Open it in a browser. |
| `password_analyzer.py` | Python CLI — standard library only, same scoring logic as the web UI. |
| `README.md` | This file. |
| `TESTS.md` | Test results (CLI + web UI logic + reuse check). |
| `.gitignore` | Ignores `*.db` and `__pycache__/` so no password hashes are committed. |

## How to run

### Web UI (easiest)

```bash
# Option A — just open the file
open index.html            # macOS
xdg-open index.html        # Linux
# or double-click index.html in a file manager

# Option B — serve it locally (optional, same page)
python3 -m http.server 8000
# then open http://localhost:8000/
```

Type a **test** password, watch the score bar, feedback list, entropy and crack time update live. Click **Generate strong password** for a 16-character suggestion, **Copy** to copy it, **Show** to reveal what you typed.

### Python CLI

Requires Python 3.8+ only — no packages to install.

```bash
python3 password_analyzer.py 'Tr0ub4dor&3x9!'
python3 password_analyzer.py 'password123' --check-reuse --save
python3 password_analyzer.py --generate 16
python3 password_analyzer.py 'Sunshine2026' --json
```

Flags:

| Flag | Meaning |
|---|---|
| `password` (positional) | Password to analyse — **test passwords only** |
| `--generate N` / `-g N` | Print a strong password of length N (≥ 12) |
| `--db PATH` | SQLite file for the reuse store (default `passwords.db`) |
| `--check-reuse` | Warn if the password's hash is already stored |
| `--save` | Store only the SHA-256 hash (never plaintext) |
| `--json` | Output the full result as JSON |

## Example passwords (test data only — never real passwords)

These are the examples used in `TESTS.md`. Do not use any of them as a real password.

| Password | Score | Label | Why |
|---|---|---|---|
| `qwerty` | 18/100 | Weak | 6 chars, one class, common password, keyboard sequence |
| `password123` | 48/100 | Fair | 11 chars, but a top-common password with a `123` sequence |
| `aB3$` | 39/100 | Weak | All 4 classes, but only 4 chars — capped at Weak |
| `Sunshine2026` | 80/100 | Strong | 12 chars, 3 classes, 71.5 bits entropy — but no symbol, and a dictionary word |
| `Tr0ub4dor&3x9!` | 94/100 | Strong | 14 chars, all 4 classes, 91.8 bits |
| `X9$mK2pQ7!vL4wR8#d` | 100/100 | Strong | 18 chars, all 4 classes, 118 bits |
| `correct-horse-battery-staple-99!` | 92/100 | Strong | Very long passphrase — length beats complexity |

## Screenshots (what the web UI looks like)

- **Main card:** dark-blue page, "🔐 Password Strength Analyzer" heading, a password field with Show/Hide, and a "Remember this password's hash locally" checkbox.
- **After typing:** a coloured score bar (red → amber → blue → green), "Score: 94 / 100 — Strong", entropy and crack-time lines, four stat boxes (Length / Complexity / Entropy / Uniqueness), and a ✓/!/✗ feedback list.
- **Generator card:** "Generate strong password (16 chars)" and Copy buttons, with the generated password shown in monospace.
- (Screenshots were not captured in this headless build — the layout above is what `index.html` renders; see `TESTS.md` for the logic verification that was run instead.)

## What was learned (expected outcome)

1. **Length matters most.** Each extra character multiplies the search space. A 4-character password with every character class still scores Weak; an 18-character password scores 100.
2. **Entropy is the honest measure.** `entropy = length × log₂(pool)`. A 12-character lowercase-only password has ~56 bits; adding upper/digit/symbol classes raises the pool from 26 to 94 and the entropy to ~79 bits for the same length.
3. **Common passwords fail instantly.** `password123` has decent length and entropy on paper, but attackers try the common-password list first — so it loses all 20 uniqueness points and its real crack time is seconds, not the 155 days the entropy alone suggests.
4. **Patterns are predictable.** `123`, `qwerty`, `abc`, and `aaa` are not random — they are the first things a dictionary / rule-based attack tries.
5. **Hashes ≠ plaintext, but hashing alone isn't login security.** This project stores SHA-256 hashes only so reuse can be detected locally. A real login system must use a slow, salted hash (bcrypt / Argon2 — see Thiranex Task 4, Secure Login System) because fast hashes like SHA-256 can be brute-forced offline. Deterministic hashing is used here *only* for the local reuse check.
6. **Crack time is an estimate, not a promise.** It assumes 10 billion guesses/second offline. Online logins (rate-limited, ~1,000 guesses/sec) are far slower to attack — which is why lockouts and 2FA matter as much as the password itself.

## Security notes

- **Never type a real password into this tool** (or any demo). Use test passwords only.
- The CLI stores hashes in `passwords.db` in the current directory; that file is git-ignored (`.gitignore`) so it is never committed.
- The common-password list is a small teaching sample, not a breach database. A production checker would query a real breached-password list (e.g. Have I Been Pwned, k-anonymity API).
- This tool is for learning and local use. It was **not** submitted to Thiranex and no login was performed.

## GitHub-ready

```bash
git init
git add .
git commit -m "Thiranex Task 1: Password Strength Analyzer"
git remote add origin https://github.com/<your-username>/thiranex-password-strength-analyzer.git
git push -u origin main
```

No secrets, no real passwords, and no `*.db` files are included.
