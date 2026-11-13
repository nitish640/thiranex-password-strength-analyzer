#!/usr/bin/env python3
"""
Thiranex Cyber Security — Task 1: Password Strength Analyzer
CLI version. Standard library only (Python 3.8+).

Scoring (0-100, shared with the web UI in index.html):
  Length      up to 30 pts
  Complexity  up to 30 pts (4 character classes x 7.5)
  Entropy     up to 20 pts (from estimated character pool)
  Uniqueness  up to 20 pts (no common password / patterns / repeats)
  Penalties are folded into Uniqueness; total is clamped to 0-100.

Labels:  0-39 Weak | 40-59 Fair | 60-79 Good | 80-100 Strong

SQLite reuse-check: only a SHA-256 hash of the password is ever stored
(never the plaintext). A deterministic hash is used here *only* so that
reuse can be detected locally; in a production login system passwords
must be stored with a per-user salt (bcrypt / Argon2), as Task 4 covers.

Examples in this file / README / tests use ONLY made-up test passwords.
Never analyse or store a real password with this demo tool.
"""
import argparse
import hashlib
import json
import math
import re
import secrets
import sqlite3
import string
import sys
from datetime import datetime, timezone
from pathlib import Path

# A small, well-known set of the most common / most breached passwords.
# Deliberately short: this is a teaching demo, not a breach database.
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "1234567",
    "1234567890", "qwerty", "abc123", "111111", "123123", "admin",
    "letmein", "welcome", "monkey", "dragon", "password1", "1234",
    "12345678910", "iloveyou", "princess", "football", "sunshine",
    "master", "shadow", "superman", "michael", "ninja", "mustang",
    "password123", "qwerty123", "admin123", "welcome123", "123qwe",
    "1q2w3e4r", "qwertyuiop", "passw0rd", "charlie", "aa123456",
    "donald", "jordan", "computer", "michelle", "jessica", "pepper",
    "123456a", "696969", "starwars", "whatever", "freedom", "hello",
    "trustno1", "batman", "zaq1zaq", "000000", "654321", "123321",
    "qazwsx", "mynoob", "thiranex", "cyber", "security",
}

SEQUENTIAL = [
    "abcdefghijklmnopqrstuvwxyz", "0123456789",
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
]
KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]


def character_classes(pw: str) -> dict:
    return {
        "lowercase": any(c.islower() for c in pw),
        "uppercase": any(c.isupper() for c in pw),
        "digits": any(c.isdigit() for c in pw),
        "symbols": any(c in string.punctuation for c in pw),
    }


def pool_size(pw: str) -> int:
    classes = character_classes(pw)
    pool = 0
    if classes["lowercase"]:
        pool += 26
    if classes["uppercase"]:
        pool += 26
    if classes["digits"]:
        pool += 10
    if classes["symbols"]:
        pool += 32
    return pool


def entropy_bits(pw: str) -> float:
    pool = pool_size(pw)
    if pool <= 1 or not pw:
        return 0.0
    return round(len(pw) * math.log2(pool), 1)


def _has_sequence(pw: str, min_len: int = 3) -> list:
    lowered = pw.lower()
    found = []
    for seq in SEQUENTIAL:
        for i in range(len(seq) - min_len + 1):
            frag = seq[i:i + min_len]
            if frag in lowered or frag[::-1] in lowered:
                found.append(frag)
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - min_len + 1):
            frag = row[i:i + min_len]
            if frag in lowered:
                found.append(frag)
    return sorted(set(found))


def _repeated_runs(pw: str) -> list:
    return sorted(set(m.group(0) for m in re.finditer(r"(.)\1{2,}", pw)))


def analyze(password: str) -> dict:
    """Score a password. Returns a dict with score, label, entropy,
    crack-time estimate and per-check feedback. No password is stored here."""
    feedback = []
    length = len(password)

    # --- Length: up to 30 ---
    if length == 0:
        length_score = 0
        feedback.append(("fail", "Password is empty."))
    elif length < 8:
        length_score = length  # 1 pt per char below 8
        feedback.append(("fail", f"Too short: {length} characters (minimum 8)."))
    elif length <= 10:
        length_score = 10
        feedback.append(("warn", f"Short: {length} characters — aim for 12+."))
    elif length <= 12:
        length_score = 18
        feedback.append(("ok", f"Good length: {length} characters."))
    elif length <= 15:
        length_score = 24
        feedback.append(("ok", f"Long: {length} characters."))
    else:
        length_score = 30
        feedback.append(("ok", f"Very long: {length} characters."))

    # --- Complexity: up to 30 (7.5 per class) ---
    classes = character_classes(password)
    present = [k for k, v in classes.items() if v]
    complexity_score = len(present) * 7.5
    for name, ok in classes.items():
        if ok:
            feedback.append(("ok", f"Contains {name}."))
        else:
            feedback.append(("warn", f"Missing {name}."))

    # --- Entropy: up to 20 ---
    ent = entropy_bits(password)
    if ent < 28:
        entropy_score = 0
    elif ent < 36:
        entropy_score = 5
    elif ent < 46:
        entropy_score = 10
    elif ent < 60:
        entropy_score = 15
    else:
        entropy_score = 20

    # --- Uniqueness: up to 20, minus pattern penalties ---
    uniqueness_score = 20
    lowered = password.lower()
    if lowered in COMMON_PASSWORDS:
        uniqueness_score -= 20
        feedback.append(("fail", "This is one of the most common passwords — attackers try it first."))
    elif any(c in lowered for c in ("password", "admin", "qwerty", "welcome", "letmein")):
        uniqueness_score -= 10
        feedback.append(("fail", "Contains a very common word (password/admin/qwerty/welcome)."))

    seqs = _has_sequence(password)
    if seqs:
        uniqueness_score -= 8
        feedback.append(("fail", f"Contains sequential/keyboard pattern(s): {', '.join(seqs[:3])}."))

    repeats = _repeated_runs(password)
    if repeats:
        uniqueness_score -= 8
        feedback.append(("fail", f"Repeated characters: {', '.join(repeats[:3])}."))

    if re.search(r"(.)\1{1,}", password) and length < 8:
        uniqueness_score -= 2

    uniqueness_score = max(0, uniqueness_score)
    if uniqueness_score == 20:
        feedback.append(("ok", "No common-password, sequential or repeated pattern found."))

    score = int(round(length_score + complexity_score + entropy_score + uniqueness_score))
    score = max(0, min(100, score))
    # A password under 8 characters can never be better than Weak,
    # however many character classes it uses — length is the floor.
    if length < 8:
        score = min(score, 39)

    if score < 40:
        label = "Weak"
    elif score < 60:
        label = "Fair"
    elif score < 80:
        label = "Good"
    else:
        label = "Strong"

    return {
        "password_length": length,
        "score": score,
        "label": label,
        "entropy_bits": ent,
        "character_classes": present,
        "crack_time_offline": crack_time(ent),
        "feedback": [{"level": lvl, "message": msg} for lvl, msg in feedback],
        "breakdown": {
            "length": length_score,
            "complexity": complexity_score,
            "entropy": entropy_score,
            "uniqueness": uniqueness_score,
        },
    }


def crack_time(entropy: float) -> str:
    """Human-readable offline crack time at 10 billion guesses/second.
    2^entropy guesses / 1e10 per second. This is an estimate, not a guarantee."""
    if entropy <= 0:
        return "instant"
    seconds = (2 ** entropy) / 10_000_000_000
    return _human_seconds(seconds)


def _human_seconds(seconds: float) -> str:
    if seconds < 1:
        return "less than a second"
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    minutes = seconds / 60
    if minutes < 60:
        return f"{minutes:.1f} minutes"
    hours = minutes / 60
    if hours < 24:
        return f"{hours:.1f} hours"
    days = hours / 24
    if days < 365:
        return f"{days:.1f} days"
    years = days / 365.25
    if years < 1_000:
        return f"{years:,.1f} years"
    if years < 1_000_000:
        return f"{years:,.0f} years"
    return f"{years:,.0f} years (effectively uncrackable by brute force)"


def generate_password(length: int = 16) -> str:
    """Generate a strong password with secrets (cryptographically secure)."""
    if length < 12:
        raise ValueError("Generated passwords should be at least 12 characters.")
    alphabet = string.ascii_letters + string.digits + string.punctuation
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        classes = character_classes(pw)
        if all(classes.values()) and not _has_sequence(pw) and not _repeated_runs(pw):
            return pw


def password_hash(password: str) -> str:
    """SHA-256 hash only — the plaintext is never stored. See module docstring."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


# --- SQLite reuse store -------------------------------------------------

def _connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "CREATE TABLE IF NOT EXISTS used_passwords ("
        "  password_hash TEXT PRIMARY KEY,"
        "  created_at TEXT NOT NULL)"
    )
    conn.commit()
    return conn


def check_reuse(password: str, db_path: Path) -> bool:
    """True if this password's hash is already in the store."""
    conn = _connect(db_path)
    try:
        row = conn.execute(
            "SELECT 1 FROM used_passwords WHERE password_hash = ?",
            (password_hash(password),),
        ).fetchone()
        return row is not None
    finally:
        conn.close()


def save_password(password: str, db_path: Path) -> bool:
    """Store only the hash. Returns False if it was already stored."""
    conn = _connect(db_path)
    try:
        conn.execute(
            "INSERT INTO used_passwords (password_hash, created_at) VALUES (?, ?)",
            (password_hash(password), datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def count_stored(db_path: Path) -> int:
    if not db_path.exists():
        return 0
    conn = _connect(db_path)
    try:
        return conn.execute("SELECT COUNT(*) FROM used_passwords").fetchone()[0]
    finally:
        conn.close()


# --- CLI -----------------------------------------------------------------

def print_result(result: dict, password: str, reused: bool | None = None) -> None:
    print(f"\nPassword: {'*' * len(password)}  (length {result['password_length']})")
    print(f"Score:    {result['score']}/100 — {result['label']}")
    print(f"Entropy:  {result['entropy_bits']} bits")
    print(f"Classes:  {', '.join(result['character_classes']) or 'none'}")
    print(f"Crack time (offline, 10bn guesses/sec): {result['crack_time_offline']}")
    print("Breakdown: " + ", ".join(
        f"{k} {v}" for k, v in result["breakdown"].items()))
    if reused is True:
        print("Reuse:    ⚠  WARNING — this password was used before (hash match). Pick a new one.")
    elif reused is False:
        print("Reuse:    OK — not seen before in this store.")
    print("Feedback:")
    for item in result["feedback"]:
        mark = {"ok": "✓", "warn": "!", "fail": "✗"}[item["level"]]
        print(f"  [{mark}] {item['message']}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Thiranex Task 1 — Password Strength Analyzer (CLI)")
    parser.add_argument("password", nargs="?", help="Password to analyse (test password only)")
    parser.add_argument("--generate", "-g", type=int, metavar="N",
                        help="Generate a strong password of length N (default 16)")
    parser.add_argument("--db", default="passwords.db",
                        help="SQLite database path for the reuse check (default: passwords.db)")
    parser.add_argument("--check-reuse", action="store_true",
                        help="Check the password against the local reuse store")
    parser.add_argument("--save", action="store_true",
                        help="Store only the SHA-256 hash in the reuse store (never plaintext)")
    parser.add_argument("--json", action="store_true", help="Output the result as JSON")
    args = parser.parse_args(argv)

    if args.generate:
        try:
            print(generate_password(args.generate))
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 2
        return 0

    if not args.password:
        parser.print_help()
        print("\nExamples (test passwords only):")
        print("  python password_analyzer.py 'Tr0ub4dor&3x9!'")
        print("  python password_analyzer.py 'password123' --check-reuse --save")
        print("  python password_analyzer.py --generate 16")
        return 2

    db_path = Path(args.db)
    result = analyze(args.password)
    reused = check_reuse(args.password, db_path) if args.check_reuse else None

    if args.json:
        out = dict(result)
        out["reused"] = reused
        print(json.dumps(out, indent=2))
    else:
        print_result(result, args.password, reused)

    if args.save:
        saved = save_password(args.password, db_path)
        print("Saved:    hash stored." if saved else "Saved:    already in store (hash match).")
        print(f"Store:    {count_stored(db_path)} hash(es) in {db_path} (no plaintext stored).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
