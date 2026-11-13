# Test results — Thiranex Task 1: Password Strength Analyzer

Run on 13 Nov 2026. All example passwords are made-up test data, never real passwords.

## 1. Python CLI — 7 example passwords (weak → strong)

Command used for each: `python3 password_analyzer.py '<password>'`

| # | Password | Score | Label | Entropy | Crack time (offline, 10bn/s) | Notes |
|---|---|---|---|---|---|---|
| 1 | `qwerty` | 18/100 | Weak | 28.2 bits | less than a second | Common password, keyboard sequence, 6 chars |
| 2 | `aB3$` | 39/100 | Weak | 26.2 bits | less than a second | All 4 classes, but only 4 chars — capped at 39 (Weak) |
| 3 | `password123` | 48/100 | Fair | 56.9 bits | 155.6 days | Common password + `123` sequence; entropy alone overstates its safety |
| 4 | `Sunshine2026` | 80/100 | Strong | 71.5 bits | 10,581 years | 12 chars, 3 classes, no symbol |
| 5 | `Tr0ub4dor&3x9!` | 94/100 | Strong | 91.8 bits | ~13.7 billion years | 14 chars, all 4 classes |
| 6 | `correct-horse-battery-staple-99!` | 92/100 | Strong | 194.8 bits | effectively uncrackable | Very long passphrase |
| 7 | `X9$mK2pQ7!vL4wR8#d` | 100/100 | Strong | 118.0 bits | effectively uncrackable | 18 chars, all 4 classes |

Full per-check feedback was printed for each run (✓/!/✗ per check) and matched expectations — e.g. `password123` flagged "most common password" and "sequential pattern: 123"; `aB3$` flagged "Too short: 4 characters".

**Fix found during testing:** the first run scored `aB3$` 54/100 (Fair) — wrong for a 4-character password. A length cap was added (under 8 chars → max 39, Weak) in both the Python CLI and the web UI, and the re-run above confirms 39/100 Weak.

## 2. Generator

```
$ python3 password_analyzer.py --generate 16
jI&yZDV>0g69/bQ>
```

Output was 16 characters, all four classes, and re-analysing generated passwords scores 94–100/100 (Strong).

## 3. SQLite reuse check

```
$ python3 password_analyzer.py 'Tr0ub4dor&3x9!' --check-reuse --save --db test.db
Reuse:    OK — not seen before in this store.
Saved:    hash stored.
Store:    1 hash(es) in test.db (no plaintext stored).

$ python3 password_analyzer.py 'Tr0ub4dor&3x9!' --check-reuse --db test.db
Reuse:    ⚠  WARNING — this password was used before (hash match). Pick a new one.

$ python3 password_analyzer.py 'DifferentPass99!' --check-reuse --db test.db
Reuse:    OK — not seen before in this store.
```

Database inspection confirmed only a hash is stored:

```
[('d9a595cdaebf8e7ae06f58ed70c469ab812c3b77d71e01be1da329410970f9f4',
  '2026-11-13T11:10:23.748186+00:00')]
```

No plaintext password appears anywhere in the database. `test.db` was deleted after testing; the project ships with no `.db` file (git-ignored).

## 4. Web UI — logic check

No browser was available in this build environment, so the UI was verified two ways:

1. **HTML parse:** `index.html` parses cleanly with Python's `html.parser`; all 17 element IDs referenced by the JavaScript (`pw`, `toggle`, `saveHash`, `fill`, `label`, `score`, `entropy`, `crack`, `bLength`, `bComplexity`, `bEntropy`, `bUnique`, `feedback`, `reuse`, `gen`, `copy`, `generated`) are present in the markup.
2. **Logic parity:** the `<script>` scoring function was extracted and run under Node.js on the same 6 passwords as the CLI:

| Password | Python CLI | Web UI (Node) | Match |
|---|---|---|---|
| `password123` | 48 Fair | 48 Fair | ✓ exact |
| `qwerty` | 18 Weak | 19 Weak | ±1 (rounding — see below) |
| `Sunshine2026` | 80 Strong | 81 Strong | ±1 (rounding) |
| `Tr0ub4dor&3x9!` | 94 Strong | 94 Strong | ✓ exact |
| `X9$mK2pQ7!vL4wR8#d` | 100 Strong | 100 Strong | ✓ exact |
| `aB3$` | 39 Weak | 39 Weak | ✓ exact |

The ±1 differences are rounding only: Python's `round()` uses banker's rounding (80.5 → 80), JavaScript's `Math.round()` rounds halves up (80.5 → 81). Labels are identical in every case. No broken controls were found in the markup: every button/input has a matching handler (`input`, `click` for Show/Hide, Generate, Copy).

## 5. Compile check

```
$ python3 -m py_compile password_analyzer.py
py_compile OK
```
