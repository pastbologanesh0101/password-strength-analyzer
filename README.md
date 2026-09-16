# Password Strength Analyzer

A small, pure-Python (stdlib only) command-line tool that estimates how
strong a password is, and gives specific, human-readable feedback on how
to improve it.

This project is for **defensive / educational purposes**: it is meant to
help people choose stronger passwords for their own accounts. It does not
attempt to crack, brute-force, or exfiltrate anyone's credentials, and it
never transmits or stores the passwords you analyze.

## How it works

1. **Entropy estimate.** The analyzer looks at which character classes
   are present in the password (lowercase, uppercase, digits, symbols) to
   approximate the size of the character "pool" an attacker would have to
   search, then computes a Shannon-entropy-style estimate:

   ```
   entropy_bits = length * log2(pool_size)
   ```

   For example, an 8-character password using only lowercase letters has
   a pool size of 26, giving `8 * log2(26) ≈ 37.6` bits. A 16-character
   password mixing all four classes has a pool size of 95, giving
   `16 * log2(95) ≈ 105` bits.

2. **Weakness detection.** Raw entropy alone overstates the strength of
   passwords that are common or follow predictable patterns, so the
   analyzer also checks for:
   - **Common / breached passwords** — exact and near-miss matches (via
     suffix stripping and edit-distance) against a bundled list of ~450
     well-known common passwords (`data/common_passwords.txt`, a
     representative sample list, not a scraped real-world breach corpus).
   - **Keyboard-walk patterns** — runs of horizontally-adjacent QWERTY
     keys, e.g. `qwerty`, `asdfgh`, `1q2w3e4r`.
   - **Repeated characters** — runs like `aaaa` or `1111`.
   - **Simple sequences** — ascending/descending runs like `1234`,
     `abcd`, or `4321`.

3. **Scoring and verdict.** Each detected weakness applies a multiplicative
   penalty to the entropy estimate. The penalized score is then mapped to
   one of five verdicts:

   | Score (bits)     | Verdict      |
   |-------------------|--------------|
   | < 28              | very weak    |
   | 28 – 36           | weak         |
   | 36 – 60           | moderate     |
   | 60 – 80           | strong       |
   | ≥ 80              | very strong  |

## Usage

No dependencies beyond the Python standard library.

```bash
python analyze.py "SomePassword123!"
```

### Example output

```text
$ python analyze.py "SomePassword123!"
Verdict:  very strong
Entropy:  105.12 bits (estimated)
Score:    105.12 (entropy after weakness penalties)
Length:   16
Feedback:
  - no significant weaknesses detected

$ python analyze.py "Password1"
Verdict:  very weak
Entropy:  53.59 bits (estimated)
Score:    2.68 (entropy after weakness penalties)
Length:   9
Feedback:
  - consider using at least 12 characters for better security
  - add symbols
  - found in common password list

$ python analyze.py "letmein123"
Verdict:  very weak
Entropy:  51.7 bits (estimated)
Score:    2.58 (entropy after weakness penalties)
Length:   10
Feedback:
  - consider using at least 12 characters for better security
  - add uppercase letters
  - add symbols
  - found in common password list

$ python analyze.py "Tr0ub4dor"
Verdict:  moderate
Entropy:  53.59 bits (estimated)
Score:    53.59 (entropy after weakness penalties)
Length:   9
Feedback:
  - consider using at least 12 characters for better security
  - add symbols
```

If you run `python analyze.py` with no argument, it will prompt you to
type a password interactively.

## Running the tests

```bash
python -m unittest discover -s tests -v
```

or, if you prefer pytest:

```bash
pytest tests/ -v
```

The test suite covers:
- Entropy calculation for each character-class combination
- Common-password detection, including near-miss / suffix-stripped matches
- Keyboard-walk detection
- Repeated-character and simple-sequence detection
- Verdict ordering (a stronger password never scores below a weaker one)
- Edge cases: empty string, single character, very long random password

Continuous integration (`.github/workflows/tests.yml`) runs the full suite
on every push and pull request against Python 3.11 and 3.12.

## Project layout

```
password-strength-analyzer/
├── analyze.py                  # CLI entry point
├── analyzer.py                 # Core analysis library (entropy, detectors, scoring)
├── data/
│   └── common_passwords.txt    # Bundled sample list of common passwords
├── tests/
│   └── test_analyzer.py        # Unit tests
├── .github/workflows/tests.yml # CI: runs tests on Python 3.11 and 3.12
├── LICENSE
└── README.md
```

## Limitations

This is an educational tool, not a production-grade password auditor. The
entropy model is a simplified worst-case estimate (it does not account for
things like dictionary-word substitution patterns or leetspeak the way a
tool like `zxcvbn` does), and the bundled common-password list is a small
representative sample rather than a real breach corpus. For production use
cases, consider a more sophisticated library such as `zxcvbn`.

## License

MIT — see [LICENSE](LICENSE).
