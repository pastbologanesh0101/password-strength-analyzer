#!/usr/bin/env python3
"""
Command-line interface for the Password Strength Analyzer.

Usage:
    python analyze.py "SomePassword123!"

If no password is given on the command line, you will be prompted to type
one (input is not hidden on all terminals, so prefer the CLI argument
when running on a shared/visible screen, or pipe it in).

This tool is for defensive/educational purposes: it helps a user judge
whether a password of their own choosing is strong enough. It does not
store, transmit, or crack passwords.
"""

import sys

from analyzer import analyze_password


def main(argv):
    if len(argv) > 1:
        password = argv[1]
    else:
        try:
            password = input("Enter a password to analyze: ")
        except (EOFError, KeyboardInterrupt):
            print()
            return 1

    result = analyze_password(password)

    print(f"Verdict:  {result.verdict}")
    print(f"Entropy:  {result.entropy_bits} bits (estimated)")
    print(f"Score:    {result.score} (entropy after weakness penalties)")
    print(f"Length:   {result.password_length}")
    print("Feedback:")
    for item in result.feedback:
        print(f"  - {item}")

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
