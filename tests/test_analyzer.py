"""Unit tests for the Password Strength Analyzer."""

import math
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer import (
    analyze_password,
    estimate_entropy_bits,
    find_common_password_match,
    find_keyboard_walks,
    find_repeated_chars,
    find_simple_sequences,
    verdict_rank,
)


class EntropyTests(unittest.TestCase):
    def test_entropy_digits_only(self):
        # pool size 10, length 6 -> 6 * log2(10)
        expected = 6 * math.log2(10)
        self.assertAlmostEqual(estimate_entropy_bits("123456"), expected, places=4)

    def test_entropy_lowercase_only(self):
        # pool size 26, length 8 -> 8 * log2(26)
        expected = 8 * math.log2(26)
        self.assertAlmostEqual(estimate_entropy_bits("abcdefgh"), expected, places=4)

    def test_entropy_lower_and_upper(self):
        # pool size 52, length 8
        expected = 8 * math.log2(52)
        self.assertAlmostEqual(estimate_entropy_bits("AbCdEfGh"), expected, places=4)

    def test_entropy_all_classes(self):
        # lower+upper+digits+symbols = 26+26+10+33 = 95
        pw = "Ab1!Cd2@"
        expected = len(pw) * math.log2(95)
        self.assertAlmostEqual(estimate_entropy_bits(pw), expected, places=4)

    def test_entropy_empty_string(self):
        self.assertEqual(estimate_entropy_bits(""), 0.0)


class CommonPasswordDetectionTests(unittest.TestCase):
    def test_exact_match(self):
        result = find_common_password_match("password")
        self.assertIsNotNone(result)
        self.assertEqual(result[1], "exact")

    def test_exact_match_case_insensitive(self):
        result = find_common_password_match("PaSsWoRd")
        self.assertIsNotNone(result)

    def test_near_miss_with_suffix(self):
        # "password123!" should reduce to "password" after stripping
        # trailing digits/symbols, which is in the common list.
        result = find_common_password_match("password123!")
        self.assertIsNotNone(result)

    def test_near_miss_edit_distance(self):
        # "qwerty" is common; "qwertz" is a 1-character substitution away.
        result = find_common_password_match("qwertz")
        self.assertIsNotNone(result)

    def test_no_match_for_random_strong_password(self):
        result = find_common_password_match("Xk9$mQ2vL#pR7zT!")
        self.assertIsNone(result)


class KeyboardWalkTests(unittest.TestCase):
    def test_detects_qwerty(self):
        walks = find_keyboard_walks("qwerty")
        self.assertTrue(len(walks) > 0)

    def test_detects_asdfgh(self):
        walks = find_keyboard_walks("asdfgh")
        self.assertTrue(len(walks) > 0)

    def test_no_walk_in_random_password(self):
        walks = find_keyboard_walks("Xk9mQ2vL")
        self.assertEqual(walks, [])

    def test_walk_embedded_in_longer_string(self):
        walks = find_keyboard_walks("myqwertypass99")
        self.assertTrue(len(walks) > 0)


class RepeatedCharAndSequenceTests(unittest.TestCase):
    def test_detects_repeated_chars(self):
        matches = find_repeated_chars("aaaa")
        self.assertEqual(matches, ["aaaa"])

    def test_detects_repeated_digits(self):
        matches = find_repeated_chars("password1111")
        self.assertTrue(any("1111" in m for m in matches))

    def test_no_repeats_in_varied_password(self):
        self.assertEqual(find_repeated_chars("abcdef"), [])

    def test_detects_ascending_sequence(self):
        sequences = find_simple_sequences("1234")
        self.assertIn("1234", sequences)

    def test_detects_alpha_sequence(self):
        sequences = find_simple_sequences("abcd")
        self.assertIn("abcd", sequences)

    def test_detects_descending_sequence(self):
        sequences = find_simple_sequences("4321")
        self.assertIn("4321", sequences)

    def test_no_sequence_in_random_password(self):
        self.assertEqual(find_simple_sequences("XkQmLpR"), [])


class VerdictOrderingTests(unittest.TestCase):
    """A stronger password should never score below a weaker one."""

    def test_verdict_thresholds_are_ordered(self):
        from analyzer import VERDICTS

        ranks = [verdict_rank(v) for v in VERDICTS]
        self.assertEqual(ranks, sorted(ranks))

    def test_stronger_password_never_scores_lower(self):
        weak = analyze_password("password")
        moderate = analyze_password("Password1")
        strong = analyze_password("Xk9$mQ2vL#pR7zT!")
        very_strong = analyze_password("Xk9$mQ2vL#pR7zT!Wb4^Ny8&")

        self.assertLessEqual(verdict_rank(weak.verdict), verdict_rank(moderate.verdict))
        self.assertLessEqual(verdict_rank(moderate.verdict), verdict_rank(strong.verdict))
        self.assertLessEqual(verdict_rank(strong.verdict), verdict_rank(very_strong.verdict))

    def test_common_password_scores_worse_than_random_of_same_length(self):
        common = analyze_password("qwertyuiop")  # 10 chars, common-ish pattern
        random_same_len = analyze_password("Xk9$mQ2vL#")  # 10 chars, high diversity
        self.assertLess(common.score, random_same_len.score)


class EdgeCaseTests(unittest.TestCase):
    def test_empty_string(self):
        result = analyze_password("")
        self.assertEqual(result.verdict, "very weak")
        self.assertEqual(result.entropy_bits, 0.0)
        self.assertIn("password is empty", result.feedback)

    def test_very_long_random_password_is_very_strong(self):
        long_random = "Xk9$mQ2vL#pR7zT!Wb4^Ny8&Ac3*Fd6@Gh1%Jk5+" * 2
        result = analyze_password(long_random)
        self.assertEqual(result.verdict, "very strong")

    def test_single_character(self):
        result = analyze_password("a")
        self.assertEqual(result.verdict, "very weak")

    def test_only_symbols_no_length_no_common_match(self):
        result = analyze_password("!@#$")
        self.assertIsInstance(result.entropy_bits, float)
        self.assertGreaterEqual(result.entropy_bits, 0.0)


if __name__ == "__main__":
    unittest.main()
