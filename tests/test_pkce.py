import unittest

from mcp_oauth_tiers import generate_verifier, is_valid_verifier, s256_challenge


class PkceTests(unittest.TestCase):
    def test_rfc7636_example(self):
        verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        self.assertTrue(is_valid_verifier(verifier))
        self.assertEqual(
            s256_challenge(verifier),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        )

    def test_generated_verifiers_are_valid_and_independent(self):
        verifiers = {generate_verifier() for _ in range(32)}
        self.assertEqual(len(verifiers), 32)
        self.assertTrue(all(is_valid_verifier(value) for value in verifiers))
        self.assertTrue(all(len(value) == 64 for value in verifiers))

    def test_boundaries_and_bad_lengths(self):
        self.assertTrue(is_valid_verifier("a" * 43))
        self.assertTrue(is_valid_verifier("~" * 128))
        self.assertFalse(is_valid_verifier("a" * 42))
        self.assertFalse(is_valid_verifier("a" * 129))
        for length in (42, 129):
            with self.assertRaises(ValueError):
                generate_verifier(length)

    def test_rejects_padding_spaces_unicode_and_non_strings(self):
        for bad in ("a" * 42 + "=", "a" * 42 + " ", "a" * 42 + "é", None, b"a" * 43):
            self.assertFalse(is_valid_verifier(bad))
        with self.assertRaises(ValueError):
            s256_challenge("a" * 42 + "=")

    def test_challenge_is_stateless_and_unpadded(self):
        verifier = "A" * 43
        first = s256_challenge(verifier)
        self.assertEqual(first, s256_challenge(verifier))
        self.assertEqual(len(first), 43)
        self.assertNotIn("=", first)

    def test_rejects_non_integer_length(self):
        for value in (True, 64.0, "64"):
            with self.assertRaises(TypeError):
                generate_verifier(value)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
