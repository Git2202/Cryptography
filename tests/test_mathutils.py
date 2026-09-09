import random
import unittest

from rsa import (
    ModulusTooSmallError,
    NegativeValueError,
    NonInvertibleError,
    NotIntegerError,
)
from rsa.mathutils import egcd, egcd_steps, gcd, lcm, modinv, mod_exp, mod_exp_steps


class TestGcdLcm(unittest.TestCase):
    def test_known_values(self):
        self.assertEqual(gcd(48, 18), 6)
        self.assertEqual(gcd(17, 5), 1)
        self.assertEqual(gcd(0, 5), 5)
        self.assertEqual(gcd(5, 0), 5)
        self.assertEqual(gcd(0, 0), 0)

    def test_lcm_known_values(self):
        self.assertEqual(lcm(4, 6), 12)
        self.assertEqual(lcm(3, 7), 21)
        self.assertEqual(lcm(0, 5), 0)
        self.assertEqual(lcm(5, 0), 0)

    def test_gcd_against_math_gcd(self):
        import math

        rng = random.Random(1)
        for _ in range(200):
            a = rng.randint(0, 100_000)
            b = rng.randint(0, 100_000)
            self.assertEqual(gcd(a, b), math.gcd(a, b))

    def test_rejects_non_int(self):
        with self.assertRaises(NotIntegerError):
            gcd(1.5, 2)
        with self.assertRaises(NotIntegerError):
            lcm("3", 2)

    def test_rejects_negative(self):
        with self.assertRaises(NegativeValueError):
            gcd(-1, 2)
        with self.assertRaises(NegativeValueError):
            lcm(3, -2)


class TestEgcd(unittest.TestCase):
    def test_bezout_identity_holds(self):
        rng = random.Random(2)
        for _ in range(200):
            a = rng.randint(0, 10_000)
            b = rng.randint(0, 10_000)
            g, x, y = egcd(a, b)
            self.assertEqual(a * x + b * y, g)
            self.assertEqual(g, gcd(a, b))

    def test_known_case_240_46(self):
        # Textbook example: gcd(240, 46) = 2, with 240*(-9) + 46*47 == 2.
        g, x, y = egcd(240, 46)
        self.assertEqual(g, 2)
        self.assertEqual(240 * x + 46 * y, 2)

    def test_egcd_steps_last_row_matches_egcd(self):
        a, b = 240, 46
        g, x, y = egcd(a, b)
        rows = egcd_steps(a, b)
        last = rows[-1]
        self.assertEqual(last["r"], g)
        self.assertEqual(last["s"], x)
        self.assertEqual(last["t"], y)

    def test_egcd_steps_every_row_satisfies_identity(self):
        a, b = 1071, 462
        for row in egcd_steps(a, b):
            self.assertEqual(a * row["s"] + b * row["t"], row["r"])

    def test_egcd_steps_json_serialisable(self):
        import json

        json.dumps(egcd_steps(1071, 462))  # must not raise


class TestModinv(unittest.TestCase):
    def test_known_value(self):
        # 3 * 4 = 12 == 1 mod 11
        self.assertEqual(modinv(3, 11), 4)

    def test_against_python_pow(self):
        rng = random.Random(3)
        for _ in range(200):
            m = rng.randint(2, 10_000)
            a = rng.randint(1, m - 1)
            if gcd(a, m) != 1:
                continue
            self.assertEqual(modinv(a, m), pow(a, -1, m))

    def test_non_invertible_raises(self):
        with self.assertRaises(NonInvertibleError):
            modinv(6, 9)  # gcd(6, 9) == 3

    def test_modulus_too_small_raises(self):
        with self.assertRaises(ModulusTooSmallError):
            modinv(1, 1)
        with self.assertRaises(ModulusTooSmallError):
            modinv(1, 0)


class TestModExp(unittest.TestCase):
    def test_known_value(self):
        self.assertEqual(mod_exp(4, 13, 497), 445)

    def test_against_python_pow(self):
        rng = random.Random(4)
        for _ in range(300):
            base = rng.randint(0, 10_000)
            exp = rng.randint(0, 1_000)
            mod = rng.randint(1, 10_000)
            self.assertEqual(mod_exp(base, exp, mod), pow(base, exp, mod))

    def test_exponent_zero(self):
        self.assertEqual(mod_exp(5, 0, 7), 1)

    def test_modulus_one_is_always_zero(self):
        self.assertEqual(mod_exp(123, 456, 1), 0)

    def test_modulus_too_small_raises(self):
        with self.assertRaises(ModulusTooSmallError):
            mod_exp(2, 3, 0)

    def test_negative_exponent_raises(self):
        with self.assertRaises(NegativeValueError):
            mod_exp(2, -1, 5)

    def test_mod_exp_steps_final_result_matches_mod_exp(self):
        base, exp, mod = 7, 560, 561
        steps = mod_exp_steps(base, exp, mod)
        self.assertEqual(steps[-1]["result"], mod_exp(base, exp, mod))

    def test_mod_exp_steps_row_count(self):
        # One setup row plus one row per binary digit of exp.
        steps = mod_exp_steps(4, 13, 497)  # 13 == 0b1101 -> 4 bits
        self.assertEqual(len(steps), 1 + 4)

    def test_mod_exp_steps_json_serialisable(self):
        import json

        json.dumps(mod_exp_steps(4, 13, 497))


if __name__ == "__main__":
    unittest.main()
