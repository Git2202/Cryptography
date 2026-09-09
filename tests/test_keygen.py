import json
import random
import unittest

from rsa import (
    EqualPrimesError,
    InvalidPublicExponentError,
    NotPrimeError,
    PrimeTooSmallError,
)
from rsa.keygen import KeyPair, carmichael_lambda, generate_keypair, totient
from rsa.mathutils import gcd


class TestTotientAndLambda(unittest.TestCase):
    def test_known_answer_61_53(self):
        self.assertEqual(totient(61, 53), 3120)
        self.assertEqual(carmichael_lambda(61, 53), 780)

    def test_lambda_divides_phi(self):
        p, q = 17, 23
        phi = totient(p, q)
        lam = carmichael_lambda(p, q)
        self.assertEqual(phi % lam, 0)

    def test_equal_primes_rejected(self):
        with self.assertRaises(EqualPrimesError):
            totient(13, 13)

    def test_non_prime_rejected(self):
        with self.assertRaises(NotPrimeError):
            totient(9, 13)  # 9 = 3*3, not prime

    def test_too_small_rejected(self):
        with self.assertRaises(PrimeTooSmallError):
            totient(2, 13)


class TestGenerateKeypairKnownAnswer(unittest.TestCase):
    """The assignment's known-answer vector: p=61, q=53, e=17.

    Verified independently with Python's own pow(e, -1, m) before trusting
    it here: n=3233, phi=3120, lambda=780, d=413 (mod lambda) / 2753 (mod
    phi); m=65 encrypts to c=2790 and both values of d decrypt it back to
    65. All figures below match the assignment brief exactly -- nothing
    needed correcting.
    """

    def setUp(self):
        self.kp = generate_keypair(p=61, q=53, e=17)

    def test_n_phi_lambda(self):
        self.assertEqual(self.kp.n, 3233)
        self.assertEqual(self.kp.phi, 3120)
        self.assertEqual(self.kp.lam, 780)

    def test_d_matches_lambda_based_value(self):
        self.assertEqual(self.kp.d, 413)

    def test_d_phi_alternative_also_valid(self):
        from rsa.mathutils import modinv

        d_phi = modinv(17, self.kp.phi)
        self.assertEqual(d_phi, 2753)
        # Both the lambda-based and phi-based private exponent must satisfy
        # e*d == 1 mod lambda(n) (that's the only congruence RSA needs).
        self.assertEqual((17 * d_phi) % self.kp.lam, 1)

    def test_public_and_private_key_views(self):
        self.assertEqual(self.kp.public.e, 17)
        self.assertEqual(self.kp.public.n, 3233)
        self.assertEqual(self.kp.private.d, 413)

    def test_trace_is_json_serialisable(self):
        json.dumps(self.kp.trace)

    def test_trace_covers_every_stage(self):
        stages = [row["stage"] for row in self.kp.trace]
        self.assertEqual(
            stages,
            [
                "select_primes",
                "compute_n",
                "compute_phi",
                "compute_lambda",
                "choose_e",
                "compute_d",
                "keys",
            ],
        )


class TestGenerateKeypairValidation(unittest.TestCase):
    def test_equal_primes_rejected(self):
        with self.assertRaises(EqualPrimesError):
            generate_keypair(p=61, q=61, e=17)

    def test_non_prime_rejected(self):
        with self.assertRaises(NotPrimeError):
            generate_keypair(p=60, q=53, e=17)

    def test_too_small_prime_rejected(self):
        with self.assertRaises(PrimeTooSmallError):
            generate_keypair(p=2, q=53, e=17)

    def test_e_out_of_range_rejected(self):
        with self.assertRaises(InvalidPublicExponentError):
            generate_keypair(p=61, q=53, e=780)  # e must be < lambda(n)
        with self.assertRaises(InvalidPublicExponentError):
            generate_keypair(p=61, q=53, e=1)  # e must be > 1

    def test_e_not_coprime_rejected(self):
        # lambda(61, 53) == 780 == 2^2 * 3 * 5 * 13; e=15 shares factors 3 and 5.
        with self.assertRaises(InvalidPublicExponentError):
            generate_keypair(p=61, q=53, e=15)


class TestGenerateKeypairRandom(unittest.TestCase):
    def test_default_random_keypair_is_valid(self):
        kp = generate_keypair(prime_low=100, prime_high=500, rng=random.Random(99))
        self.assertNotEqual(kp.p, kp.q)
        self.assertEqual(kp.n, kp.p * kp.q)
        self.assertEqual((kp.e * kp.d) % kp.lam, 1)
        self.assertTrue(1 < kp.e < kp.lam)
        self.assertEqual(gcd(kp.e, kp.lam), 1)

    def test_determinism_same_seed_same_keypair(self):
        kp1 = generate_keypair(prime_low=100, prime_high=5000, rng=random.Random(2024))
        kp2 = generate_keypair(prime_low=100, prime_high=5000, rng=random.Random(2024))
        self.assertEqual((kp1.p, kp1.q, kp1.e, kp1.d), (kp2.p, kp2.q, kp2.e, kp2.d))

    def test_many_random_keypairs_satisfy_rsa_identity(self):
        rng = random.Random(123)
        for _ in range(20):
            kp = generate_keypair(prime_low=50, prime_high=2000, rng=rng)
            self.assertEqual((kp.e * kp.d) % kp.lam, 1)


if __name__ == "__main__":
    unittest.main()
