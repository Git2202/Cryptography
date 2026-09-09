import random
import unittest

from rsa import InvalidRangeError, NotIntegerError
from rsa.primes import (
    is_prime_miller_rabin,
    is_prime_trial,
    random_prime,
    sieve_of_eratosthenes,
)


class TestSieve(unittest.TestCase):
    def test_small_known_primes(self):
        self.assertEqual(
            sieve_of_eratosthenes(50),
            [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47],
        )

    def test_limit_two_returns_just_two(self):
        self.assertEqual(sieve_of_eratosthenes(2), [2])

    def test_matches_trial_division_up_to_2000(self):
        sieve_primes = set(sieve_of_eratosthenes(2000))
        trial_primes = {n for n in range(2, 2001) if is_prime_trial(n)}
        self.assertEqual(sieve_primes, trial_primes)

    def test_rejects_limit_below_two(self):
        with self.assertRaises(InvalidRangeError):
            sieve_of_eratosthenes(1)

    def test_rejects_non_int(self):
        with self.assertRaises(NotIntegerError):
            sieve_of_eratosthenes(50.0)


class TestIsPrimeTrial(unittest.TestCase):
    def test_known_values(self):
        self.assertFalse(is_prime_trial(-5))
        self.assertFalse(is_prime_trial(0))
        self.assertFalse(is_prime_trial(1))
        self.assertTrue(is_prime_trial(2))
        self.assertTrue(is_prime_trial(3))
        self.assertFalse(is_prime_trial(4))
        self.assertTrue(is_prime_trial(97))
        self.assertFalse(is_prime_trial(91))  # 7 * 13


class TestIsPrimeMillerRabin(unittest.TestCase):
    def test_agrees_with_trial_division_below_10000(self):
        for n in range(0, 10_000):
            self.assertEqual(
                is_prime_miller_rabin(n),
                is_prime_trial(n),
                msg=f"disagreement at n={n}",
            )

    def test_known_carmichael_number_is_not_prime(self):
        # 561 = 3 * 11 * 17 is the smallest Carmichael number: Fermat's test
        # is fooled by it for many bases, but Miller-Rabin must not be.
        self.assertFalse(is_prime_miller_rabin(561))

    def test_larger_known_prime(self):
        self.assertTrue(is_prime_miller_rabin(104729))  # the 10000th prime

    def test_rejects_invalid_rounds(self):
        with self.assertRaises(NotIntegerError):
            is_prime_miller_rabin(97, rounds=0)


class TestRandomPrime(unittest.TestCase):
    def test_returns_prime_within_range(self):
        rng = random.Random(42)
        for _ in range(50):
            p = random_prime(100, 200, rng=rng)
            self.assertTrue(is_prime_trial(p))
            self.assertTrue(100 <= p <= 200)

    def test_deterministic_with_seeded_rng(self):
        p1 = random_prime(1000, 5000, rng=random.Random(7))
        p2 = random_prime(1000, 5000, rng=random.Random(7))
        self.assertEqual(p1, p2)

    def test_single_prime_range(self):
        self.assertEqual(random_prime(97, 97), 97)

    def test_raises_when_no_prime_in_range(self):
        with self.assertRaises(InvalidRangeError):
            random_prime(24, 28)  # 25, 26, 27, 28 all composite, 24 too

    def test_raises_when_low_greater_than_high(self):
        with self.assertRaises(InvalidRangeError):
            random_prime(100, 10)


if __name__ == "__main__":
    unittest.main()
