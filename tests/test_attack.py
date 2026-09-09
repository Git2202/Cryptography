import unittest

from rsa import FactorizationError
from rsa.attack import factor_n, recover_d
from rsa.cipher import decrypt, encrypt
from rsa.keygen import PrivateKey, generate_keypair


class TestFactorN(unittest.TestCase):
    def test_recovers_known_factors(self):
        p, q, attempts, elapsed_ms = factor_n(3233)  # 61 * 53
        self.assertEqual({p, q}, {61, 53})
        self.assertGreater(attempts, 0)
        self.assertGreaterEqual(elapsed_ms, 0)

    def test_factors_are_ordered_ascending(self):
        p, q, _attempts, _elapsed_ms = factor_n(3233)
        self.assertLess(p, q)

    def test_prime_n_raises(self):
        with self.assertRaises(FactorizationError):
            factor_n(97)  # 97 is prime, has no two-factor split

    def test_too_small_n_raises(self):
        with self.assertRaises(FactorizationError):
            factor_n(3)


class TestFullAttack(unittest.TestCase):
    def test_break_known_answer_key(self):
        kp = generate_keypair(p=61, q=53, e=17)
        c = encrypt(65, kp.public)

        p, q, _attempts, _elapsed_ms = factor_n(kp.n)
        recovered_d = recover_d(p, q, kp.e)
        recovered_priv = PrivateKey(d=recovered_d, n=kp.n, p=p, q=q)

        self.assertEqual(decrypt(c, recovered_priv), 65)

    def test_break_random_small_key(self):
        kp = generate_keypair(p=113, q=127, e=17)  # n = 14351
        message = 4242
        c = encrypt(message, kp.public)

        p, q, attempts, elapsed_ms = factor_n(kp.n)
        recovered_d = recover_d(p, q, kp.e)
        recovered_priv = PrivateKey(d=recovered_d, n=kp.n, p=p, q=q)

        self.assertEqual(decrypt(c, recovered_priv), message)
        self.assertGreater(attempts, 0)
        self.assertGreaterEqual(elapsed_ms, 0)


if __name__ == "__main__":
    unittest.main()
