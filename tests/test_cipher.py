import random
import unittest

from rsa import MessageOutOfRangeError, TextTooLargeForModulusError
from rsa.cipher import blocks_to_text, decrypt, decrypt_crt, encrypt, text_to_blocks
from rsa.keygen import generate_keypair


class TestKnownAnswerVector(unittest.TestCase):
    """p=61, q=53, e=17, d=413: m=65 -> c=2790 -> back to 65."""

    def setUp(self):
        self.kp = generate_keypair(p=61, q=53, e=17)

    def test_encrypt_known_value(self):
        self.assertEqual(encrypt(65, self.kp.public), 2790)

    def test_decrypt_known_value(self):
        self.assertEqual(decrypt(2790, self.kp.private), 65)

    def test_full_round_trip(self):
        c = encrypt(65, self.kp.public)
        self.assertEqual(decrypt(c, self.kp.private), 65)

    def test_crt_matches_plain_decrypt(self):
        c = encrypt(65, self.kp.public)
        self.assertEqual(decrypt_crt(c, self.kp.private), decrypt(c, self.kp.private))


class TestExhaustiveRoundTrip(unittest.TestCase):
    def test_every_message_round_trips(self):
        kp = generate_keypair(p=61, q=53, e=17)
        for m in range(kp.n):
            c = encrypt(m, kp.public)
            self.assertEqual(decrypt(c, kp.private), m, msg=f"failed for m={m}")

    def test_every_message_round_trips_via_crt(self):
        kp = generate_keypair(p=61, q=53, e=17)
        for m in range(kp.n):
            c = encrypt(m, kp.public)
            self.assertEqual(decrypt_crt(c, kp.private), m, msg=f"failed for m={m}")


class TestPropertyRandomKeys(unittest.TestCase):
    def test_decrypt_of_encrypt_is_identity_for_random_keys_and_messages(self):
        rng = random.Random(55)
        for _ in range(15):
            kp = generate_keypair(prime_low=50, prime_high=2000, rng=rng)
            self.assertEqual((kp.e * kp.d) % kp.lam, 1)
            for _ in range(10):
                m = rng.randint(0, kp.n - 1)
                c = encrypt(m, kp.public)
                self.assertEqual(decrypt(c, kp.private), m)
                self.assertEqual(decrypt_crt(c, kp.private), m)


class TestNegativeCases(unittest.TestCase):
    def setUp(self):
        self.kp = generate_keypair(p=61, q=53, e=17)

    def test_message_too_large_rejected(self):
        with self.assertRaises(MessageOutOfRangeError):
            encrypt(self.kp.n, self.kp.public)  # m == n is out of range

    def test_negative_message_rejected(self):
        with self.assertRaises(MessageOutOfRangeError):
            encrypt(-1, self.kp.public)

    def test_ciphertext_out_of_range_rejected(self):
        with self.assertRaises(MessageOutOfRangeError):
            decrypt(self.kp.n, self.kp.private)


class TestTextBlocks(unittest.TestCase):
    def test_round_trip_short_ascii(self):
        kp = generate_keypair(p=61, q=53, e=17)  # n=3233 -> 1 byte/block
        blocks = text_to_blocks("HI!", kp.n)
        self.assertTrue(all(b < kp.n for b in blocks))
        self.assertEqual(blocks_to_text(blocks, kp.n), "HI!")

    def test_round_trip_through_actual_encryption(self):
        kp = generate_keypair(p=61, q=53, e=17)
        blocks = text_to_blocks("RSA", kp.n)
        cipher_blocks = [encrypt(b, kp.public) for b in blocks]
        decrypted_blocks = [decrypt(c, kp.private) for c in cipher_blocks]
        self.assertEqual(blocks_to_text(decrypted_blocks, kp.n), "RSA")

    def test_larger_modulus_multibyte_blocks(self):
        # n just over 256**2 = 65536 -> 2 bytes per block.
        kp = generate_keypair(p=257, q=263, e=17)  # n = 67591
        text = "Hello, RSA!"
        blocks = text_to_blocks(text, kp.n)
        self.assertTrue(all(b < kp.n for b in blocks))
        self.assertEqual(blocks_to_text(blocks, kp.n), text)

    def test_modulus_too_small_for_text_rejected(self):
        with self.assertRaises(TextTooLargeForModulusError):
            text_to_blocks("hi", 100)  # n < 256, can't hold even one byte


if __name__ == "__main__":
    unittest.main()
