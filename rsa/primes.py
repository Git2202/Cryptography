"""Primality testing, a classic sieve, and random prime search.

is_prime_miller_rabin reuses mod_exp from mathutils rather than Python's
built-in pow(), so the whole primality test is built from the primitives
this assignment implements.
"""

import random

from . import InvalidRangeError, NotIntegerError
from .mathutils import mod_exp

# Deterministic Miller-Rabin witness set: testing every n below this bound
# against exactly these bases is a *proof* of primality, not a probabilistic
# guess. Source: Pomerance/Selfridge/Wagstaff-style deterministic base sets,
# as tabulated at https://miller-rabin.appspot.com/ and widely reproduced in
# textbooks (e.g. Menezes et al., Handbook of Applied Cryptography).
_DETERMINISTIC_BOUND = 3_317_044_064_679_887_385_961_981
_DETERMINISTIC_WITNESSES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)


def _require_int(value, name):
    if not isinstance(value, int) or isinstance(value, bool):
        raise NotIntegerError(f"{name} must be an int, got {type(value).__name__}")


def sieve_of_eratosthenes(limit):
    """All primes p with 2 <= p <= limit, in increasing order."""
    _require_int(limit, "limit")
    if limit < 2:
        raise InvalidRangeError(f"limit must be >= 2, got {limit}")

    is_composite = [False] * (limit + 1)
    primes = []
    for candidate in range(2, limit + 1):
        if not is_composite[candidate]:
            primes.append(candidate)
            for multiple in range(candidate * candidate, limit + 1, candidate):
                is_composite[multiple] = True
    return primes


def is_prime_trial(n):
    """True iff n is prime, checked by trial division up to sqrt(n)."""
    _require_int(n, "n")
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    divisor = 3
    while divisor * divisor <= n:
        if n % divisor == 0:
            return False
        divisor += 2
    return True


def _first_k_primes(k):
    primes = []
    candidate = 41  # continue just past the fixed deterministic witness set
    while len(primes) < k:
        if is_prime_trial(candidate):
            primes.append(candidate)
        candidate += 2
    return primes


def _miller_rabin_round(a, d, n, s):
    """One Miller-Rabin round with witness a. True means 'not proven composite'."""
    if a % n == 0:
        return True
    x = mod_exp(a, d, n)
    if x == 1 or x == n - 1:
        return True
    for _ in range(s - 1):
        x = mod_exp(x, 2, n)
        if x == n - 1:
            return True
    return False


def is_prime_miller_rabin(n, rounds=20):
    """Miller-Rabin primality test.

    For every n below _DETERMINISTIC_BOUND (far larger than anything this
    assignment generates), this is fully deterministic: it tests exactly the
    fixed witness set known to be correct for all such n, regardless of
    `rounds`. Only for n at or above that bound does `rounds` matter, where
    it selects how many additional small-prime witnesses to try; that branch
    is a high-confidence probabilistic check, not a proof.
    """
    _require_int(n, "n")
    if not isinstance(rounds, int) or isinstance(rounds, bool) or rounds < 1:
        raise NotIntegerError(f"rounds must be a positive int, got {rounds!r}")

    if n < 2:
        return False
    for p in _DETERMINISTIC_WITNESSES:
        if n == p:
            return True
        if n % p == 0:
            return False

    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1

    if n < _DETERMINISTIC_BOUND:
        witnesses = _DETERMINISTIC_WITNESSES
    else:
        witnesses = _first_k_primes(rounds)

    return all(_miller_rabin_round(a, d, n, s) for a in witnesses)


def random_prime(low, high, rng=None):
    """A prime chosen from [low, high] (inclusive), using rng if given.

    rng must be a random.Random instance (or compatible); None creates a
    fresh, system-seeded one. Passing the same seeded random.Random twice
    yields the same prime both times, which is what the determinism test
    relies on.
    """
    _require_int(low, "low")
    _require_int(high, "high")
    if low > high:
        raise InvalidRangeError(f"low ({low}) must be <= high ({high})")

    low = max(low, 2)
    if low > high:
        raise InvalidRangeError(f"no integers >= 2 in [{low}, {high}]")

    if rng is None:
        rng = random.Random()

    span = high - low + 1

    # Random sampling is fast when primes are reasonably dense in the range.
    for _ in range(min(span, 10_000)):
        candidate = rng.randint(low, high)
        if is_prime_miller_rabin(candidate):
            return candidate

    # Fallback: deterministic scan from a random offset, wrapping around, so
    # this terminates and finds a prime if the range contains one at all.
    start_offset = rng.randint(0, span - 1)
    for step in range(span):
        candidate = low + (start_offset + step) % span
        if is_prime_miller_rabin(candidate):
            return candidate

    raise InvalidRangeError(f"no prime found in [{low}, {high}]")
