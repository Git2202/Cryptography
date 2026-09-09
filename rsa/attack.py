"""Breaking small-modulus RSA: recover p, q and d from a public key alone.

This is exactly why RSA with small primes is insecure -- trial division
factors n in milliseconds once n only has a few million possibilities to
try. See the report for how this time grows with modulus size.
"""

import time

from . import FactorizationError, NotIntegerError
from .keygen import carmichael_lambda
from .mathutils import modinv


def _require_int(value, name):
    if not isinstance(value, int) or isinstance(value, bool):
        raise NotIntegerError(f"{name} must be an int, got {type(value).__name__}")


def factor_n(n):
    """Factor n = p * q by trial division.

    Returns (p, q, attempts, elapsed_ms):
      p, q        - the two factors found, p < q
      attempts    - how many candidate divisors were tried
      elapsed_ms  - wall-clock time taken, in milliseconds

    Raises FactorizationError if n has no factor up to sqrt(n) (e.g. n is
    itself prime, or n == 1).
    """
    _require_int(n, "n")
    if n < 4:
        raise FactorizationError(f"n = {n} is too small to be a product of two primes >= 2")

    start = time.perf_counter()
    attempts = 0

    candidate = 2
    while candidate * candidate <= n:
        attempts += 1
        if n % candidate == 0:
            elapsed_ms = (time.perf_counter() - start) * 1000
            return candidate, n // candidate, attempts, elapsed_ms
        candidate = 3 if candidate == 2 else candidate + 2

    elapsed_ms = (time.perf_counter() - start) * 1000
    raise FactorizationError(
        f"could not factor n = {n} by trial division up to sqrt(n) "
        f"({attempts} attempts, {elapsed_ms:.3f} ms) -- n may be prime"
    )


def recover_d(p, q, e):
    """Rebuild the private exponent d from the factors p, q and public e.

    This is the attacker's last step: once n is factored, lambda(n) can be
    recomputed exactly as the key's owner did, and d falls out the same way
    (d = e^-1 mod lambda(n)).
    """
    lam = carmichael_lambda(p, q)
    return modinv(e, lam)
