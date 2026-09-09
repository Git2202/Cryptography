"""RSA key generation: n, phi(n), lambda(n), e, d, and the KeyPair holding them.

Every intermediate value computed along the way is also appended to
KeyPair.trace as a JSON-serialisable dict, so the virtual lab's "key
generation walkthrough" panel can replay the exact same arithmetic the
Python code performed instead of re-deriving it.
"""

from dataclasses import dataclass, field

from . import (
    EqualPrimesError,
    InvalidPublicExponentError,
    NotIntegerError,
    NotPrimeError,
    PrimeTooSmallError,
)
from .mathutils import egcd_steps, gcd, lcm, modinv
from .primes import is_prime_miller_rabin, random_prime

# RSA needs two *odd* primes; excluding 2 avoids the degenerate case
# p=2 -> lambda(n) can end up as small as 1, leaving no valid e.
MIN_PRIME = 3

# A short list of small, well-known public exponents to try first when the
# caller doesn't supply e, most-preferred first. 65537 (a Fermat prime,
# 2^16+1) is the real-world default; it's tried first and falls through to
# smaller ones only because our primes (and hence lambda(n)) are small
# enough that 65537 often doesn't satisfy e < lambda(n).
_PREFERRED_E_CANDIDATES = (65537, 257, 17, 5, 3)


def _require_int(value, name):
    if not isinstance(value, int) or isinstance(value, bool):
        raise NotIntegerError(f"{name} must be an int, got {type(value).__name__}")


def _validate_distinct_primes(p, q):
    _require_int(p, "p")
    _require_int(q, "q")
    if p == q:
        raise EqualPrimesError(f"p and q must be different primes, both were {p}")
    for name, value in (("p", p), ("q", q)):
        if value < MIN_PRIME:
            raise PrimeTooSmallError(
                f"{name} must be >= {MIN_PRIME} (RSA needs odd primes), got {value}"
            )
        if not is_prime_miller_rabin(value):
            raise NotPrimeError(f"{name} = {value} is not prime")


def totient(p, q):
    """Euler's totient phi(n) for n = p*q, i.e. (p-1)*(q-1)."""
    _validate_distinct_primes(p, q)
    return (p - 1) * (q - 1)


def carmichael_lambda(p, q):
    """Carmichael's function lambda(n) for n = p*q, i.e. lcm(p-1, q-1)."""
    _validate_distinct_primes(p, q)
    return lcm(p - 1, q - 1)


def _choose_e(lam):
    """Pick a default public exponent e with 1 < e < lam and gcd(e, lam) == 1.

    Returns (e, candidates) where candidates is the trace of every e that
    was tried, in order, with its gcd against lambda(n).
    """
    candidates = []
    for e in _PREFERRED_E_CANDIDATES:
        if e >= lam:
            candidates.append({"e": e, "gcd_with_lambda": None, "accepted": False, "reason": "e >= lambda(n)"})
            continue
        g = gcd(e, lam)
        accepted = g == 1
        candidates.append({"e": e, "gcd_with_lambda": g, "accepted": accepted, "reason": None})
        if accepted:
            return e, candidates

    # None of the preferred exponents worked (only possible for very small
    # lambda(n)); fall back to a linear search over odd e.
    e = 3
    while e < lam:
        if e not in _PREFERRED_E_CANDIDATES:
            g = gcd(e, lam)
            accepted = g == 1
            candidates.append({"e": e, "gcd_with_lambda": g, "accepted": accepted, "reason": None})
            if accepted:
                return e, candidates
        e += 2

    raise InvalidPublicExponentError(f"no valid public exponent e found for lambda(n) = {lam}")


def _validate_e(e, lam):
    _require_int(e, "e")
    if not (1 < e < lam):
        raise InvalidPublicExponentError(f"e must satisfy 1 < e < lambda(n) ({lam}), got {e}")
    g = gcd(e, lam)
    if g != 1:
        raise InvalidPublicExponentError(f"e = {e} is not coprime with lambda(n) = {lam} (gcd = {g})")


@dataclass(frozen=True)
class PublicKey:
    e: int
    n: int


@dataclass(frozen=True)
class PrivateKey:
    d: int
    n: int
    p: int
    q: int


@dataclass(frozen=True)
class KeyPair:
    p: int
    q: int
    n: int
    phi: int
    lam: int
    e: int
    d: int
    trace: list = field(default_factory=list)

    @property
    def public(self) -> PublicKey:
        return PublicKey(e=self.e, n=self.n)

    @property
    def private(self) -> PrivateKey:
        return PrivateKey(d=self.d, n=self.n, p=self.p, q=self.q)


def generate_keypair(p=None, q=None, e=None, prime_low=100, prime_high=9999, rng=None):
    """Generate an RSA KeyPair.

    If p and q are given, they are used directly (and validated). Otherwise
    two distinct primes are drawn from [prime_low, prime_high] using rng
    (random_prime's rules apply: rng=None means system-seeded).

    If e is given it is validated (1 < e < lambda(n), gcd(e, lambda(n)) == 1).
    Otherwise a default e is chosen automatically from a short preferred list.

    d is computed as the inverse of e modulo lambda(n) (Carmichael's
    function), not phi(n) -- see the report for why textbooks usually use
    phi(n) even though lambda(n) gives the smaller, "true" private exponent.
    """
    trace = []

    if p is None or q is None:
        if p is not None or q is not None:
            raise NotIntegerError("p and q must both be given, or both omitted")
        while True:
            p = random_prime(prime_low, prime_high, rng=rng)
            q = random_prime(prime_low, prime_high, rng=rng)
            if p != q:
                break
    trace.append({"stage": "select_primes", "p": p, "q": q})

    _validate_distinct_primes(p, q)

    n = p * q
    trace.append(
        {"stage": "compute_n", "p": p, "q": q, "n": n, "equation": f"n = p * q = {p} * {q} = {n}"}
    )

    phi = totient(p, q)
    trace.append(
        {
            "stage": "compute_phi",
            "p": p,
            "q": q,
            "phi": phi,
            "equation": f"phi(n) = (p-1) * (q-1) = {p - 1} * {q - 1} = {phi}",
        }
    )

    lam = carmichael_lambda(p, q)
    trace.append(
        {
            "stage": "compute_lambda",
            "p": p,
            "q": q,
            "lam": lam,
            "equation": f"lambda(n) = lcm(p-1, q-1) = lcm({p - 1}, {q - 1}) = {lam}",
        }
    )

    if e is None:
        e, e_candidates = _choose_e(lam)
    else:
        _validate_e(e, lam)
        e_candidates = [{"e": e, "gcd_with_lambda": gcd(e, lam), "accepted": True, "reason": "given by caller"}]
    trace.append({"stage": "choose_e", "candidates": e_candidates, "chosen_e": e})

    egcd_table = egcd_steps(e, lam)
    d = modinv(e, lam)
    trace.append(
        {
            "stage": "compute_d",
            "e": e,
            "lam": lam,
            "egcd_table": egcd_table,
            "d": d,
            "equation": f"d = e^-1 mod lambda(n) = {e}^-1 mod {lam} = {d}",
        }
    )

    trace.append({"stage": "keys", "public": {"e": e, "n": n}, "private": {"d": d, "n": n}})

    return KeyPair(p=p, q=q, n=n, phi=phi, lam=lam, e=e, d=d, trace=trace)
