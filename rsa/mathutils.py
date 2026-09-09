"""Modular-arithmetic building blocks used everywhere else in the package.

Functions here are deliberately split into a "just the answer" version and,
for the two functions the virtual lab needs to animate row by row, a
"_steps" version that returns the full working as a list of JSON-serialisable
dicts (only int/str/bool values, no custom objects).
"""

from . import (
    DomainError,
    ModulusTooSmallError,
    NegativeValueError,
    NonInvertibleError,
    NotIntegerError,
)


def _require_int(value, name):
    if not isinstance(value, int) or isinstance(value, bool):
        raise NotIntegerError(f"{name} must be an int, got {type(value).__name__}")


def _require_nonnegative(value, name):
    _require_int(value, name)
    if value < 0:
        raise NegativeValueError(f"{name} must be >= 0, got {value}")


def gcd(a, b):
    """Greatest common divisor of two non-negative integers (Euclid's algorithm).

    gcd(0, 0) is defined as 0, matching math.gcd, so callers never have to
    special-case it.
    """
    _require_nonnegative(a, "a")
    _require_nonnegative(b, "b")
    while b:
        a, b = b, a % b
    return a


def lcm(a, b):
    """Least common multiple of two non-negative integers.

    lcm(a, 0) == lcm(0, b) == 0 by convention (matches math.lcm).
    """
    _require_nonnegative(a, "a")
    _require_nonnegative(b, "b")
    if a == 0 or b == 0:
        return 0
    return (a // gcd(a, b)) * b


def egcd(a, b):
    """Extended Euclidean algorithm.

    Returns (g, x, y) such that a*x + b*y == g == gcd(a, b).
    """
    _require_nonnegative(a, "a")
    _require_nonnegative(b, "b")

    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t


def egcd_steps(a, b):
    """Extended Euclidean algorithm, returning every row of the textbook table.

    Each row is a dict with:
      i        - row index, starting at 0
      r        - remainder at this row
      q        - quotient used to produce the *next* row's remainder
                 (None on the last row, since there is no next remainder)
      s, t     - Bezout coefficients at this row, so that a*s + b*t == r
      equation - a human-readable rendering of r == a*s + b*t

    The final row (where r == gcd(a, b)) carries the answer; a lab UI can
    just display this list top to bottom as the table.
    """
    _require_nonnegative(a, "a")
    _require_nonnegative(b, "b")

    rows = []
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1

    rows.append(
        {
            "i": 0,
            "r": old_r,
            "q": None,
            "s": old_s,
            "t": old_t,
            "equation": f"{old_r} == {a}*{old_s} + {b}*{old_t}",
        }
    )

    i = 1
    while r != 0:
        q = old_r // r
        rows[-1]["q"] = q  # the quotient belongs to the row that produced it

        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t

        rows.append(
            {
                "i": i,
                "r": old_r,
                "q": None,
                "s": old_s,
                "t": old_t,
                "equation": f"{old_r} == {a}*{old_s} + {b}*{old_t}",
            }
        )
        i += 1

    return rows


def modinv(a, m):
    """Modular inverse of a mod m: the unique x in [0, m) with a*x % m == 1.

    Raises ModulusTooSmallError if m < 2, NonInvertibleError if gcd(a, m) != 1.
    """
    _require_nonnegative(a, "a")
    _require_int(m, "m")
    if m < 2:
        raise ModulusTooSmallError(f"modulus m must be >= 2, got {m}")

    g, x, _y = egcd(a % m, m)
    if g != 1:
        raise NonInvertibleError(
            f"no inverse: gcd({a}, {m}) == {g}, not 1"
        )
    return x % m


def mod_exp(base, exp, mod):
    """base**exp mod mod, via left-to-right square-and-multiply.

    exp must be >= 0. mod must be >= 1 (mod == 1 always yields 0).
    """
    _require_nonnegative(base, "base")
    _require_nonnegative(exp, "exp")
    _require_int(mod, "mod")
    if mod < 1:
        raise ModulusTooSmallError(f"modulus mod must be >= 1, got {mod}")
    if mod == 1:
        return 0

    result = 1
    base = base % mod
    for bit in bin(exp)[2:]:  # MSB first, e.g. "1011"
        result = (result * result) % mod
        if bit == "1":
            result = (result * base) % mod
    return result


def mod_exp_steps(base, exp, mod):
    """Square-and-multiply, returning one dict per exponent bit processed.

    Row 0 is a "setup" row recording the reduced base and the exponent's
    binary form. Every following row corresponds to one bit of exp,
    processed MSB to LSB, and shows the square step and (if the bit is 1)
    the multiply step.
    """
    _require_nonnegative(base, "base")
    _require_nonnegative(exp, "exp")
    _require_int(mod, "mod")
    if mod < 1:
        raise ModulusTooSmallError(f"modulus mod must be >= 1, got {mod}")

    exp_bits = bin(exp)[2:]
    base_mod = 0 if mod == 1 else base % mod

    rows = [
        {
            "step": 0,
            "type": "setup",
            "base": base,
            "mod": mod,
            "base_mod_n": base_mod,
            "exponent_binary": exp_bits,
            "note": "Reduce base mod n, then process exponent bits MSB to LSB.",
        }
    ]

    result = 1
    for idx, bit in enumerate(exp_bits):
        before = result
        if mod == 1:
            after_square = 0
        else:
            after_square = (result * result) % mod
        multiplied = bit == "1"
        if multiplied:
            after_multiply = 0 if mod == 1 else (after_square * base_mod) % mod
        else:
            after_multiply = after_square
        result = after_multiply

        rows.append(
            {
                "step": idx + 1,
                "type": "bit",
                "bit_index": idx,
                "bit": bit,
                "result_before": before,
                "result_after_square": after_square,
                "multiplied": multiplied,
                "result_after_multiply": after_multiply,
                "result": result,
            }
        )

    return rows
