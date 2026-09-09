"""RSA encryption/decryption (plain and CRT) and short-text block encoding.

Block-size limit: text_to_blocks needs n large enough to hold at least one
byte (n >= 256). It picks the largest byte-width k with 256**k <= n, so
every block value is guaranteed to be < n. The plaintext is zero-padded on
the right to a multiple of k bytes before splitting; blocks_to_text strips
trailing zero bytes when reconstructing. That means a message that
genuinely ends with a NUL byte (U+0000) cannot round-trip exactly -- an
accepted limitation for the short, human-readable demo strings this
assignment encrypts.
"""

from . import MessageOutOfRangeError, NotIntegerError, TextTooLargeForModulusError
from .mathutils import mod_exp, modinv


def _require_int(value, name):
    if not isinstance(value, int) or isinstance(value, bool):
        raise NotIntegerError(f"{name} must be an int, got {type(value).__name__}")


def _require_in_range(value, name, n):
    _require_int(value, name)
    if not (0 <= value < n):
        raise MessageOutOfRangeError(f"{name} must satisfy 0 <= {name} < n ({n}), got {value}")


def encrypt(m, pub):
    """RSA encryption: c = m^e mod n."""
    _require_in_range(m, "m", pub.n)
    return mod_exp(m, pub.e, pub.n)


def decrypt(c, priv):
    """Plain RSA decryption: m = c^d mod n."""
    _require_in_range(c, "c", priv.n)
    return mod_exp(c, priv.d, priv.n)


def decrypt_crt(c, priv):
    """RSA decryption using the Chinese Remainder Theorem.

    Mathematically identical to decrypt(c, priv), but does the modular
    exponentiation modulo the (much smaller) primes p and q instead of
    modulo n, which is why real implementations use it for speed.
    """
    _require_in_range(c, "c", priv.n)
    p, q, d = priv.p, priv.q, priv.d

    dp = d % (p - 1)
    dq = d % (q - 1)
    q_inv = modinv(q, p)

    m1 = mod_exp(c, dp, p)
    m2 = mod_exp(c, dq, q)

    h = (q_inv * (m1 - m2)) % p
    return m2 + h * q


def _block_byte_width(n):
    _require_int(n, "n")
    if n < 256:
        raise TextTooLargeForModulusError(
            f"n = {n} is too small to encode even one byte as a block (need n >= 256)"
        )
    k = 1
    while 256 ** (k + 1) <= n:
        k += 1
    return k


def text_to_blocks(s, n):
    """Split UTF-8 text s into integer blocks, each guaranteed to be < n."""
    if not isinstance(s, str):
        raise NotIntegerError(f"s must be a str, got {type(s).__name__}")
    k = _block_byte_width(n)

    data = s.encode("utf-8")
    pad_len = (-len(data)) % k
    padded = data + b"\x00" * pad_len
    if not padded:
        return []
    return [int.from_bytes(padded[i : i + k], "big") for i in range(0, len(padded), k)]


def blocks_to_text(blocks, n):
    """Inverse of text_to_blocks: reassemble integer blocks into UTF-8 text."""
    k = _block_byte_width(n)
    raw = bytearray()
    for block in blocks:
        _require_in_range(block, "block", n)
        raw.extend(block.to_bytes(k, "big"))
    return bytes(raw).rstrip(b"\x00").decode("utf-8")
