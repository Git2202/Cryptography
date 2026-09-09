"""rsa: a small, stdlib-only, from-scratch implementation of textbook RSA.

Written for a college assignment on RSA key generation with small primes.
Every module here uses only the Python standard library.

This file also defines the exception hierarchy shared by every submodule,
so that callers can catch specific, descriptive error types instead of a
generic ValueError/TypeError.
"""

__all__ = [
    "RSAError",
    "NotIntegerError",
    "DomainError",
    "NegativeValueError",
    "NonInvertibleError",
    "ModulusTooSmallError",
    "InvalidRangeError",
    "NotPrimeError",
    "EqualPrimesError",
    "PrimeTooSmallError",
    "InvalidPublicExponentError",
    "MessageOutOfRangeError",
    "TextTooLargeForModulusError",
    "FactorizationError",
]


class RSAError(Exception):
    """Base class for every error raised by the rsa package."""


class NotIntegerError(RSAError, TypeError):
    """Raised when an argument that must be an int is not one."""


class DomainError(RSAError, ValueError):
    """Base class for arguments of the right type but the wrong value."""


class NegativeValueError(DomainError):
    """Raised when a value that must be >= 0 (or >= some bound) is negative."""


class NonInvertibleError(DomainError):
    """Raised when a modular inverse does not exist (gcd(a, m) != 1)."""


class ModulusTooSmallError(DomainError):
    """Raised when a modulus is too small to be meaningful (e.g. m < 2)."""


class InvalidRangeError(DomainError):
    """Raised when a numeric search range [low, high] is empty or invalid."""


class NotPrimeError(DomainError):
    """Raised when a value required to be prime is not prime."""


class EqualPrimesError(DomainError):
    """Raised when RSA's two primes p and q are equal."""


class PrimeTooSmallError(DomainError):
    """Raised when a prime supplied for key generation is below the minimum."""


class InvalidPublicExponentError(DomainError):
    """Raised when e is out of range or not coprime with lambda(n)/phi(n)."""


class MessageOutOfRangeError(DomainError):
    """Raised when a plaintext/ciphertext integer m is not in [0, n)."""


class TextTooLargeForModulusError(DomainError):
    """Raised when the modulus n is too small to encode a single byte block."""


class FactorizationError(RSAError, RuntimeError):
    """Raised when factor_n cannot factor n within its search bound."""
