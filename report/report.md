# RSA Key Generation with Small Primes: Implementation, Virtual Laboratory, and Security Analysis

**A college assignment in cryptography**

---

*A note on this document's format: this report was built as Markdown. Neither
`pandoc` nor `weasyprint` (the two PDF-generation tools the assignment brief
allows) is installed on the machine this project was built on, so no PDF was
generated — this `.md` file (renderable directly on GitHub/GitLab or any
Markdown viewer) is the deliverable, as the brief's own fallback instruction
("if not, skip it and tell me") anticipates. See [README.md](../README.md)
for how to produce a PDF if `pandoc` or `weasyprint` becomes available.*

## Abstract

This report documents a from-scratch, standard-library-only implementation
of textbook RSA using small (a few hundred to a few tens of thousands)
primes, built for a cryptography assignment. It covers the mathematics that
makes RSA work, the algorithms used to generate keys and to encrypt/decrypt,
a from-scratch attack that breaks the scheme by brute-force factorisation,
an interactive browser-based virtual laboratory that visualises every step
of the process, and an experimental study — run on this project's own code
— of how key-generation time, factoring time, and CRT-accelerated
decryption scale with number size. The central practical finding is
unambiguous: trial-division factoring time grows roughly four-fold for
every two extra bits added to each prime, from 0.006 ms at a 15-bit modulus
to 719 ms at a 48-bit modulus (Section 6) — a trend that, extrapolated,
explains directly why real RSA deployments use 1024-bit (or larger) primes
rather than the small ones used here for demonstration.

---

## 1. Introduction and Objectives

RSA, published by Rivest, Shamir and Adleman in 1978 [1], was the first
practical public-key cryptosystem: it lets two parties who have never met
exchange a secret message using only publicly known information. Its
security rests on a simple asymmetry — multiplying two large primes
together is fast, but factoring the product back into those primes is
believed to be computationally infeasible once the primes are large enough.

The objective of this assignment is threefold:

1. **Implement** every primitive RSA needs (modular arithmetic, primality
   testing, key generation, encryption/decryption, and a factoring attack)
   from first principles, using nothing but the Python standard library, and
   verify the implementation against a known-answer test vector and an
   extensive automated test suite.
2. **Visualise** the algorithm interactively, so that each arithmetic step —
   not just the final answer — is inspectable, through a self-contained,
   offline virtual laboratory.
3. **Demonstrate empirically**, rather than just assert, why RSA with small
   primes is insecure, by building and running an attack against the
   project's own generated keys and measuring how attack cost scales with
   key size.

Deliberately using *small* primes throughout is what makes both the
attack and the visualisation possible within a classroom setting: a real
2048-bit RSA modulus cannot be factored by trial division in the age of the
universe, but a 24-bit one can be factored in well under a second, which is
precisely what makes it a useful teaching example rather than a secure
cryptosystem.

---

## 2. Mathematical Background

### 2.1 Modular arithmetic

All RSA arithmetic happens modulo a number `n`. Two integers `a` and `b`
are *congruent modulo n*, written `a ≡ b (mod n)`, if `n` divides `a - b`.
Modular arithmetic behaves like ordinary arithmetic under addition,
subtraction and multiplication (it forms a ring), which is what allows
`m^e mod n` to be computed a step at a time — as done in `mod_exp` — rather
than by first computing the (potentially astronomically large) integer
`m^e` and reducing it afterwards.

### 2.2 Fermat's little theorem

If `p` is prime and `a` is any integer not divisible by `p`, then

```
a^(p-1) ≡ 1 (mod p)
```

This is the p=prime special case that both Euler's theorem and the RSA
correctness proof below build on.

### 2.3 Euler's theorem and φ(n)

Euler's totient function `φ(n)` counts the integers in `[1, n]` that are
coprime to `n`. For `n = p·q` with `p ≠ q` both prime,

```
φ(n) = (p-1)(q-1)
```

(this is `rsa.keygen.totient`). Euler's theorem generalises Fermat's little
theorem to any modulus: for any integer `a` coprime to `n`,

```
a^φ(n) ≡ 1 (mod n)
```

### 2.4 Why `m^(ed) ≡ m (mod n)` — RSA's correctness

RSA chooses `e` and `d` so that `e·d ≡ 1 (mod λ(n))` (Section 2.5 explains
`λ(n)`), i.e. `e·d = 1 + k·λ(n)` for some integer `k`. Correctness needs to
show `m^(ed) ≡ m (mod n)` for **every** message `m` in `[0, n)`, not only
those coprime to `n` — the exhaustive round-trip test in
[`tests/test_cipher.py`](../tests/test_cipher.py) checks exactly this,
every `m` from `0` to `n-1`.

The clean way to see it is via the Chinese Remainder Theorem (CRT), working
mod `p` and mod `q` separately and combining:

- **Case `p ∤ m`** (p does not divide m): Fermat's little theorem gives
  `m^(p-1) ≡ 1 (mod p)`. Since `(p-1) | λ(n)` (by construction,
  `λ(n) = lcm(p-1, q-1)`), also `(p-1) | (ed - 1)`, so
  `m^(ed-1) ≡ 1 (mod p)`, hence `m^(ed) ≡ m (mod p)`.
- **Case `p | m`**: then `m ≡ 0 (mod p)`, so trivially `m^(ed) ≡ 0 ≡ m (mod p)`.

Either way, `m^(ed) ≡ m (mod p)`. The same argument mod `q` gives
`m^(ed) ≡ m (mod q)`. Since `p` and `q` are distinct primes (so coprime),
the Chinese Remainder Theorem says a number congruent to `m` modulo both
`p` and `q` is congruent to `m` modulo `n = p·q` — so `m^(ed) ≡ m (mod n)`
for **every** `m`, not just those coprime to `n`.

### 2.5 λ(n) versus φ(n)

Carmichael's function `λ(n) = lcm(p-1, q-1)` (`rsa.keygen.carmichael_lambda`)
is what the correctness proof above actually needs: `e·d ≡ 1 (mod λ(n))` is
the exact condition required for `m^(ed) ≡ m (mod n)` to hold for every `m`.
Since `λ(n)` always divides `φ(n) = (p-1)(q-1)` (because `lcm(a,b)` always
divides `a·b`), choosing `d` as the inverse of `e` modulo the larger `φ(n)`
also satisfies the `λ(n)` congruence (any multiple of `φ(n)` added to `1` is
also a multiple of `λ(n)` added to `1`, since `λ(n) | φ(n)`) — so both
choices of `d` are valid private exponents; the `λ(n)`-based one is simply
the smaller, tighter one. The assignment's known-answer vector demonstrates
both work: for `p=61, q=53, e=17`, `d = 413 (mod λ(n)=780)` and
`d = 2753 (mod φ(n)=3120)` both correctly decrypt `c = 2790` back to `m = 65`
(verified in [`tests/test_keygen.py`](../tests/test_keygen.py); Section 4.5
covers a second, related test proving both choices of `d` decrypt the same
ciphertext, motivated by the virtual lab's own choice to use `φ(n)`).

**Why textbooks usually teach φ(n) anyway:** Euler's theorem (needing only
`φ(n)`) is typically covered before the more specialised Carmichael's
theorem (needing `λ(n)`) in a first course, and `φ(n) = (p-1)(q-1)` is a
one-line formula, whereas `λ(n) = lcm(p-1, q-1)` requires an extra `lcm`
(itself a `gcd`) step. Since both give a mathematically valid `d`, the
simpler `φ(n)` is pedagogically convenient even though `λ(n)` is the
minimal, and therefore the theoretically "correct", choice. This
implementation uses `λ(n)` by default (`rsa.keygen.generate_keypair`) and
exposes `φ(n)` alongside it so both can be compared directly, as above.

### 2.6 The Chinese Remainder Theorem and CRT decryption

Section 2.4 already used the CRT to prove correctness; it is also the basis
of a real speed optimisation. Given a ciphertext `c`, plain decryption
computes `c^d mod n` directly — one exponentiation modulo the full-size
`n`. CRT decryption (`rsa.cipher.decrypt_crt`) instead computes:

```
d_p = d mod (p-1)
d_q = d mod (q-1)
q_inv = q^-1 mod p
m1 = c^d_p mod p
m2 = c^d_q mod q
h = q_inv * (m1 - m2) mod p
m = m2 + h*q
```

`m1` and `m2` are `m mod p` and `m mod q` respectively (by the same
Fermat/Euler argument as Section 2.4, restricted to the smaller exponents
`d_p`, `d_q`); the last two lines are Garner's formula for reconstructing
the unique `m mod n` consistent with both, which is exactly what the CRT
guarantees exists. Because `p` and `q` have roughly half as many bits as
`n`, and because schoolbook multiplication cost grows worse than linearly
with operand size, real (large-key) RSA implementations see CRT decryption
run close to four times faster than plain decryption. Section 6.4 reports
what was actually measured for the small keys used in this assignment,
which — perhaps surprisingly — does *not* show that speedup, and explains why.

---

## 3. Algorithms (Pseudocode)

### 3.1 Key generation

```
function generate_keypair(prime_low, prime_high, e = None):
    repeat:
        p = random_prime(prime_low, prime_high)
        q = random_prime(prime_low, prime_high)
    until p != q

    n   = p * q
    phi = (p - 1) * (q - 1)
    lam = lcm(p - 1, q - 1)

    if e is None:
        for candidate in [65537, 257, 17, 5, 3, ...]:      # preferred, then a linear search
            if 1 < candidate < lam and gcd(candidate, lam) == 1:
                e = candidate
                break
    else:
        assert 1 < e < lam and gcd(e, lam) == 1

    d = modinv(e, lam)          # e*d == 1 (mod lam)
    return public_key(e, n), private_key(d, n)
```

### 3.2 Extended Euclidean algorithm

Used both to compute `gcd(a, b)` with its Bézout coefficients, and (as
`modinv`) to compute the modular inverse needed for `d` above.

```
function egcd(a, b):
    (old_r, r) = (a, b)
    (old_s, s) = (1, 0)
    (old_t, t) = (0, 1)
    while r != 0:
        q = old_r div r                       # integer division
        (old_r, r) = (r, old_r - q * r)
        (old_s, s) = (s, old_s - q * s)
        (old_t, t) = (t, old_t - q * t)
    return old_r, old_s, old_t                # g, x, y  with  a*x + b*y = g

function modinv(a, m):
    g, x, _ = egcd(a mod m, m)
    assert g == 1                             # otherwise no inverse exists
    return x mod m
```

### 3.3 Square-and-multiply (modular exponentiation)

```
function mod_exp(base, exp, mod):
    if mod == 1: return 0
    result = 1
    base = base mod mod
    for each bit of exp, most-significant first:
        result = (result * result) mod mod    # square
        if bit == 1:
            result = (result * base) mod mod  # multiply
    return result
```

This computes `base^exp mod mod` in `O(log exp)` multiplications instead of
`O(exp)`, which is what makes RSA with hundreds-of-digit exponents
practical at all.

### 3.4 Primality testing (deterministic Miller–Rabin)

```
function is_prime_miller_rabin(n):
    if n < 2: return false
    for p in {2,3,5,7,11,...,37}:             # fixed witness set
        if n == p: return true
        if n % p == 0: return false

    write n - 1 = 2^s * d                     # d odd

    for a in {2,3,5,7,11,...,37}:
        x = mod_exp(a, d, n)
        if x == 1 or x == n - 1: continue
        repeat s - 1 times:
            x = mod_exp(x, 2, n)
            if x == n - 1: break (continue outer loop)
        else:
            return false                       # n is definitely composite
    return true                                 # n is prime (proved, for all n
                                                  # below the deterministic bound)
```

Testing exactly the fixed witness set `{2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
31, 37}` is a *proof* of primality (not a probabilistic guess) for every
`n` below `3,317,044,064,679,887,385,961,981` — a bound far larger than
anything this assignment's "small primes" ever approach, so every prime
this project generates is certifiably, not just probably, prime.

---

## 4. Implementation Methodology

### 4.1 Module structure

```
rsa/
  __init__.py    exception hierarchy shared by every module below
  mathutils.py   gcd, lcm, egcd (+ egcd_steps), modinv, mod_exp (+ mod_exp_steps)
  primes.py      sieve_of_eratosthenes, is_prime_trial, is_prime_miller_rabin, random_prime
  keygen.py      totient, carmichael_lambda, KeyPair/PublicKey/PrivateKey, generate_keypair
  cipher.py      encrypt, decrypt, decrypt_crt, text_to_blocks, blocks_to_text
  attack.py      factor_n, recover_d
cli.py           command-line demo over all of the above
tests/           one test module per rsa/ module, plus the known-answer vector
tools/               run_experiments.py, which produced every number in Section 6
RSA-Virtual-Lab/     index.html, style.css, script.js (Section 5) + README.md
```

Each module depends only on the ones above it in this list (`cipher.py` and
`attack.py` both build on `keygen.py`, which builds on `primes.py` and
`mathutils.py`), so the dependency graph is a straight line, not a web.

### 4.2 Design decisions

- **λ(n) by default, φ(n) exposed alongside it** — see Section 2.5.
- **A public exponent search order of `[65537, 257, 17, 5, 3]`, then a
  linear scan** — 65537 is the real-world default (a Fermat prime, so it is
  coprime with `λ(n)` unless `λ(n)` is itself a multiple of 65537), but with
  small primes `λ(n)` is frequently smaller than 65537, so the search
  falls through to smaller, still-standard exponents.
- **Miller–Rabin built on `mod_exp`, not Python's built-in `pow()`** — so
  the primality test is composed from this project's own primitives rather
  than silently depending on the standard library for the one piece of
  arithmetic that matters most.
- **A minimum prime of 3** — excluding 2 avoids the degenerate case where
  `λ(n)` can be as small as 1, which would leave no valid `e`.

### 4.3 Why the trace objects exist

`egcd_steps`, `mod_exp_steps`, and `KeyPair.trace` all return the *complete
working*, not just the final answer, as a list of small, JSON-serialisable
dictionaries (plain ints, strings and booleans — no custom objects). This
exists for two reasons: (1) it is what lets `tests/` assert on intermediate
correctness (e.g. "every row of the extended-Euclid table satisfies
`a*s + b*t == r`", not just the final `d`), and (2) conceptually, it is
exactly the data a UI would need to replay the computation step by step —
though in practice the virtual laboratory (Section 5) reimplements the same
logic independently in JavaScript rather than consuming this Python output
directly, since it must run fully offline with no server and no build step.

### 4.4 Input validation

Every public function validates its arguments and raises one of the
specific exception subclasses defined in `rsa/__init__.py` (e.g.
`EqualPrimesError`, `NotPrimeError`, `PrimeTooSmallError`,
`InvalidPublicExponentError`, `MessageOutOfRangeError`,
`TextTooLargeForModulusError`) rather than a generic `ValueError`, so
calling code — and the tests — can distinguish *why* an input was
rejected. Each such error case has a corresponding negative test in
`tests/`.

### 4.5 A second implementation of d: the virtual lab uses φ(n), not λ(n)

The virtual laboratory (Section 5) computes the private exponent `d` as the
inverse of `e` modulo `φ(n) = (p-1)(q-1)`, not modulo `λ(n)` like
`rsa/keygen.py` does. This is a deliberate, independent choice for that
rewrite, not an inconsistency to be fixed: Section 2.5 already established
that both are mathematically valid private exponents, and the lab's brief
specifically calls for `φ(n)` (the more commonly taught quantity) throughout
its step cards. The practical consequence is that, given the same `p`, `q`
and `e`, the lab and the Python package can compute two different values of
`d` for the same key — both correct, since both satisfy `e·d ≡ 1 (mod λ(n))`
(the `φ(n)`-based one satisfies it too, because `λ(n) | φ(n)`, Section 2.5).
[`tests/test_keygen.py`](../tests/test_keygen.py)'s
`test_lambda_and_phi_based_d_both_decrypt_the_same_ciphertext` proves this
directly on the known-answer key: it computes `d` both ways, checks each
against its own congruence, and confirms both independently decrypt one real
ciphertext back to the original message.

### 4.6 A deliberate deviation: Python 3.9 compatibility

The assignment brief specifies Python 3.10+. The machine this project was
built and tested on has only Python 3.9.6 installed, with no other
interpreter available (`py -0p` lists nothing else). Rather than write code
untestable on the available machine, every module was written to run
correctly on **3.9+** — avoiding syntax that only exists in 3.10+ (no
`match`/`case` statements, no bare `int | None` runtime type unions) — so
it still satisfies "stdlib only, no external packages" and runs unmodified
on 3.10+ where available. This is recorded as an explicit, considered
choice (see [`PLAN.md`](../PLAN.md)), not an oversight.

---

## 5. Virtual Laboratory Design

`RSA-Virtual-Lab/` is a three-file, self-contained web page — `index.html`,
`style.css`, `script.js`, no external scripts, no CDN links, no build step
— that opens directly by double-clicking `index.html` and works with no
network connection. Like the assignment's other JavaScript deliverables, it
reimplements RSA independently rather than calling into the Python package,
since a browser cannot run Python; unlike the version described in an
earlier draft of this report, it deliberately favours plain, explicit code
a second-year student can read line by line over compactness, and it uses
`φ(n)` throughout (Section 4.5) rather than `λ(n)`.

### 5.1 Layout

A header band states what RSA is in two or three sentences, followed by an
input panel (`p`, `q`, a message `M`, and an optional public exponent
override `e`), two flow diagrams built from plain HTML boxes and CSS arrow
characters (no images, no SVG) — one for key generation
(`p, q → n and φ(n) → choose e → calculate d → Public + Private Key`) and
one for the message path
(`Plaintext → Encrypt with Public Key → Ciphertext → Decrypt with Private
Key → Original Plaintext`) — and finally the numbered result cards that
appear once "Generate RSA" is clicked. A CSS media query switches the page
to a single column with full-width fields and a stacked, rotated-arrow flow
diagram below 640px, and widens the main content column above 1000px, so
the same page is usable on a phone or a projector.

### 5.2 The ten result cards

Clicking "Generate RSA" builds ten cards in order, each fading and sliding
in slightly after the last (a small CSS `animation-delay` per card, plus a
decorative progress bar), and highlights the matching box in whichever flow
diagram applies as it goes:

1. **Validate p and q** — confirms both are prime and different (real
   rejection happens earlier, as inline field errors, before any card is
   shown at all — see Section 5.3).
2. **n = p × q**, with the real numbers substituted directly under the
   symbolic formula.
3. **φ(n) = (p−1)(q−1)**, likewise.
4. **Choose e** — every candidate `e` tried (starting from 2, in order) is
   listed with its `gcd(e, φ(n))` and whether it was accepted, exactly
   mirroring how `findPublicExponent` in `script.js` works, so the table
   *is* the function's trace, not a separate explanation of it.
5. **Find d** — the extended Euclidean algorithm's working, as a small
   table of `(r, quotient, s)` rows from `modInverse`, ending in `d` and a
   visible check that `d × e mod φ(n) = 1`.
6. **Public Key**, in its own blue-bordered card.
7. **Private Key**, in its own purple-bordered card — a different colour
   from the public key card on purpose, so the two are never confused at a
   glance.
8. **Encrypt**: `C = M^e mod n`, symbolic and substituted.
9. **Decrypt**: `M = C^d mod n`, symbolic and substituted.
10. **Verification** — green "Verification Successful" if the decrypted
    value equals the original `M`, red failure text otherwise (this should
    never fire if the arithmetic above it is correct, but the check runs
    for real on every click rather than being assumed).

### 5.3 Validation and error handling

Every rejection — a non-prime or non-integer `p`/`q`, `p = q`, a `p`/`q`
pair small enough that `φ(n) < 3` (leaving no room for any valid `e` at
all), a non-integer or out-of-range `M`, `M ≥ n`, or an invalid custom `e`
— is shown as a message next to the specific field it concerns, and stops
generation before any result card is drawn. No `alert()` is used anywhere
on the page.

### 5.4 Why BigInt appears in exactly one function

`modPow` is the only function in `script.js` that uses JavaScript's
`BigInt` type; every other function (`isPrime`, `gcd`, `modInverse`,
`findPublicExponent`, and all of the validation and card-building code)
uses ordinary numbers, because the primes this lab is designed for stay
small enough that ordinary numbers represent them exactly. Modular
exponentiation is different: while squaring the base and reducing it
modulo `n` at every step of `modPow`'s square-and-multiply loop keeps the
final answer small, the intermediate values before each reduction can
exceed what an ordinary JavaScript number can hold exactly (`2^53`), and
`Math.pow` computes in floating point regardless, which would silently
round rather than error. `modPow` converts its arguments to `BigInt` at the
very start and converts its answer back to an ordinary number at the very
end, so this is invisible to every other function that calls it —
consistent with the general JavaScript rule that `BigInt` and ordinary
numbers can never appear in the same arithmetic expression.

---

## 6. Experimental Results

All figures below were produced by `tools/run_experiments.py` and saved to
`report/results/`; nothing in this section is estimated or invented.
`matplotlib` is not installed on the machine this was built on
(`report/results/matplotlib_status.txt`), so results are presented as
Markdown tables rather than plots, as the assignment brief's own fallback
instructs.

### 6.1 Test suite results

The full suite (`python -m unittest discover -s tests`) passes: **78
tests, 0 failures, 0 errors**. Raw output is saved at
[`report/results/test_output.txt`](results/test_output.txt); an excerpt:

```
test_bezout_identity_holds (test_mathutils.TestEgcd) ... ok
test_egcd_steps_every_row_satisfies_identity (test_mathutils.TestEgcd) ... ok
...
test_known_carmichael_number_is_not_prime (test_primes.TestIsPrimeMillerRabin) ... ok
...
----------------------------------------------------------------------
Ran 78 tests in 0.355s

OK
```

Per-module breakdown (from [`report/results/test_summary.md`](results/test_summary.md)):

| test module | passed | failed | errored |
|---|---|---|---|
| test_attack | 6 | 0 | 0 |
| test_cipher | 14 | 0 | 0 |
| test_keygen | 20 | 0 | 0 |
| test_mathutils | 23 | 0 | 0 |
| test_primes | 15 | 0 | 0 |

### 6.2 Sample generated keypairs

Three keypairs generated from increasingly wide prime ranges (seeded,
[`report/results/sample_keypairs.md`](results/sample_keypairs.md)):

| prime range | p | q | n | φ(n) | λ(n) | e | d |
|---|---|---|---|---|---|---|---|
| [100, 999] | 421 | 863 | 363323 | 362040 | 181020 | 65537 | 53513 |
| [1000, 9999] | 6577 | 7043 | 46321811 | 46308192 | 23154096 | 65537 | 16543889 |
| [10000, 99999] | 86771 | 76369 | 6626614499 | 6626451360 | 3313225680 | 65537 | 1650975953 |

`e = 65537` (the real-world default) was valid in every case here, since
`λ(n)` was always larger than 65537 at these sizes.

### 6.3 Key-generation time vs. prime bit length

Mean of 15 trials per size ([`report/results/keygen_time_vs_bitlength.md`](results/keygen_time_vs_bitlength.md)):

| prime bit length | trials | mean keygen time (ms) | min (ms) | max (ms) |
|---|---|---|---|---|
| 8 | 15 | 0.2164 | 0.1170 | 0.5187 |
| 12 | 15 | 0.2101 | 0.1616 | 0.3194 |
| 16 | 15 | 0.2387 | 0.1813 | 0.3184 |
| 20 | 15 | 0.3267 | 0.2367 | 0.6495 |
| 24 | 15 | 0.3289 | 0.2674 | 0.4589 |
| 28 | 15 | 0.3687 | 0.3149 | 0.4741 |
| 32 | 15 | 0.6788 | 0.5058 | 1.1382 |

Key generation stays well under a millisecond across the entire range
tested (8-bit to 32-bit primes) and grows only mildly with size — Miller–
Rabin's cost per candidate scales gently with bit length at this scale, and
candidate primes are dense enough (by the prime number theorem, roughly 1
in `ln(2^b)` numbers near `2^b` is prime) that few candidates need testing
before one succeeds.

### 6.4 Factoring time vs. modulus bit length

Trial division (`rsa.attack.factor_n`) against `n = p·q` for matched prime
bit lengths, one trial per size
([`report/results/factoring_time_vs_bitlength.md`](results/factoring_time_vs_bitlength.md)):

| prime bit length (each) | n bit length | n | trial-division attempts | time (ms) |
|---|---|---|---|---|
| 8 | 15 | 30967 | 87 | 0.006 |
| 10 | 20 | 778997 | 385 | 0.026 |
| 12 | 24 | 9714427 | 1336 | 0.093 |
| 14 | 27 | 109234787 | 4776 | 0.329 |
| 16 | 31 | 1489717261 | 18066 | 1.590 |
| 18 | 35 | 29366434777 | 79927 | 6.972 |
| 20 | 40 | 667874851019 | 372997 | 36.535 |
| 22 | 44 | 14811803940337 | 1916934 | 184.769 |
| 24 | 48 | 241650776912617 | 7628034 | 718.653 |

This is the assignment's central empirical result. Attempt count — and
elapsed time with it — roughly **quadruples for every 2 extra bits added to
each prime** (average ratio across the eight steps above is ≈4.2×), exactly
as expected: trial division's cost is `O(√n)`, and `√n` doubles for every
one extra bit in each prime, hence quadruples for every two. Extrapolating
this trend (not measured directly — 1024-bit primes are entirely out of
reach of trial division) makes the point vividly: going from the 24-bit
primes above to the 1024-bit primes real RSA uses is over 1000 bits of
further growth, i.e. roughly `4^500` times more work — a number vastly
larger than the count of atoms in the observable universe. This is why
factoring a real RSA modulus by trial division is not merely "slow", but
meaningfully impossible.

### 6.5 Plain vs. CRT decryption timing

Mean per-operation time over 2000 repetitions
([`report/results/decrypt_plain_vs_crt.md`](results/decrypt_plain_vs_crt.md)):

| prime bit length (each) | n bit length | reps | plain decrypt (µs/op) | CRT decrypt (µs/op) | speedup |
|---|---|---|---|---|---|
| 16 | 31 | 2000 | 6.239 | 6.120 | 1.02x |
| 24 | 47 | 2000 | 8.994 | 8.060 | 1.12x |
| 32 | 64 | 2000 | 11.069 | 13.960 | 0.79x |

**This does not show the textbook ~4x CRT speedup** — at 32-bit primes, CRT
decryption measured *slower* than plain decryption. This is a genuine,
reproducible result at this scale, not noise to be smoothed over, and it
has a straightforward explanation: CRT's theoretical advantage comes from
schoolbook multiplication cost scaling worse than linearly with operand
size (multiplying two `k`-bit numbers costs `O(k²)` by the schoolbook
method), so doing two exponentiations on `k/2`-bit numbers instead of one
on `k`-bit numbers is a real asymptotic win — but only once `k` is large
enough for that quadratic cost to dominate. At the 16–64-bit operand sizes
used here, Python's arbitrary-precision integers are already only one or
two machine words internally, so multiplication cost is close to constant
regardless of whether the operand is 16 or 64 bits; what actually dominates
the measured time is the fixed per-call overhead of the CPython interpreter
and this project's own Python-level `mod_exp` loop — and `decrypt_crt` does
*more* of that fixed-overhead work (two full `mod_exp` calls plus the
Garner-formula combination step, instead of one). CRT's real-world benefit
only appears once keys reach cryptographic size (512-bit primes and up),
which is outside this assignment's deliberately small-prime scope; Section
8 notes this as a natural extension.

---

## 7. Discussion

### 7.1 Why small primes are insecure

Section 6.4 demonstrates this directly rather than merely asserting it:
this project's own `factor_n` breaks a 48-bit RSA modulus by brute-force
trial division in well under a second, and recovers the exact private
exponent `d` used to generate it (`tests/test_attack.py` confirms the
recovered key decrypts real ciphertext correctly). RSA's entire security
argument is that factoring `n` is hard; with small primes it demonstrably
is not.

### 7.2 Other textbook-RSA weaknesses

The implementation in this project is deliberately "textbook RSA" — no
padding scheme — which has several weaknesses independent of key size:

- **Deterministic encryption and malleability.** `encrypt(m, pub)` always
  produces the same ciphertext for the same `m`, so an eavesdropper who
  sees the same ciphertext twice learns the plaintexts repeated, even
  without decrypting either. Worse, RSA is multiplicatively homomorphic:
  `encrypt(m1) * encrypt(m2) mod n == encrypt(m1 * m2 mod n)`. An attacker
  who intercepts `c = encrypt(m, pub)` can compute `c' = c * encrypt(k, pub)
  mod n` for a chosen `k`, and `c'` will decrypt to `m*k mod n` — a
  meaningful, attacker-controlled modification of the plaintext made
  without ever knowing `m`. This is exactly what padding schemes such as
  OAEP are designed to prevent, by randomising each encryption and binding
  structure into the padded message that a naive multiplicative
  manipulation destroys.
- **Håstad's broadcast attack (small e).** If the same message `m` is
  encrypted with a small public exponent (classically `e=3`) under three
  different moduli `n1, n2, n3` for three different recipients, an attacker
  who intercepts all three ciphertexts can use the CRT to reconstruct
  `m^3` as an ordinary integer (since `m^3 < n1*n2*n3`), then recover `m`
  by an integer cube root — without factoring any modulus.
- **Wiener's small-`d` attack.** If the private exponent `d` is chosen too
  small (roughly `d < n^0.25`), continued-fraction expansion of the public
  `e/n` efficiently recovers `d` in polynomial time. This project's default
  exponent search prefers *large* `e` (65537 first), which correspondingly
  tends to produce a large, safe `d` — but nothing in the implementation
  prevents a caller from supplying a tiny custom `e` (and hence a `d`
  vulnerable to exactly this attack).
- **Common modulus attack.** If the same `n` is reused for two users with
  different, coprime public exponents `e1` and `e2`, and the same message
  `m` is ever encrypted to both, an attacker holding both ciphertexts can
  recover `m` directly via the extended Euclidean algorithm on `(e1, e2)` —
  again without factoring `n` or knowing either private key.

### 7.3 What real implementations do differently

- **OAEP padding** (RSAES-OAEP, part of PKCS#1 v2.x): randomises every
  encryption and adds structural redundancy, closing the deterministic-
  encryption and malleability gaps in Section 7.2.
- **2048-bit or larger keys.** NIST SP 800-57 / FIPS 186-5 [4] treat
  2048-bit RSA as the current minimum for new deployments, with 3072-bit
  recommended for longer-term security — chosen specifically so that the
  best known factoring algorithms (the General Number Field Sieve, not
  trial division) remain infeasible for decades, per Section 6.4's
  extrapolation.
- **Standards-compliant prime generation.** FIPS 186-5's prime-generation
  procedures use many more Miller–Rabin rounds calibrated to key size,
  require a cryptographically secure random source (`secrets`/`os.urandom`
  in Python, not the `random` module this project's lab and experiment
  scripts use for convenience), and impose structural checks (e.g. a
  minimum distance `|p - q|`) absent from this project's simpler
  `random_prime`.

---

## 8. Limitations and Future Work

- **Trial division only.** `factor_n` is deliberately the simplest possible
  factoring algorithm; real-world factoring research uses far more
  sophisticated methods (Pollard's rho, the quadratic sieve, the general
  number field sieve) that factor numbers many times larger than trial
  division can reach in the same time — meaning even the extrapolation in
  Section 6.4 *understates* how much of an advantage an attacker with
  modern tools would have over "just trial division", not overstates it.
- **No padding scheme.** As discussed in Section 7.2, this is textbook
  RSA; adding OAEP would be a natural extension.
- **`random` module, not a CSPRNG.** Key generation here (and the
  experiment/lab code) uses Python's `random` module for reproducibility
  (seeded trials, deterministic tests) — real key generation must use a
  cryptographically secure random source.
- **CRT speedup not observed at this scale (Section 6.5).** A natural
  follow-up experiment is to rerun the plain-vs-CRT comparison at prime
  sizes large enough (several hundred bits) for the theoretical crossover
  to appear, to find the point at which CRT actually starts winning on
  this hardware.
- **Single-machine, single-run timings.** Section 6's timing figures (aside
  from the 15-trial keygen table) are each one run on one machine; a more
  rigorous study would repeat every measurement and report variance, not
  just the keygen table's min/mean/max.

---

## 9. Conclusion

This project implements every layer of textbook RSA — modular arithmetic,
primality testing, key generation, encryption/decryption (plain and CRT),
and a working factoring attack — from the Python standard library alone,
verified against the assignment's known-answer vector and a 78-test
automated suite, and made interactively explorable through an offline,
three-file web page that independently reproduces the same mathematics in
plain JavaScript. The experiments in Section 6 turn the assignment's central
claim — "small primes are insecure" — into a directly measured result
rather than an assertion: an attacker factors a 48-bit modulus in 719 ms
using nothing more sophisticated than trial division, with attempt counts
that quadruple every two bits, a trend whose extrapolation to real 1024-bit
RSA primes explains, in a single number, why the cryptosystem's security
depends entirely on key size.

---

## 10. References

1. Rivest, R. L., Shamir, A., and Adleman, L. (1978). "A Method for
   Obtaining Digital Signatures and Public-Key Cryptosystems."
   *Communications of the ACM*, 21(2), 120–126.
2. Katz, J., and Lindell, Y. *Introduction to Modern Cryptography.*
   Chapman and Hall/CRC.
3. Menezes, A. J., van Oorschot, P. C., and Vanstone, S. A. *Handbook of
   Applied Cryptography.* CRC Press.
4. National Institute of Standards and Technology. *FIPS 186-5: Digital
   Signature Standard (DSS).* U.S. Department of Commerce.
