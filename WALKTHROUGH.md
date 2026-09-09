# How this project works — a spoken walkthrough

This document is written to be said out loud, for a viva. Every fact in it
was checked against the actual files in this repository — `README.md`,
`PLAN.md`, `cli.py`, everything in `rsa/`, `virtual-lab/index.html`, and
`tools/run_experiments.py` — and the one number trace in Section 3 was
re-run through the real code (not hand-calculated) to make sure it's exact.

> **Note (later change):** Sections 5 and 6 below describe the *original*
> virtual lab, `virtual-lab/index.html` — a single file using `BigInt`
> everywhere, with five panels including an attack panel and a self-test
> panel. That lab was later replaced by a plainer, three-file rebuild aimed
> at second-year-student readability: `RSA-Virtual-Lab/index.html` +
> `style.css` + `script.js`, using `φ(n)` instead of `λ(n)`, `BigInt` only
> inside one function (`modPow`), and a ten-card Generate/Reset flow instead
> of five panels. Sections 1–4 (the Python side) are unaffected and still
> accurate. For the current lab, see
> [`RSA-Virtual-Lab/README.md`](RSA-Virtual-Lab/README.md) and
> [`report/report.md`](report/report.md) section 5 rather than Sections 5–6
> below.

---

## 1. What this project does, and why

This project is an implementation of RSA, a method for scrambling a message
so that only one specific person can unscramble it, even though the method
for scrambling it is public. RSA works by picking two secret prime numbers
(a prime number is a whole number greater than 1 with no divisors except 1
and itself), multiplying them together, and using that product — together
with some arithmetic built from the two primes — to build a "public key"
anyone can use to scramble a message, and a matching "private key" that
only unscrambles what that specific public key scrambled.

This project deliberately uses *small* primes — a few hundred to a few tens
of thousands, not the huge primes real RSA uses — for one reason: with
small primes, both the full arithmetic and a working attack that breaks the
key fit inside a classroom demonstration. There are four parts: the Python
implementation itself, an automated test suite that checks it, a browser-
based visual lab that lets you click through every step, and a written
report. All four are described below.

## 2. The end-to-end flow of RSA key generation, as this code does it

This is what happens, in order, when this code builds one RSA key. Each
step names the file and function that actually does it.

1. **Pick two different prime numbers, `p` and `q`.**
   File: `rsa/primes.py`, function `random_prime`. It picks a random number
   in a given range and checks whether it's prime using a test called
   Miller–Rabin (explained in Section 6, since the browser lab reimplements
   the same test). If the number isn't prime, it tries another, until it
   finds one. This gets called twice — once for `p`, once for `q` — from
   inside `rsa/keygen.py`'s `generate_keypair` function, and if the two
   turn out equal, it just tries again.

2. **Multiply them: `n = p × q`.**
   File: `rsa/keygen.py`, inside `generate_keypair`. `n` is called the
   "modulus" — it becomes part of the public key, and every later
   calculation "wraps around" at `n` (that's what "modulus" means: like a
   clock face wrapping around at 12, arithmetic here wraps around at `n`).

3. **Compute `φ(n)` — read "phi of n", called Euler's totient.**
   File: `rsa/keygen.py`, function `totient`. It's just
   `(p - 1) × (q - 1)`. In plain English, `φ(n)` counts how many whole
   numbers below `n` share no common factor with `n`. This project computes
   it mainly so it can be compared side by side with the next step.

4. **Compute `λ(n)` — read "lambda of n", called the Carmichael function.**
   File: `rsa/keygen.py`, function `carmichael_lambda`. It's the smallest
   common multiple of `(p - 1)` and `(q - 1)` — "smallest common multiple"
   (lcm) meaning the smallest number both `(p-1)` and `(q-1)` divide into
   evenly. This calls `lcm`, which itself calls `gcd` ("greatest common
   divisor" — the biggest number that divides evenly into both of two
   given numbers), both in `rsa/mathutils.py`. `λ(n)` is what this project
   actually uses in the next two steps, instead of `φ(n)` — both work
   mathematically, but `λ(n)` is the smaller, tighter choice. The report
   (`report/report.md`, section 2.5) explains why textbooks usually teach
   `φ(n)` anyway even though `λ(n)` is the "better" one.

5. **Choose the public exponent `e`.**
   File: `rsa/keygen.py`, function `_choose_e`. `e` has to be a number
   strictly between 1 and `λ(n)` that shares no common factor with `λ(n)`
   (mathematicians call that "coprime" — `gcd(e, λ(n)) == 1`). This
   function tries a short list of standard choices in order — 65537, then
   257, then 17, then 5, then 3 — and picks the first one that fits; if
   none of those work it falls back to trying every odd number upward.

6. **Compute the private exponent `d`.**
   File: `rsa/mathutils.py`, function `modinv` (short for "modular
   inverse"). `d` is the number such that `(e × d)` leaves a remainder of
   exactly 1 when divided by `λ(n)`. Finding it uses another function in
   the same file, `egcd` ("extended Euclidean algorithm" — Section 3 shows
   it running on real numbers), which is really just a structured way of
   running long division backwards.

7. **Package the results into a public key and a private key.**
   File: `rsa/keygen.py`. The public key is the pair `(e, n)` — safe to
   share with anyone. The private key is `(d, n)` — must be kept secret.
   Both are just small Python objects (`PublicKey` and `PrivateKey`) that
   hold these numbers together, plus `p` and `q` on the private key, which
   are needed for one specific speed-up (Section 3 explains where).

## 3. Tracing one concrete run: `p=61, q=53, message=65`

This is exactly what `python cli.py demo` runs. Every number below was
produced by actually running this project's code — not worked out by hand —
so it can be trusted and repeated exactly.

**Step A — generate the key.**
`cli.py`'s `cmd_demo` function calls `generate_keypair(p=61, q=53, e=17)`
in `rsa/keygen.py`. Walking through what that function does:

- `n = 61 × 53 = 3233`
- `φ(n) = 60 × 52 = 3120`
- `λ(n) = lcm(60, 52)`. `lcm` calls `gcd(60, 52)`, which works out to `4`.
  So `λ(n) = (60 ÷ 4) × 52 = 780`.
- `e = 17` was given directly, so it's just checked: is `17` strictly
  between `1` and `780`? Yes. Does `gcd(17, 780) = 1`? Yes. Accepted.
- `d` comes from `modinv(17, 780)`, which runs `egcd(17, 780)`. This is
  the part worth saying carefully, because the very first row looks
  backwards: since `17` is smaller than `780`, the algorithm's first
  "division" step does nothing useful (it divides `17` by `780` and gets
  `0` remainder `17`), so the *second* row is where the numbers actually
  swap into the order you'd expect. Six rows are produced in total; the
  final one says `1 = 17×(-367) + 780×8` — meaning `-367` is `17`'s
  inverse, before wrapping it into the range `[0, 780)`. Wrapped, that's
  `-367 + 780 = 413`.
- So: **public key = (e=17, n=3233), private key = (d=413, n=3233).**

**Step B — encrypt the message.**
`encrypt(65, public_key)` in `rsa/cipher.py` checks `0 ≤ 65 < 3233` (yes),
then calls `mod_exp(65, 17, 3233)` in `rsa/mathutils.py`. This is
"square-and-multiply": `17` in binary is `10001` (5 digits), and the
function processes those digits left to right, squaring the running result
every time and, additionally, multiplying in the base whenever the digit is
`1`:

| binary digit | before | after squaring | multiply by base? | result |
|---|---|---|---|---|
| 1 | 1 | 1 | yes | 65 |
| 0 | 65 | 992 | no | 992 |
| 0 | 992 | 1232 | no | 1232 |
| 0 | 1232 | 1547 | no | 1547 |
| 1 | 1547 | 789 | yes | **2790** |

**So `c = 2790`.**

**Step C — decrypt it back.**
`decrypt(2790, private_key)` calls `mod_exp(2790, 413, 3233)`. `413` in
binary is `110011101` — 9 digits, so 9 rows this time, same mechanism as
above (this project ran it rather than hand-computing it, to avoid a
transcription mistake in a 9-row table): the running result goes
`2790 → 296 → 325 → 2169 → 597 → 834 → 2689 → 1733 → 65`. **The last value
is `65` — the original message, recovered.**

**Step D — decrypt it a second way, with CRT.**
`decrypt_crt(2790, private_key)`, also in `rsa/cipher.py`, is a shortcut
that uses `p` and `q` directly instead of the full `n`. It computes
`dp = 413 mod 60 = 53`, `dq = 413 mod 52 = 49`, and `qinv` (the inverse of
`53` modulo `61`) `= 38`. Then `m1 = 2790^53 mod 61 = 4` and
`m2 = 2790^49 mod 53 = 12`. The last combining step —
`h = (38 × (4 − 12)) mod 61 = 1`, then `m = 12 + 1×53 = 65` — is honestly
the hardest single line in this whole project to justify out loud without
writing out the underlying theorem (the Chinese Remainder Theorem); the
full proof of why it works is in `report/report.md` section 2.6, and this
walkthrough won't pretend it's obvious.

**Step E — break the key from scratch, using only the public parts.**
`factor_n(3233)` in `rsa/attack.py` tries dividing `3233` by `2`, then
every odd number upward, until one divides evenly — it finds `53` after 27
attempts. `recover_d(53, 61, 17)` then rebuilds `λ(n)` from those factors
(same `780` as before) and calls `modinv(17, 780)` again, getting `413` —
**the exact same private exponent**, obtained without ever having had
access to it. Decrypting `2790` with this recovered key gives `65` again.

## 4. What happens when you run each entry point

- **`python cli.py <subcommand>`** — `cli.py` is a small command-line front
  end. It parses your `--flags` with Python's built-in `argparse`, then
  calls straight into the `rsa/` functions described above and prints the
  results. `python cli.py demo` runs exactly the trace in Section 3, start
  to finish, with everything printed. Other subcommands (`keygen`,
  `encrypt`, `decrypt`, `attack`) do one step each.

- **`python -m unittest discover -s tests`** — Python's built-in test
  runner looks inside `tests/`, finds every file starting with `test_`
  (one per module in `rsa/`), and runs every function inside them starting
  with `test_`. There are 77 such functions in total. Each one calls into
  `rsa/` and checks the result with `assertEqual` or similar — for example,
  `tests/test_keygen.py` builds the exact key from Section 3 and asserts
  `n == 3233`, `d == 413`, and so on. If everything matches, it prints `OK`.

- **`python tools/run_experiments.py`** — this script imports `rsa/`
  directly (like `cli.py` does) but instead of printing to the screen, it
  runs the key-generation, encryption, and attack functions many times at
  different sizes, times how long each takes, and writes the results as
  Markdown tables into `report/results/`. `report/report.md` section 6
  quotes those files directly — nothing in the report's numbers is typed
  in by hand.

- **Opening `virtual-lab/index.html`** — this just opens the file in
  whatever browser you double-click it with. There is no server and no
  installation step; the browser reads the HTML, CSS and JavaScript
  straight out of the one file and runs it. Section 6 below explains what
  happens next in detail.

## 5. How the four parts relate to each other

The project has four parts: the Python code in `rsa/` (the actual
implementation), the tests in `tests/` (proof it's correct), the browser
lab in `virtual-lab/` (a way to see it happen step by step), and the report
in `report/` (the write-up, with real measured numbers).

The tests depend on the Python code — they import it directly and check
its answers. The report depends on both — it quotes real output from the
tests and from `tools/run_experiments.py`, which also imports the Python
code directly. So those three are one connected chain, all running the
same `rsa/` code.

The browser lab is different, and this is worth being honest about: it
does **not** import or call the Python code at all. It is a second,
independent copy of the same mathematics, written from scratch in
JavaScript. This is a real design constraint, not an oversight — the
assignment requires the lab to be one self-contained HTML file that opens
by double-clicking and works with no internet connection, and a web
browser cannot run Python. So the maths had to be written twice: once in
`rsa/`, once in `<script>` inside `index.html`. `virtual-lab/NOTES.md`
lists every JavaScript function next to the Python function it's supposed
to match.

Having the same logic in two languages raises an obvious question: how do
you know they actually agree? That's what the **"Self-Test" panel** (panel
5 of the lab) is for. When you click "Run self-test", the JavaScript
builds the exact key from Section 3 — `p=61, q=53, e=17` — entirely inside
the browser, and checks that it gets `n=3233`, `d=413`, `encrypt(65)=2790`,
and `decrypt(2790)=65`, the same numbers this walkthrough already verified
against the real Python code. If those match, it's direct evidence that
the JavaScript reimplementation computes the same answers as the Python
implementation, on the one example both sides can be checked against by
hand. It then also runs a handful of random small keys and checks each one
decrypts back to the message that was encrypted, as a broader (if less
rigorous) check. It is *not* proof the two implementations agree on every
possible input — it's proof on this one worked example plus a few random
ones, which is the practical, honest thing a page like this can actually
demonstrate.

## 6. A slower walkthrough of the JavaScript in `index.html`

This section assumes you haven't written much JavaScript, so it goes
slower and explains more.

### What "self-contained" actually means here

Normally a web page loads its CSS (styling rules) and JavaScript (behaviour)
from separate files, or even from the internet. This page doesn't: the
`<style>` block and the `<script>` block are written directly inside the
one `index.html` file, between the HTML tags. When a browser opens the
file, it reads top to bottom and runs everything it finds — no separate
downloads, no server. That's what makes double-clicking it "just work"
offline.

### Why BigInt instead of ordinary numbers

JavaScript's ordinary numbers can represent whole numbers exactly only up
to about 9,007,199,254,740,991 (`2^53 - 1`). Above that, they can silently
round to the nearest number they *can* represent — which for cryptography
would be catastrophic, since a rounded modulus or exponent gives a
completely wrong, silently-wrong answer with no error message. `BigInt` is
a second, separate number type built into JavaScript specifically for
exact whole numbers of any size. You write a `BigInt` literal with a
lowercase `n` on the end — `65n`, `3233n`, `780n` — and all the normal
arithmetic symbols (`+ - * / % **`) work on them the same way, just never
rounding. Every RSA number in this file — `p`, `q`, `n`, `e`, `d`, the
message, the ciphertext — is a `BigInt`. Things that are just counting or
measuring (a loop counter, an array position, a timer reading in
milliseconds) stay as ordinary numbers, because there's no risk of them
overflowing and BigInt math is measurably slower.

### The main functions, and what they mirror

The `<script>` block is laid out in the same order as the Python package,
and says so in a comment at the top. The important functions:

- `gcd`, `lcm`, `egcd`, `egcdSteps`, `modInv`, `modExp`, `modExpSteps` —
  these do exactly what their same-named Python functions in
  `rsa/mathutils.py` do, just written with BigInt arithmetic and
  JavaScript syntax instead of Python's.
- `sieveOfEratosthenes`, `isPrimeTrial`, `isPrimeMillerRabin` — mirror
  `rsa/primes.py`.
- `totient`, `carmichaelLambda`, `chooseE`, `generateKeys` — mirror
  `rsa/keygen.py`'s `totient`, `carmichael_lambda`, `_choose_e`, and
  `generate_keypair`.
- `textToBlocks`, `blocksToText`, `encryptValue`, `decryptValue` — mirror
  `rsa/cipher.py`.
- `factorN`, `recoverD` — mirror `rsa/attack.py`.

One JavaScript-specific wrinkle worth flagging: inside `textToBlocks`,
turning bytes of text into one big number uses `value = (value << 8n) |
BigInt(byte)`. `<<` shifts all the bits of `value` left by 8 places (making
room), and `|` fills in the new empty bits with the next byte. If you
haven't done bitwise operations before, that line is genuinely doing two
things at once and is worth just stating plainly rather than working
through bit by bit in a viva — it's the standard trick for packing several
small numbers into one big one, byte by byte.

### A single global `state` object

The whole page keeps track of what's going on in one plain JavaScript
object called `state` — for example `state.selectedP`, `state.keys`,
`state.keygenStep`. There is no framework (no React, no Vue) — every time
something changes, a `render...` function clears out part of the page's
HTML and rebuilds it from the current `state`, by hand, using a small
helper function called `el()` that creates one HTML element at a time.

### What happens when you click through the panels

1. **Panel 1 (Prime Selection).** On page load, `rebuildSieve()` runs
   automatically, calls `sieveOfEratosthenes(200)`, and `renderSieveGrid()`
   draws one small box per number from 2 to 200. Every prime box gets a
   click handler that calls `selectPrime(thatNumber)`. Clicking a prime
   sets `state.selectedP`; clicking a second, different prime sets
   `state.selectedQ`. Clicking the *same* prime twice is caught by an
   `if` check inside `selectPrime` and shown as a red message box — never
   a browser `alert()` popup, since the assignment specifically asks for
   messages to stay inline on the page.

2. **Panel 2 (Key Generation).** Clicking its tab calls
   `renderKeygenPanel()`, which — if it hasn't already — calls
   `generateKeys(selectedP, selectedQ)` once and stores the result in
   `state.keys`. The panel then shows one "card" at a time out of six
   (`renderKeygenCard()`, driven by `state.keygenStep`), matching the seven
   steps in Section 2 above (step 1 of Section 2, picking the primes, has
   already happened in panel 1). The "Next ▶" and "◀ Back" buttons just
   change `state.keygenStep` by one and re-run `renderKeygenCard()`.

3. **Panel 3 (Encrypt / Decrypt).** Clicking "Encrypt" reads whatever is in
   the text box, calls `encryptValue()`, and calls `renderModExpTable()` to
   draw the same kind of row-by-row table shown in Section 3, Step B above
   — one row per binary digit of `e`. Clicking "Decrypt" does the mirror
   image with `decryptValue()` and `d`.

4. **Panel 4 (Attack).** "Break this key" calls `factorN()` on the current
   `n`, then `recoverD()`, then decrypts the last ciphertext with the
   *recovered* key rather than the real one, and says so on screen. This
   is the JavaScript equivalent of Step E in Section 3.

5. **Panel 5 (Self-Test).** The "Run self-test" button calls
   `runSelfTest()`, which is the function described at the end of Section
   5 above: it builds the known key, checks every number against the fixed
   values worked out in Section 3, then does a handful of random ones, and
   prints a table of pass/fail rows.

Every one of those five steps is a normal `addEventListener("click", ...)`
call near the bottom of the script — nothing more exotic than "when this
button is clicked, run this function."
