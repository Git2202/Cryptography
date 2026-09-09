# RSA Key Generation with Small Primes

A college cryptography assignment: a from-scratch, standard-library-only
Python implementation of textbook RSA, an offline interactive virtual
laboratory, and a technical report — built around deliberately small primes
so that both a real factoring attack and a full visual walkthrough of every
algorithm step are feasible in a classroom setting.

See [PLAN.md](PLAN.md) for the working plan, assumptions, and the exact
order this project was built in, and [report/report.md](report/report.md)
for the full write-up (mathematical background, algorithms, design
decisions, and experimental results).

## What's here

```
rsa/                  the implementation (Python 3.9+, standard library only)
  __init__.py           shared exception hierarchy
  mathutils.py          gcd, lcm, egcd (+egcd_steps), modinv, mod_exp (+mod_exp_steps)
  primes.py             sieve_of_eratosthenes, is_prime_trial, is_prime_miller_rabin, random_prime
  keygen.py             totient, carmichael_lambda, KeyPair/PublicKey/PrivateKey, generate_keypair
  cipher.py             encrypt, decrypt, decrypt_crt, text_to_blocks, blocks_to_text
  attack.py             factor_n, recover_d
cli.py                 command-line demo over the whole package
tests/                 unittest suite, one module per rsa/ module (77 tests)
tools/
  run_experiments.py    regenerates every number quoted in report/report.md §6
virtual-lab/
  index.html             self-contained offline RSA lab (open by double-click)
  NOTES.md               maps every lab JS function to its Python counterpart
report/
  report.md              the technical report (10 sections)
  results/                raw test/experiment output the report quotes
  figures/                (empty — no matplotlib on the build machine; see report §6)
PLAN.md                 working plan, assumptions, and step order
```

## Requirements

**Python 3.9+ or 3.10+, standard library only** — no `pip install` needed
anywhere in `rsa/`, `tests/`, `cli.py`, or `tools/run_experiments.py`. (The
assignment brief targets 3.10+; this project was built and tested on 3.9.6,
the only interpreter available on the build machine, using only syntax that
also runs unmodified on 3.10+ — see PLAN.md and report.md §4.5 for why.)

`virtual-lab/index.html` needs nothing but a modern browser (it uses
`BigInt`, supported by every current browser) — no Python, no server, no
internet connection.

## Running the tests

From the project root, on a machine with no packages installed beyond
Python itself:

```bash
python -m unittest discover -s tests -v
```

Expect `Ran 77 tests ... OK`. Raw output from the last full run is saved at
[report/results/test_output.txt](report/results/test_output.txt).

## CLI usage

```bash
# A fixed, fully-printed walkthrough of the assignment's known-answer vector
python cli.py demo

# Generate a key pair from chosen primes
python cli.py keygen --p 61 --q 53 --e 17

# Generate one from random primes in a range, with a seed for reproducibility
python cli.py keygen --random --low 100 --high 9999 --seed 42

# Encrypt / decrypt an integer message
python cli.py encrypt --e 17 --n 3233 --message 65
python cli.py decrypt --d 413 --n 3233 --cipher 2790

# Encrypt / decrypt short text (auto block-splits under the modulus)
python cli.py encrypt --e 17 --n 67591 --text "Hello, RSA!"
python cli.py decrypt --d 13809 --n 67591 --text-blocks "57452,23644,20604,28070,2703,17107"

# CRT decryption (needs p and q as well)
python cli.py decrypt --d 13809 --n 67591 --p 257 --q 263 --crt --cipher 57452

# Break a key using only its public parts
python cli.py attack --n 3233 --e 17 --cipher 2790
```

Run `python cli.py <subcommand> --help` for the full option list of any
subcommand.

## Opening the virtual laboratory

Double-click [virtual-lab/index.html](virtual-lab/index.html), or open it
via `File > Open` in any modern browser. No server, build step, or internet
connection is needed — everything, including the "Self-Test" panel, runs
entirely client-side. Start on panel 1 (pick two primes, or press "🎲
Random prime pair"), then step forward through key generation,
encryption/decryption, the attack panel, and finally the self-test.

## Regenerating the report data

```bash
python tools/run_experiments.py
```

This overwrites everything in `report/results/` with a fresh run (test
summary, sample keypairs, keygen-time-vs-bit-length, factoring-time-vs-
bit-length, and plain-vs-CRT decrypt timing) and prints what it wrote.
`report/report.md` §6 quotes these files directly. If `matplotlib` is
installed, add plotting there yourself and point `report/report.md` at the
resulting images — it isn't installed on the machine this project was
built on, so the report currently presents this data as Markdown tables
instead, as recorded in `report/results/matplotlib_status.txt`.

To also refresh `report/results/test_output.txt` before regenerating the
experiment data (the experiments script's test-summary table parses it):

```bash
python -m unittest discover -s tests -v > report/results/test_output.txt 2>&1
python tools/run_experiments.py
```

## Regenerating a PDF of the report

Neither `pandoc` nor `weasyprint` was available on the machine this project
was built on, so `report/report.md` is the deliverable as-is. If one
becomes available:

```bash
# pandoc converts Markdown to PDF directly
pandoc report/report.md -o report/report.pdf

# weasyprint only converts HTML to PDF, so a Markdown-to-HTML step (e.g. the
# third-party `markdown` package, or pandoc itself with -t html) is needed first:
pandoc report/report.md -o report/report.html
weasyprint report/report.html report/report.pdf
```
