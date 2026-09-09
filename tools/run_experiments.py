#!/usr/bin/env python3
"""Generate every number quoted in report.md section 6 from a real run.

Writes plain-text/Markdown tables (no plotting library is installed on the
machine this was built on, so no figures are produced -- see
report/results/matplotlib_status.txt) to report/results/:

  test_summary.md               - pass/fail counts per test module
  sample_keypairs.md            - a handful of generated key pairs
  keygen_time_vs_bitlength.md   - key-generation time vs. prime bit length
  factoring_time_vs_bitlength.md- trial-division factoring time vs. modulus bits
  decrypt_plain_vs_crt.md       - plain vs. CRT decryption timing
  experiments_raw.json          - all of the above, machine-readable

Run from the project root:  python tools/run_experiments.py
"""

import json
import os
import random
import re
import statistics
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from rsa.attack import factor_n  # noqa: E402
from rsa.cipher import decrypt, decrypt_crt, encrypt  # noqa: E402
from rsa.keygen import generate_keypair  # noqa: E402

RESULTS_DIR = os.path.join(ROOT, "report", "results")
FIGURES_DIR = os.path.join(ROOT, "report", "figures")


def write(name, text):
    path = os.path.join(RESULTS_DIR, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"wrote {os.path.relpath(path, ROOT)}")


# ---------------------------------------------------------------------------
# 1. Test summary, parsed from the raw unittest output saved earlier.
# ---------------------------------------------------------------------------
def experiment_test_summary():
    test_output_path = os.path.join(RESULTS_DIR, "test_output.txt")
    with open(test_output_path, encoding="utf-8") as f:
        lines = f.readlines()

    per_module = {}
    row_re = re.compile(r"^test_\S+ \((test_\w+)\.\w+\) \.\.\. (ok|FAIL|ERROR)$")
    for line in lines:
        m = row_re.match(line.strip())
        if not m:
            continue
        module, outcome = m.group(1), m.group(2)
        counts = per_module.setdefault(module, {"ok": 0, "FAIL": 0, "ERROR": 0})
        counts[outcome] += 1

    summary_line = next((l for l in lines if l.startswith("Ran ")), "").strip()
    final_status = "OK" if lines and lines[-1].strip() == "OK" else "SEE test_output.txt"

    md = ["| test module | passed | failed | errored |", "|---|---|---|---|"]
    for module in sorted(per_module):
        c = per_module[module]
        md.append(f"| {module} | {c['ok']} | {c['FAIL']} | {c['ERROR']} |")
    md.append("")
    md.append(f"`{summary_line}` -- final status: **{final_status}**")
    md.append("")
    md.append("Raw output: `report/results/test_output.txt`.")
    write("test_summary.md", "\n".join(md) + "\n")

    return {"per_module": per_module, "summary_line": summary_line, "final_status": final_status}


# ---------------------------------------------------------------------------
# 2. A handful of sample generated key pairs.
# ---------------------------------------------------------------------------
def experiment_sample_keypairs():
    rng = random.Random(2026)
    rows = []
    for low, high in [(100, 999), (1_000, 9_999), (10_000, 99_999)]:
        kp = generate_keypair(prime_low=low, prime_high=high, rng=rng)
        rows.append(
            {
                "prime_range": f"[{low}, {high}]",
                "p": kp.p,
                "q": kp.q,
                "n": kp.n,
                "phi": kp.phi,
                "lam": kp.lam,
                "e": kp.e,
                "d": kp.d,
            }
        )

    md = [
        "| prime range | p | q | n | phi(n) | lambda(n) | e | d |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        md.append(
            f"| {r['prime_range']} | {r['p']} | {r['q']} | {r['n']} | "
            f"{r['phi']} | {r['lam']} | {r['e']} | {r['d']} |"
        )
    write("sample_keypairs.md", "\n".join(md) + "\n")
    return rows


# ---------------------------------------------------------------------------
# 3. Key-generation time vs. prime bit length.
# ---------------------------------------------------------------------------
def experiment_keygen_time_vs_bitlength():
    bit_lengths = [8, 12, 16, 20, 24, 28, 32]
    trials_per_size = 15
    rng = random.Random(7)
    rows = []
    for bits in bit_lengths:
        low, high = 2 ** (bits - 1), 2 ** bits - 1
        times_ms = []
        for _ in range(trials_per_size):
            start = time.perf_counter()
            generate_keypair(prime_low=low, prime_high=high, rng=rng)
            times_ms.append((time.perf_counter() - start) * 1000)
        rows.append(
            {
                "prime_bits": bits,
                "trials": trials_per_size,
                "mean_ms": statistics.mean(times_ms),
                "min_ms": min(times_ms),
                "max_ms": max(times_ms),
            }
        )

    md = [
        "| prime bit length | trials | mean keygen time (ms) | min (ms) | max (ms) |",
        "|---|---|---|---|---|",
    ]
    for r in rows:
        md.append(
            f"| {r['prime_bits']} | {r['trials']} | {r['mean_ms']:.4f} | "
            f"{r['min_ms']:.4f} | {r['max_ms']:.4f} |"
        )
    write("keygen_time_vs_bitlength.md", "\n".join(md) + "\n")
    return rows


# ---------------------------------------------------------------------------
# 4. Trial-division factoring time vs. modulus bit length.
# ---------------------------------------------------------------------------
def experiment_factoring_time_vs_bitlength():
    # Both primes drawn from the same bit length, so n's bit length is
    # roughly double. Capped deliberately -- the whole point of this table
    # is to show trial division becoming impractical, and it does so fast:
    # each extra prime bit roughly doubles the attempt count.
    prime_bit_lengths = [8, 10, 12, 14, 16, 18, 20, 22, 24]
    rng = random.Random(99)
    rows = []
    for bits in prime_bit_lengths:
        low, high = 2 ** (bits - 1), 2 ** bits - 1
        kp = generate_keypair(prime_low=low, prime_high=high, rng=rng)
        p, q, attempts, elapsed_ms = factor_n(kp.n)
        rows.append(
            {
                "prime_bits": bits,
                "n_bits": kp.n.bit_length(),
                "n": kp.n,
                "attempts": attempts,
                "elapsed_ms": elapsed_ms,
            }
        )

    md = [
        "| prime bit length (each) | n bit length | n | trial-division attempts | time (ms) |",
        "|---|---|---|---|---|",
    ]
    for r in rows:
        md.append(
            f"| {r['prime_bits']} | {r['n_bits']} | {r['n']} | "
            f"{r['attempts']} | {r['elapsed_ms']:.3f} |"
        )
    write("factoring_time_vs_bitlength.md", "\n".join(md) + "\n")
    return rows


# ---------------------------------------------------------------------------
# 5. Plain vs. CRT decryption timing.
# ---------------------------------------------------------------------------
def experiment_decrypt_plain_vs_crt():
    prime_bit_lengths = [16, 24, 32]
    reps = 2000
    rng = random.Random(555)
    rows = []
    for bits in prime_bit_lengths:
        low, high = 2 ** (bits - 1), 2 ** bits - 1
        kp = generate_keypair(prime_low=low, prime_high=high, rng=rng)
        m = rng.randint(0, kp.n - 1)
        c = encrypt(m, kp.public)
        assert decrypt(c, kp.private) == m
        assert decrypt_crt(c, kp.private) == m

        start = time.perf_counter()
        for _ in range(reps):
            decrypt(c, kp.private)
        plain_ms = (time.perf_counter() - start) * 1000 / reps

        start = time.perf_counter()
        for _ in range(reps):
            decrypt_crt(c, kp.private)
        crt_ms = (time.perf_counter() - start) * 1000 / reps

        rows.append(
            {
                "prime_bits": bits,
                "n_bits": kp.n.bit_length(),
                "reps": reps,
                "plain_us": plain_ms * 1000,
                "crt_us": crt_ms * 1000,
                "speedup": plain_ms / crt_ms if crt_ms > 0 else float("inf"),
            }
        )

    md = [
        "| prime bit length (each) | n bit length | reps | plain decrypt (us/op) | CRT decrypt (us/op) | speedup |",
        "|---|---|---|---|---|---|",
    ]
    for r in rows:
        md.append(
            f"| {r['prime_bits']} | {r['n_bits']} | {r['reps']} | "
            f"{r['plain_us']:.3f} | {r['crt_us']:.3f} | {r['speedup']:.2f}x |"
        )
    write("decrypt_plain_vs_crt.md", "\n".join(md) + "\n")
    return rows


def main():
    os.makedirs(RESULTS_DIR, exist_ok=True)
    os.makedirs(FIGURES_DIR, exist_ok=True)

    try:
        import matplotlib  # noqa: F401

        matplotlib_available = True
    except ImportError:
        matplotlib_available = False

    write(
        "matplotlib_status.txt",
        "matplotlib available: {}\n".format(matplotlib_available)
        + (
            ""
            if matplotlib_available
            else "matplotlib is not installed on this machine; report/figures/ is "
            "intentionally empty and report.md presents this data as Markdown "
            "tables instead of plots, as instructed.\n"
        ),
    )

    results = {}
    results["test_summary"] = experiment_test_summary()
    results["sample_keypairs"] = experiment_sample_keypairs()
    results["keygen_time_vs_bitlength"] = experiment_keygen_time_vs_bitlength()
    results["factoring_time_vs_bitlength"] = experiment_factoring_time_vs_bitlength()
    results["decrypt_plain_vs_crt"] = experiment_decrypt_plain_vs_crt()
    results["matplotlib_available"] = matplotlib_available

    write("experiments_raw.json", json.dumps(results, indent=2))
    print("\nAll experiments complete.")


if __name__ == "__main__":
    main()
