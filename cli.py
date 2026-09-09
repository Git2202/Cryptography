#!/usr/bin/env python3
"""Command-line demo for the rsa package.

Examples:
    python cli.py keygen --p 61 --q 53 --e 17
    python cli.py keygen --random --low 100 --high 9999 --seed 42
    python cli.py encrypt --e 17 --n 3233 --message 65
    python cli.py encrypt --e 17 --n 3233 --text "HI"
    python cli.py decrypt --d 413 --n 3233 --cipher 2790
    python cli.py decrypt --d 413 --n 3233 --p 61 --q 53 --cipher 2790 --crt
    python cli.py attack --n 3233 --e 17 --cipher 2790
    python cli.py demo
"""

import argparse
import json
import random
import sys

from rsa import RSAError
from rsa.attack import factor_n, recover_d
from rsa.cipher import blocks_to_text, decrypt, decrypt_crt, encrypt, text_to_blocks
from rsa.keygen import PrivateKey, PublicKey, generate_keypair


def cmd_keygen(args):
    if args.random:
        rng = random.Random(args.seed) if args.seed is not None else None
        kp = generate_keypair(prime_low=args.low, prime_high=args.high, e=args.e, rng=rng)
    else:
        if args.p is None or args.q is None:
            raise SystemExit("keygen: either pass --p and --q, or pass --random")
        kp = generate_keypair(p=args.p, q=args.q, e=args.e)

    print(f"p          = {kp.p}")
    print(f"q          = {kp.q}")
    print(f"n = p*q    = {kp.n}")
    print(f"phi(n)     = {kp.phi}")
    print(f"lambda(n)  = {kp.lam}")
    print(f"e          = {kp.e}")
    print(f"d          = {kp.d}")
    print(f"public key  (e, n) = ({kp.e}, {kp.n})")
    print(f"private key (d, n) = ({kp.d}, {kp.n})")
    if args.trace:
        print(json.dumps(kp.trace, indent=2))


def cmd_encrypt(args):
    pub = PublicKey(e=args.e, n=args.n)
    if args.text is not None:
        blocks = text_to_blocks(args.text, args.n)
        cipher_blocks = [encrypt(block, pub) for block in blocks]
        print(f"plaintext blocks = {blocks}")
        print(f"cipher blocks    = {cipher_blocks}")
    else:
        c = encrypt(args.message, pub)
        print(f"c = {c}")


def cmd_decrypt(args):
    if args.crt and (args.p is None or args.q is None):
        raise SystemExit("decrypt --crt requires --p and --q")

    priv = PrivateKey(d=args.d, n=args.n, p=args.p or 0, q=args.q or 0)

    if args.text_blocks is not None:
        cipher_blocks = [int(x) for x in args.text_blocks.split(",")]
        decrypt_fn = decrypt_crt if args.crt else decrypt
        plain_blocks = [decrypt_fn(c, priv) for c in cipher_blocks]
        print(f"plaintext blocks = {plain_blocks}")
        print(f"text             = {blocks_to_text(plain_blocks, args.n)!r}")
    else:
        m = decrypt_crt(args.cipher, priv) if args.crt else decrypt(args.cipher, priv)
        print(f"m = {m}")


def cmd_attack(args):
    p, q, attempts, elapsed_ms = factor_n(args.n)
    d = recover_d(p, q, args.e)
    print(f"factored n = {args.n} -> p = {p}, q = {q}")
    print(f"attempts = {attempts}, elapsed = {elapsed_ms:.3f} ms")
    print(f"recovered d = {d}")
    if args.cipher is not None:
        priv = PrivateKey(d=d, n=args.n, p=p, q=q)
        m = decrypt(args.cipher, priv)
        print(f"decrypted c = {args.cipher} -> m = {m} (private key never used)")


def cmd_demo(_args):
    """A fixed, fully-printed walkthrough using the assignment's KAT vector."""
    print("=== RSA demo: p=61, q=53, e=17 (the assignment's known-answer vector) ===\n")
    kp = generate_keypair(p=61, q=53, e=17)
    print(f"n = p*q = {kp.p}*{kp.q} = {kp.n}")
    print(f"phi(n) = {kp.phi}, lambda(n) = {kp.lam}")
    print(f"public key  = (e={kp.e}, n={kp.n})")
    print(f"private key = (d={kp.d}, n={kp.n})\n")

    m = 65
    c = encrypt(m, kp.public)
    print(f"encrypt(m={m}) -> c = {c}")
    print(f"decrypt(c={c}) -> m = {decrypt(c, kp.private)}")
    print(f"decrypt_crt(c={c}) -> m = {decrypt_crt(c, kp.private)}\n")

    print("=== Attack: recover the private key from (e, n) alone ===")
    p, q, attempts, elapsed_ms = factor_n(kp.n)
    recovered_d = recover_d(p, q, kp.e)
    print(f"factor_n({kp.n}) -> p={p}, q={q} ({attempts} attempts, {elapsed_ms:.3f} ms)")
    print(f"recovered d = {recovered_d} (matches real d: {recovered_d == kp.d})")
    recovered_priv = PrivateKey(d=recovered_d, n=kp.n, p=p, q=q)
    print(f"decrypt(c={c}) with recovered key -> m = {decrypt(c, recovered_priv)}")


def build_parser():
    parser = argparse.ArgumentParser(description="Command-line demo for the rsa package.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_keygen = sub.add_parser("keygen", help="generate an RSA key pair")
    p_keygen.add_argument("--p", type=int, default=None)
    p_keygen.add_argument("--q", type=int, default=None)
    p_keygen.add_argument("--e", type=int, default=None, help="public exponent (auto-chosen if omitted)")
    p_keygen.add_argument("--random", action="store_true", help="draw p, q randomly instead of --p/--q")
    p_keygen.add_argument("--low", type=int, default=100, help="lower bound for random primes")
    p_keygen.add_argument("--high", type=int, default=9999, help="upper bound for random primes")
    p_keygen.add_argument("--seed", type=int, default=None, help="seed the RNG for reproducible output")
    p_keygen.add_argument("--trace", action="store_true", help="also print the full JSON trace")
    p_keygen.set_defaults(func=cmd_keygen)

    p_encrypt = sub.add_parser("encrypt", help="encrypt a message with a public key")
    p_encrypt.add_argument("--e", type=int, required=True)
    p_encrypt.add_argument("--n", type=int, required=True)
    group = p_encrypt.add_mutually_exclusive_group(required=True)
    group.add_argument("--message", type=int, help="an integer message, 0 <= m < n")
    group.add_argument("--text", type=str, help="a short text message to block-encode and encrypt")
    p_encrypt.set_defaults(func=cmd_encrypt)

    p_decrypt = sub.add_parser("decrypt", help="decrypt a ciphertext with a private key")
    p_decrypt.add_argument("--d", type=int, required=True)
    p_decrypt.add_argument("--n", type=int, required=True)
    p_decrypt.add_argument("--p", type=int, default=None, help="prime factor p (required for --crt)")
    p_decrypt.add_argument("--q", type=int, default=None, help="prime factor q (required for --crt)")
    p_decrypt.add_argument("--crt", action="store_true", help="use CRT decryption instead of plain")
    dgroup = p_decrypt.add_mutually_exclusive_group(required=True)
    dgroup.add_argument("--cipher", type=int, help="a single ciphertext integer")
    dgroup.add_argument(
        "--text-blocks",
        dest="text_blocks",
        type=str,
        help="comma-separated cipher blocks produced by 'encrypt --text', decoded back to text",
    )
    p_decrypt.set_defaults(func=cmd_decrypt)

    p_attack = sub.add_parser("attack", help="break a key using only its public parts")
    p_attack.add_argument("--n", type=int, required=True)
    p_attack.add_argument("--e", type=int, required=True)
    p_attack.add_argument("--cipher", type=int, default=None, help="optionally decrypt this ciphertext too")
    p_attack.set_defaults(func=cmd_attack)

    p_demo = sub.add_parser("demo", help="run a fixed end-to-end walkthrough")
    p_demo.set_defaults(func=cmd_demo)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except RSAError as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
