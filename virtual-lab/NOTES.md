# Virtual lab ↔ Python mapping

`index.html` reimplements the RSA logic independently in JavaScript (the lab
must run fully offline with no build step, so it cannot import the Python
package). This table maps every JS function in `<script>` to the Python
function it mirrors, so the two can be compared line by line. "Self-test"
proves the two agree on the assignment's known-answer vector at runtime.

| JS function | Python counterpart | Notes |
|---|---|---|
| `gcd(a, b)` | `rsa.mathutils.gcd` | Same Euclidean-algorithm loop, BigInt instead of int. |
| `lcm(a, b)` | `rsa.mathutils.lcm` | |
| `egcd(a, b)` | `rsa.mathutils.egcd` | |
| `egcdSteps(a, b)` | `rsa.mathutils.egcd_steps` | Same row shape (`i, r, q, s, t`); drives the Step 5 table in panel 2. |
| `modInv(a, m)` | `rsa.mathutils.modinv` | |
| `modExp(base, exp, mod)` | `rsa.mathutils.mod_exp` | Left-to-right square-and-multiply, MSB first. |
| `modExpSteps(base, exp, mod)` | `rsa.mathutils.mod_exp_steps` | Same row shape; drives the square-and-multiply tables in panel 3. |
| `sieveOfEratosthenes(limit)` | `rsa.primes.sieve_of_eratosthenes` | Also records which prime eliminated each composite, for the grid labels — Python's version only needs the prime list, not that bookkeeping. |
| `isPrimeTrial(n)` | `rsa.primes.is_prime_trial` | |
| `isPrimeMillerRabin(n)` | `rsa.primes.is_prime_miller_rabin` | Same fixed deterministic witness set `{2,3,5,7,...,37}`. |
| `totient(p, q)` | `rsa.keygen.totient` | |
| `carmichaelLambda(p, q)` | `rsa.keygen.carmichael_lambda` | |
| `chooseE(lam)` | `rsa.keygen._choose_e` | Same preferred-candidate list `[65537, 257, 17, 5, 3]` and fallback search. |
| `validateE(e, lam)` | `rsa.keygen._validate_e` | |
| `generateKeys(p, q, customE)` | `rsa.keygen.generate_keypair` | Returns `{p,q,n,phi,lam,e,eCandidates,egcdTable,d}` — the JS equivalent of `KeyPair` + its `trace`. |
| `blockByteWidth(n)` | `rsa.cipher._block_byte_width` | |
| `textToBlocks(text, n)` | `rsa.cipher.text_to_blocks` | Uses `TextEncoder`/UTF-8, same zero-padding rule. |
| `blocksToText(blocks, n)` | `rsa.cipher.blocks_to_text` | Same trailing-zero-byte trim. |
| `encryptValue(m, e, n)` | `rsa.cipher.encrypt` | Also returns the `modExpSteps` trace. |
| `decryptValue(c, d, n)` | `rsa.cipher.decrypt` | Also returns the `modExpSteps` trace. (No CRT variant in the lab — not one of the five required panels.) |
| `factorN(nBig)` | `rsa.attack.factor_n` | Converts to a plain Number first (safe: p, q are capped well under 2^53) for a faster tight loop; returns `{p, q, attempts, elapsedMs}`. |
| `recoverD(p, q, e)` | `rsa.attack.recover_d` | |
| `randomPrimeInRange(low, high)` | `rsa.primes.random_prime` | Simplified: samples directly from a range with `Math.random()` rather than taking a seeded `random.Random` — the lab has no determinism requirement, only the Python test suite does. |
| `runSelfTest()` | `tests/test_keygen.py` + `tests/test_cipher.py` (the p=61, q=53, e=17 known-answer vector) + `tests/test_attack.py` | Runs the same KAT plus a few random round trips, in-browser. |

Everything under "UI STATE", "PANEL NAVIGATION", and the five `PANEL n:`
sections in `index.html` is page glue (rendering, event listeners, form
validation) with no Python counterpart — Part 1 of the assignment has no
notion of a UI.
