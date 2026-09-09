# RSA Virtual Lab — Alice & Bob

A three-file, offline, interactive web page: "RSA Algorithm — Interactive
Secure Communication between Alice and Bob." Alice and Bob each type in
their own two primes and public exponent; the page computes real keys for
both of them and then walks through, one gated step at a time, an actual
message going from Alice to Bob (encrypted with Bob's public key, decrypted
with Bob's private key) and a reply going from Bob back to Alice (encrypted
with Alice's public key, decrypted with Alice's private key) — including an
animated packet that visibly travels between them.

## 1. Creating these files in VS Code

If you're typing this project up from scratch rather than copying it:

1. Open VS Code.
2. `File > Open Folder...` and create (or pick) a folder called
   `RSA-Virtual-Lab`.
3. In the Explorer sidebar, create three new files inside it: `index.html`,
   `style.css`, and `script.js` (right-click the folder → "New File").
4. Paste the matching content into each file and save (`Ctrl+S`). All three
   files must sit directly inside the same folder — `index.html` loads the
   other two as `<link rel="stylesheet" href="style.css">` and
   `<script src="script.js">`, both plain relative paths.

## 2. Running it

No server, no build step, no `npm install`, no Python. Just open
`index.html` directly:

- **Double-click `index.html`** in File Explorer (or Finder), or
- In VS Code, right-click `index.html` in the Explorer sidebar → **"Reveal
  in File Explorer"**, then double-click it there, or
- Drag `index.html` into any open browser window.

Any modern browser (Chrome, Edge, Firefox, Safari) can run it, since it
only uses standard HTML, CSS and JavaScript already built into the
browser — nothing needs to be downloaded. A "Load these values into the
form" button under the Sample Experiment panel fills in the fields below
for you, or type your own primes.

## 3. Sample test case

Click **"Load these values into the form"** (or type these in yourself),
then **Generate Keys ▶**:

| field | Alice | Bob |
|---|---|---|
| Prime p | 5 | 7 |
| Prime q | 11 | 11 |
| Public exponent e | 3 | 7 |

Alice's message defaults to "HELLO BOB"; Bob's reply defaults to
"HOW ARE YOU". Both can be left as they are or changed to any text using
only A–Z and spaces.

## 4. Expected output for the sample case

Computed by actually running the page's own code and confirmed in the
browser before writing it down here — not assumed:

| quantity | Alice | Bob |
|---|---|---|
| n = p × q | 5 × 11 = **55** | 7 × 11 = **77** |
| φ(n) = (p−1)(q−1) | 4 × 10 = **40** | 6 × 10 = **60** |
| d (found by trying d = 1, 2, 3, …) | **27** (27 × 3 mod 40 = 1) | **43** (43 × 7 mod 60 = 1) |
| Public Key PU | (3, 55) | (7, 77) |
| Private Key PR | (27, 55) | (43, 77) |

With the default messages: **"HELLO BOB"** encrypted with Bob's public key
(7, 77), sent, and decrypted with Bob's private key (43, 77) comes back as
**"HELLO BOB"** — ✅ MESSAGE SUCCESSFULLY RECOVERED. **"HOW ARE YOU"**
encrypted with Alice's public key (3, 55), sent, and decrypted with Alice's
private key (27, 55) comes back as **"HOW ARE YOU"** — ✅ MESSAGE
SUCCESSFULLY RECOVERED.

(The fixed "Sample Experiment" reference panel at the top of the page
shows a third, even smaller worked example — p=5, q=11, e=3, M=7 → C=13 →
back to 7 — for checking the single-character arithmetic by hand.)

## 5. How Alice → Bob and Bob → Alice work

Both directions use exactly the same six-line algorithm; only *whose* keys
are used, and in which role, changes:

```
n  = p × q
φ(n) = (p − 1)(q − 1)
choose e with 1 < e < φ(n) and gcd(e, φ(n)) = 1        (typed in, not generated)
find d with (e × d) mod φ(n) = 1                        (found by trying d = 1, 2, 3, ...)
Public key PU = (e, n)      Private key PR = (d, n)
C = M^e mod n                M = C^d mod n
```

**Alice → Bob**: Alice wants to send Bob a message only Bob can read. She
looks up Bob's *public* key `PU_Bob = (e_Bob, n_Bob)` — public keys are
meant to be shared, so she doesn't need anything secret from Bob to do
this — and computes `C = M^e_Bob mod n_Bob` for every letter of her
message. Only the ciphertext `C` ever crosses the wire. Bob is the only
one who holds the matching *private* key `PR_Bob = (d_Bob, n_Bob)`, so only
Bob can compute `M = C^d_Bob mod n_Bob` and recover the letters. Alice's
own key pair is never used in this direction at all — a sender never
encrypts with their own public key, because that would mean only *they*
could decrypt it back.

**Bob → Alice**: the same pattern, mirrored. Bob replies using *Alice's*
public key `PU_Alice = (e_Alice, n_Alice)` to compute
`C = M^e_Alice mod n_Alice`, sends `C`, and only Alice's private key
`PR_Alice = (d_Alice, n_Alice)` can reverse it: `M = C^d_Alice mod n_Alice`.

So across the whole exchange, four keys exist (Alice's public, Alice's
private, Bob's public, Bob's private), but any single message only ever
touches two of them: the *receiver's* public key to lock it, and that same
receiver's private key to unlock it.
