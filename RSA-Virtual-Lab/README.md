# RSA messenger

A three-file, offline web page styled as a two-way messenger between Alice
and Bob. Both type their own primes and public exponent (nothing is
auto-generated); every message either of them sends is encrypted with the
*receiver's* public key, travels across an animated "wire" as ciphertext
blocks, and is decrypted on arrival with the receiver's private key — with
every intermediate number computed live and shown on screen, never
hard-coded.

## 1. Creating these files in VS Code

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

The page loads with Alice (p=5, q=11, e=3) and Bob (p=7, q=13, e=5) already
filled in, so it works immediately — each of them has their own message box
and "Encrypt and send" button at the bottom of their own panel. Type a
message (A–Z and spaces only) in either box and click that party's own
button (or just press Enter in the box) to send as them.

## 3. How Alice → Bob and Bob → Alice work

Both directions use exactly the same maths; only *whose* keys are used, and
in which role, changes:

```
n = p × q
φ(n) = (p − 1)(q − 1)
e is typed by the user; must satisfy 1 < e < φ(n) and gcd(e, φ(n)) = 1
d is found by trying d = 1, 2, 3, ... until (e × d) mod φ(n) = 1
Public key (e, n)      Private key (d, n)
C = M^e mod n           M = C^d mod n
```

**Alice → Bob**: Alice wants to send Bob a message only Bob can read. She
looks up Bob's *public* key `(e_Bob, n_Bob)` — public keys are meant to be
shared, so nothing secret from Bob is needed to do this — and computes
`C = M^e_Bob mod n_Bob` for every letter, one block per letter. Only the
ciphertext blocks ever cross the wire; the plaintext never does. Bob is the
only one holding the matching *private* key `(d_Bob, n_Bob)`, so only Bob
can compute `M = C^d_Bob mod n_Bob` and recover the letters. Alice's own key
pair plays no part in this direction — a sender never encrypts with their
own public key, since that would mean only *they* could decrypt it back.

**Bob → Alice**: the same pattern, mirrored. Bob replies using *Alice's*
public key `(e_Alice, n_Alice)` to compute `C = M^e_Alice mod n_Alice`,
sends the blocks, and only Alice's private key `(d_Alice, n_Alice)` can
reverse it: `M = C^d_Alice mod n_Alice`.

With the page's default keys, this was verified by actually running the
code (not hand-typed): Alice sending **"HELLO"** to Bob produces ciphertext
blocks **63 23 72 72 14** and decrypts back to **HELLO**; Bob sending
**"HI"** to Alice produces **13 17** and decrypts back to **HI**.

### A property worth noticing, not a bug

Letters **A (0)** and **B (1)** always encrypt to themselves, under *any*
key: `0^e mod n` is always `0`, and `1^e mod n` is always `1`, whatever `e`
and `n` are — raising zero or one to any power never changes them. Some
keys have *other* fixed points too, letters that happen to encrypt to
themselves for that particular `(e, n)`: with the page's default Bob key
`(e=5, n=91)`, the letter **O (14)** is one — `14^5 mod 91 = 14`, which is
exactly why the worked "HELLO" example above ends in a `14` in both its
plaintext numbers and its ciphertext. This is a genuine, well-known property
of textbook RSA without padding (a message can have "unconcealed" fixed
points for a given key), not a flaw in this page's arithmetic.
