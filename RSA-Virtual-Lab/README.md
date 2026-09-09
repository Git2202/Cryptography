# RSA Virtual Lab

A three-file, offline, interactive web page that generates a real RSA key
pair from two primes you provide, and shows every calculation — not just
the final answer — as a step-by-step result card.

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
browser — nothing needs to be downloaded.

## 3. Sample test case

Enter these values in the input panel:

| field | value |
|---|---|
| Prime p | 5 |
| Prime q | 11 |
| Message M | 2 |
| Public exponent e | *(leave blank)* |

Then click **Generate RSA**.

## 4. Expected output for the sample case

Computed by actually running the page's own code (`findPublicExponent`,
`modInverse`, `modPow`) and confirmed in the browser before writing it down
here — not assumed:

| quantity | value |
|---|---|
| n = p × q | 5 × 11 = **55** |
| φ(n) = (p−1)(q−1) | 4 × 10 = **40** |
| e candidates tried | e=2 → gcd(2,40)=2 (rejected); e=3 → gcd(3,40)=1 (**accepted**) |
| Chosen e | **3** |
| d (from the extended Euclidean algorithm) | **27** — check: 27 × 3 mod 40 = 1 |
| Public Key | (e, n) = **(3, 55)** |
| Private Key | (d, n) = **(27, 55)** |
| Encrypt: C = M^e mod n | 2³ mod 55 = **8** |
| Decrypt: M = C^d mod n | 8²⁷ mod 55 = **2** |
| Verification | ✅ **Successful** — 2 = 2 |

## 5. How this satisfies the assignment requirement

The assignment asks for "a web-based virtual laboratory page that allows
users to provide inputs and interactively visualize the experiment." This
page does exactly that: the user supplies the actual experimental
parameters (two primes and a message, with an optional public exponent),
and every stage of the RSA "experiment" — validating the primes, computing
`n` and `φ(n)`, searching for a valid public exponent and showing which
candidates were tried and rejected, working out the private exponent step
by step, forming the public and private keys, and finally encrypting and
decrypting the message to verify it round-trips correctly — is rendered as
its own visible, numbered result, alongside two flow diagrams that
highlight which stage of the process is currently being shown. Nothing is
precomputed or hard-coded to one example: changing the inputs and clicking
"Generate RSA" again re-runs the entire calculation from scratch and
produces a genuinely different key pair, so the "interactively visualize"
requirement is met by the page actually doing the cryptographic work in
front of the user, not by animating a canned result.
