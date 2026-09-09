// ==========================================================================
// RSA Virtual Laboratory — Alice & Bob — script.js
//
// Plain JavaScript, plain named functions only (no classes, no modules, no
// async, no arrow-function chains). Every RSA function has a short comment
// above it saying what it does and what it returns. BigInt is used ONLY
// inside modPow -- everywhere else ordinary numbers are used, because the
// primes this lab is built for stay small enough that ordinary numbers
// represent them exactly.
//
// Algorithm used, and nothing else:
//   n = p * q
//   phi(n) = (p-1)(q-1)
//   choose e with 1 < e < phi(n) and gcd(e, phi(n)) = 1   (typed by the user)
//   find d with (e * d) mod phi(n) = 1                     (found by trying
//                                                            d = 1, 2, 3, ...)
//   Public key PU = (e, n)      Private key PR = (d, n)
//   C = M^e mod n               M = C^d mod n
// No lambda(n)/Carmichael, no padding, no CRT.
// ==========================================================================

"use strict";


// ==========================================================================
// CORE RSA FUNCTIONS
// ==========================================================================

// Checks whether a whole number is prime, by trying to divide it by every
// number from 2 up to its square root. Returns true or false.
function isPrime(num) {
  if (num < 2) {
    return false;
  }
  if (num === 2) {
    return true;
  }
  if (num % 2 === 0) {
    return false;
  }
  for (var divisor = 3; divisor * divisor <= num; divisor = divisor + 2) {
    if (num % divisor === 0) {
      return false;
    }
  }
  return true;
}

// Finds the greatest common divisor of two whole numbers, using Euclid's
// algorithm (repeatedly replace the bigger number with the remainder of
// dividing it by the smaller one, until the remainder is zero).
// Returns a single whole number.
function gcd(a, b) {
  while (b !== 0) {
    var remainder = a % b;
    a = b;
    b = remainder;
  }
  return a;
}

// Computes the RSA modulus n = p * q. Returns a whole number.
function calculateN(p, q) {
  return p * q;
}

// Computes Euler's totient phi(n) = (p-1)(q-1). Returns a whole number.
function calculatePhi(p, q) {
  return (p - 1) * (q - 1);
}

// Finds the private exponent d by brute force: try d = 1, then d = 2, then
// d = 3, and so on, stopping as soon as (e * d) mod phi equals 1. This is
// deliberately the simple, obvious search (not the extended Euclidean
// algorithm), so every step of the search can be shown on screen.
// Returns an object: { d: <the answer, or null if none exists in range>,
// trials: <an array of every d tried, each row recording d, the product
// e*d, the remainder (e*d) mod phi, and whether that row was the hit> }.
function calculateD(e, phi) {
  var trials = [];
  var found = null;

  for (var d = 1; d < phi; d = d + 1) {
    var product = e * d;
    var remainder = product % phi;
    var isHit = (remainder === 1);
    trials.push({ d: d, product: product, remainder: remainder, isHit: isHit });
    if (isHit) {
      found = d;
      break;
    }
  }

  return { d: found, trials: trials };
}

// Computes (base ^ exponent) mod modulus, using the "square-and-multiply"
// method (also called repeated squaring), which needs only about
// log2(exponent) multiplications instead of doing "exponent" multiplications
// one at a time.
//
// This is the ONE function on this page that uses BigInt. While working
// through the exponent bit by bit, the numbers being squared can briefly
// get larger than an ordinary JavaScript number can hold exactly (ordinary
// numbers are only exact up to 2^53); BigInt has no such limit. Ordinary
// exponentiation operators are also unusable here on purpose: Math.pow and
// the ** operator both compute in floating point, which would round a
// large result instead of giving the exact whole-number remainder that
// cryptography needs.
//
// BigInt values are created from ordinary numbers right at the top of this
// function, and the final BigInt answer is converted back to an ordinary
// number right before returning, so nothing outside this function ever has
// to deal with BigInt. (BigInt and ordinary numbers can never appear
// together in the same arithmetic expression -- JavaScript throws a
// TypeError if you try -- which is exactly why the conversion happens at
// the boundary here, and nowhere else.)
function modPow(base, exponent, modulus) {
  var result = 1n;
  var b = BigInt(base) % BigInt(modulus);
  var e = BigInt(exponent);
  var m = BigInt(modulus);

  while (e > 0n) {
    if (e % 2n === 1n) {
      // The lowest bit of what's left of the exponent is 1, so multiply
      // this power of the base into the running result.
      result = (result * b) % m;
    }
    b = (b * b) % m; // square the base, ready for the next bit
    e = e / 2n; // BigInt division drops the remainder -- this moves to the next bit
  }

  return Number(result);
}

// Converts one uppercase letter A-Z into its number 0-25 (A=0, B=1, ...
// Z=25). Returns null for a space, since a space is never turned into a
// number -- it passes through encryption untouched.
function charToNum(ch) {
  if (ch === " ") {
    return null;
  }
  return ch.charCodeAt(0) - "A".charCodeAt(0);
}

// Converts a number 0-25 back into its uppercase letter A-Z (the reverse
// of charToNum). Returns a single-character string.
function numToChar(num) {
  return String.fromCharCode(num + "A".charCodeAt(0));
}

// Encrypts a message letter by letter with the public key (e, n). message
// must already be uppercase A-Z and spaces only (validateMessageCharacters
// below checks that before this is ever called).
// Returns an array with one entry per character of the message:
//   { char: the original letter (or space), isSpace: true/false,
//     plainNum: 0-25 (or null for a space),
//     cipherNum: plainNum^e mod n (or null for a space) }
function rsaEncrypt(message, e, n) {
  var entries = [];
  for (var i = 0; i < message.length; i = i + 1) {
    var ch = message.charAt(i);
    if (ch === " ") {
      entries.push({ char: ch, isSpace: true, plainNum: null, cipherNum: null });
    } else {
      var plainNum = charToNum(ch);
      var cipherNum = modPow(plainNum, e, n);
      entries.push({ char: ch, isSpace: false, plainNum: plainNum, cipherNum: cipherNum });
    }
  }
  return entries;
}

// Decrypts a list of received blocks with the private key (d, n).
// receivedEntries is the array rsaEncrypt produced (or an equivalent array
// with at least isSpace and cipherNum on each entry) -- exactly what was
// "transmitted".
// Returns a new array with one entry per character:
//   { isSpace: true/false, cipherNum: the value that was received,
//     decryptedNum: 0-25 (or null for a space),
//     decryptedChar: the recovered letter (or a space) }
function rsaDecrypt(receivedEntries, d, n) {
  var results = [];
  for (var i = 0; i < receivedEntries.length; i = i + 1) {
    var entry = receivedEntries[i];
    if (entry.isSpace) {
      results.push({ isSpace: true, cipherNum: null, decryptedNum: null, decryptedChar: " " });
    } else {
      var decryptedNum = modPow(entry.cipherNum, d, n);
      var decryptedChar = numToChar(decryptedNum);
      results.push({
        isSpace: false,
        cipherNum: entry.cipherNum,
        decryptedNum: decryptedNum,
        decryptedChar: decryptedChar
      });
    }
  }
  return results;
}

// Joins an array of entries (from rsaEncrypt or rsaDecrypt) back into a
// plain text string, reading whichever field name holds the character on
// each entry. Returns a string.
function entriesToText(entries, charField) {
  var text = "";
  for (var i = 0; i < entries.length; i = i + 1) {
    text = text + entries[i][charField];
  }
  return text;
}


// ==========================================================================
// VALIDATION
// ==========================================================================

// Checks whether a piece of text is a valid non-negative whole number
// (digits only, no minus sign, no decimal point, not empty).
// Returns true or false.
function isValidNonNegativeInteger(text) {
  if (text.length === 0) {
    return false;
  }
  return /^[0-9]+$/.test(text);
}

// Validates one person's three input fields (p, q, e) and, if they're all
// valid, computes n, phi(n) and d for them. prefix is "alice" or "bob",
// used to find the right input elements on the page.
// Returns an object:
//   { ok: true/false, p, q, e, n, phi, d, dTrials,
//     errors: { p: "", q: "", e: "" } }
// (errors hold empty strings where there is no problem).
function validatePerson(prefix) {
  var pText = document.getElementById(prefix + "-p").value.trim();
  var qText = document.getElementById(prefix + "-q").value.trim();
  var eText = document.getElementById(prefix + "-e").value.trim();

  var result = {
    ok: true,
    p: null, q: null, e: null, n: null, phi: null, d: null, dTrials: null,
    errors: { p: "", q: "", e: "" }
  };

  // --- p ---
  if (!isValidNonNegativeInteger(pText)) {
    result.errors.p = "p must be a whole number.";
    result.ok = false;
  } else {
    var pValue = parseInt(pText, 10);
    if (!isPrime(pValue)) {
      result.errors.p = "p must be a prime number.";
      result.ok = false;
    } else {
      result.p = pValue;
    }
  }

  // --- q ---
  if (!isValidNonNegativeInteger(qText)) {
    result.errors.q = "q must be a whole number.";
    result.ok = false;
  } else {
    var qValue = parseInt(qText, 10);
    if (!isPrime(qValue)) {
      result.errors.q = "q must be a prime number.";
      result.ok = false;
    } else {
      result.q = qValue;
    }
  }

  // --- p and q must be different ---
  if (result.p !== null && result.q !== null && result.p === result.q) {
    result.errors.q = "q must be different from p.";
    result.ok = false;
    result.q = null;
  }

  // From here on we need valid p and q to say anything useful about e.
  if (result.p === null || result.q === null) {
    if (eText.length === 0) {
      result.errors.e = "e must be a whole number.";
    }
    return result;
  }

  var n = calculateN(result.p, result.q);
  var phi = calculatePhi(result.p, result.q);
  result.n = n;
  result.phi = phi;

  // --- e ---
  if (!isValidNonNegativeInteger(eText)) {
    result.errors.e = "e must be a whole number.";
    result.ok = false;
    return result;
  }
  var eValue = parseInt(eText, 10);
  if (!(eValue > 1 && eValue < phi)) {
    result.errors.e = "e must satisfy 1 < e < phi(n) (phi(n) = " + phi + ").";
    result.ok = false;
    return result;
  }
  var eGcd = gcd(eValue, phi);
  if (eGcd !== 1) {
    result.errors.e =
      "e must share no common factor with phi(n) = " + phi +
      " (gcd(e, phi(n)) = " + eGcd + ", must be 1).";
    result.ok = false;
    return result;
  }
  result.e = eValue;

  // --- d must exist (it always will once the gcd check above passes, but
  //     this is checked directly rather than assumed) ---
  var dResult = calculateD(eValue, phi);
  if (dResult.d === null) {
    result.errors.e = "no private exponent d exists for this e and phi(n).";
    result.ok = false;
    return result;
  }
  result.d = dResult.d;
  result.dTrials = dResult.trials;

  return result;
}

// Validates both Alice's and Bob's input fields, writes any error messages
// onto the page next to the field they belong to, and returns the combined
// result. This is the page's single entry point for checking Step 1.
// Returns { ok: true/false, alice: <validatePerson result>, bob: <validatePerson result> }.
function validateInputs() {
  var aliceResult = validatePerson("alice");
  var bobResult = validatePerson("bob");

  document.getElementById("alice-p-error").textContent = aliceResult.errors.p;
  document.getElementById("alice-q-error").textContent = aliceResult.errors.q;
  document.getElementById("alice-e-error").textContent = aliceResult.errors.e;
  document.getElementById("bob-p-error").textContent = bobResult.errors.p;
  document.getElementById("bob-q-error").textContent = bobResult.errors.q;
  document.getElementById("bob-e-error").textContent = bobResult.errors.e;

  return { ok: aliceResult.ok && bobResult.ok, alice: aliceResult, bob: bobResult };
}

// Checks that a typed message contains only uppercase letters A-Z and
// spaces (the text is uppercased first, so lowercase letters are fine to
// type). Returns { ok: true/false, cleaned: <uppercased text>,
// errorChar: <the first character that isn't allowed, if any> }.
function validateMessageCharacters(rawText) {
  var cleaned = rawText.toUpperCase();
  for (var i = 0; i < cleaned.length; i = i + 1) {
    var ch = cleaned.charAt(i);
    var isLetter = ch >= "A" && ch <= "Z";
    if (!isLetter && ch !== " ") {
      return { ok: false, cleaned: cleaned, errorChar: ch };
    }
  }
  return { ok: true, cleaned: cleaned, errorChar: null };
}

// Checks that every letter in a message maps to a number smaller than the
// modulus n it's about to be encrypted with (spaces are skipped, since
// they are never turned into a number). Returns { ok: true/false,
// offendingChar: <the first letter that's too big, if any>,
// offendingValue: <that letter's number, if any> }.
function checkMessageFitsModulus(cleanedMessage, n) {
  for (var i = 0; i < cleanedMessage.length; i = i + 1) {
    var ch = cleanedMessage.charAt(i);
    if (ch === " ") {
      continue;
    }
    var value = charToNum(ch);
    if (value >= n) {
      return { ok: false, offendingChar: ch, offendingValue: value };
    }
  }
  return { ok: true, offendingChar: null, offendingValue: null };
}


// ==========================================================================
// TINY DOM HELPERS
// ==========================================================================

function $(id) {
  return document.getElementById(id);
}

// Appends a new step card to the page (steps are never removed once shown
// -- earlier steps stay visible below the current one, like a running
// record of the whole experiment). Returns the card element, so the
// caller can look inside it for buttons/inputs it just created.
function appendStepCard(stepNumber, title, bodyHtml) {
  var card = document.createElement("div");
  card.className = "step-card";

  var badge = document.createElement("span");
  badge.className = "step-badge";
  badge.textContent = "Step " + stepNumber;

  var heading = document.createElement("h3");
  heading.appendChild(badge);
  heading.appendChild(document.createTextNode(title));
  card.appendChild(heading);

  var body = document.createElement("div");
  body.innerHTML = bodyHtml;
  card.appendChild(body);

  $("stepsArea").appendChild(card);
  card.scrollIntoView({ behavior: "smooth", block: "nearest" });
  return card;
}


// ==========================================================================
// STATE
// ==========================================================================

var STEP_LABELS = [
  "", // no step 0
  "Enter Parameters",
  "Alice's Keys",
  "Bob's Keys",
  "Alice → Bob",
  "Encrypt Alice's Message",
  "Send Ciphertext",
  "Bob Decrypts",
  "Bob → Alice",
  "Encrypt Bob's Message",
  "Send Ciphertext",
  "Alice Decrypts",
  "Verification"
];

var state = {
  currentStep: 1,
  alice: null,
  bob: null,
  a2b: null, // { message, entries, decrypted }
  b2a: null
};


// ==========================================================================
// PROGRESS BAR
// ==========================================================================

// Updates the progress bar's fill width and label to match state.currentStep.
// Does not return anything.
function updateProgressBar() {
  var percent = Math.round((state.currentStep / 12) * 100);
  $("progressFill").style.width = percent + "%";
  $("progressLabel").textContent =
    "Step " + state.currentStep + " of 12 — " + STEP_LABELS[state.currentStep];
}


// ==========================================================================
// SHARED HTML BUILDERS (used by both directions)
// ==========================================================================

// Builds the small vertical flow diagram (plain HTML boxes + CSS arrows)
// for one message direction. Returns an HTML string.
function buildFlowDiagramHtml(senderName, receiverName, encryptKeyLabel, encryptKeyValue, decryptKeyLabel, decryptKeyValue) {
  var boxes = [
    { text: "Plaintext (" + senderName + "'s message)", keyStep: false },
    { text: "Key used: " + encryptKeyLabel + " = " + encryptKeyValue, keyStep: true },
    { text: "Encrypt", keyStep: false },
    { text: "Ciphertext", keyStep: false },
    { text: "Transmit to " + receiverName, keyStep: false },
    { text: "Key used: " + decryptKeyLabel + " = " + decryptKeyValue, keyStep: true },
    { text: "Decrypt", keyStep: false },
    { text: "Plaintext (recovered)", keyStep: false }
  ];

  var html = "<div class='flow-diagram'>";
  for (var i = 0; i < boxes.length; i = i + 1) {
    if (i > 0) {
      html = html + "<div class='flow-arrow-down'>&#8595;</div>";
    }
    var extraClass = boxes[i].keyStep ? " key-step" : "";
    html = html + "<div class='flow-box" + extraClass + "'>" + boxes[i].text + "</div>";
  }
  html = html + "</div>";
  return html;
}

// Builds the table showing calculateD's search: the first few trials, a
// "..." gap if the hit wasn't near the start, and the hit row itself.
// Returns an HTML string.
function buildDTrialsTableHtml(trials) {
  var rowsToShow = [];
  var previewCount = Math.min(3, trials.length);
  for (var i = 0; i < previewCount; i = i + 1) {
    rowsToShow.push(trials[i]);
  }
  var hitIndex = -1;
  for (var j = 0; j < trials.length; j = j + 1) {
    if (trials[j].isHit) {
      hitIndex = j;
      break;
    }
  }
  var needsGap = hitIndex >= previewCount;

  var html = "<table class='working-table'><tr><th>d tried</th><th>e &times; d</th><th>(e &times; d) mod &phi;(n)</th><th>hit?</th></tr>";
  for (var k = 0; k < rowsToShow.length; k = k + 1) {
    html = html + buildDTrialRowHtml(rowsToShow[k]);
  }
  if (needsGap) {
    html = html + "<tr><td colspan='4'>&hellip;</td></tr>";
    html = html + buildDTrialRowHtml(trials[hitIndex]);
  }
  html = html + "</table>";
  return html;
}

function buildDTrialRowHtml(row) {
  var rowClass = row.isHit ? " class='row-hit'" : "";
  return "<tr" + rowClass + "><td>" + row.d + "</td><td>" + row.product + "</td><td>" +
    row.remainder + "</td><td>" + (row.isHit ? "yes ✓" : "no") + "</td></tr>";
}

// Builds the key-generation card body (n, phi(n), d-search, public/private
// key boxes) for one person. Returns an HTML string.
function buildKeysCardHtml(personLabel, person) {
  var html = "";
  html = html + "<p class='formula'>n = p &times; q</p>";
  html = html + "<p class='formula-sub'>n = " + person.p + " &times; " + person.q + " = <b>" + person.n + "</b></p>";
  html = html + "<p class='formula'>&phi;(n) = (p &minus; 1)(q &minus; 1)</p>";
  html = html + "<p class='formula-sub'>&phi;(n) = (" + person.p + " &minus; 1)(" + person.q + " &minus; 1) = <b>" + person.phi + "</b></p>";
  html = html + "<p class='formula'>Find d so that (e &times; d) mod &phi;(n) = 1, by trying d = 1, 2, 3, &hellip;</p>";
  html = html + buildDTrialsTableHtml(person.dTrials);
  html = html + "<div class='key-box public'><span class='key-tag'>SHAREABLE</span><br>Public Key PU = (e, n) = <span class='key-value'>(" + person.e + ", " + person.n + ")</span></div>";
  html = html + "<div class='key-box private'><span class='key-tag'>SECRET</span><br>Private Key PR = (d, n) = <span class='key-value'>(" + person.d + ", " + person.n + ")</span></div>";
  return html;
}

// Builds the character-mapping / encryption working table for a message.
// Returns an HTML string.
function buildEncryptTableHtml(entries, e, n) {
  var html = "<table class='working-table'><tr><th>char</th><th>number</th><th>C = number<sup>" + e + "</sup> mod " + n + "</th></tr>";
  for (var i = 0; i < entries.length; i = i + 1) {
    var entry = entries[i];
    if (entry.isSpace) {
      html = html + "<tr class='row-space'><td>(space)</td><td colspan='2'>space — not encrypted</td></tr>";
    } else {
      html = html + "<tr><td>" + entry.char + " &rarr; " + entry.plainNum + "</td><td>" + entry.plainNum + "</td><td><b>" + entry.cipherNum + "</b></td></tr>";
    }
  }
  html = html + "</table>";
  return html;
}

// Builds the decryption working table for a received message.
// Returns an HTML string.
function buildDecryptTableHtml(results, d, n) {
  var html = "<table class='working-table'><tr><th>received</th><th>M = received<sup>" + d + "</sup> mod " + n + "</th><th>letter</th></tr>";
  for (var i = 0; i < results.length; i = i + 1) {
    var r = results[i];
    if (r.isSpace) {
      html = html + "<tr class='row-space'><td colspan='3'>space — passed through</td></tr>";
    } else {
      html = html + "<tr><td>" + r.cipherNum + "</td><td>" + r.decryptedNum + "</td><td><b>" + r.decryptedChar + "</b></td></tr>";
    }
  }
  html = html + "</table>";
  return html;
}

// Builds the green/red verification box comparing the original message to
// what was decrypted. Returns an HTML string.
function buildVerifyBoxHtml(original, decrypted) {
  var success = (original === decrypted);
  var boxClass = success ? "verify-box success" : "verify-box fail";
  var html = "<div class='compare-row'>";
  html = html + "<div class='compare-item'>Original:&nbsp; \"" + original + "\"</div>";
  html = html + "<div class='compare-item'>Decrypted:&nbsp; \"" + decrypted + "\"</div>";
  html = html + "</div>";
  if (success) {
    html = html + "<div class='" + boxClass + "'>&#9989; MESSAGE SUCCESSFULLY RECOVERED</div>";
  } else {
    html = html + "<div class='" + boxClass + "'>&#10060; VERIFICATION FAILED — recovered text does not match the original</div>";
  }
  return html;
}

// Builds the big animated communication area for one direction. Returns
// the card's HTML string; the packet element is found and animated
// separately afterwards (see animatePacket below).
function buildCommAreaHtml(senderName, senderAvatar, senderClass, receiverName, receiverAvatar, receiverClass) {
  var html = "<div class='not-sent-banner'>The original message is NOT sent.<br>Only the encrypted ciphertext is transmitted.</div>";
  html = html + "<div class='comm-area'>";
  html = html + "<div class='person-card " + senderClass + "-card role-sending'>";
  html = html + "<span class='role-label sending'>SENDING</span>";
  html = html + "<span class='avatar-big'>" + senderAvatar + "</span>";
  html = html + "<div class='person-name'>" + senderName + "</div>";
  html = html + "</div>";
  html = html + "<div class='comm-gap'><div class='packet'>&#128274; CIPHERTEXT</div></div>";
  html = html + "<div class='person-card " + receiverClass + "-card role-receiving'>";
  html = html + "<span class='role-label receiving'>RECEIVING</span>";
  html = html + "<span class='avatar-big'>" + receiverAvatar + "</span>";
  html = html + "<div class='person-name'>" + receiverName + "</div>";
  html = html + "</div>";
  html = html + "</div>";
  return html;
}

// How long the packet's CSS "left" transition takes, in milliseconds. Must
// match the "transition: left ..." duration on .packet in style.css.
var PACKET_TRAVEL_MS = 1800;

// Starts the packet-travel animation inside a just-created comm area card,
// moving the packet from the left side to the right side (or right to
// left, if reversed is true). Calls onFinished once, after the travel is
// done. Does not return anything.
//
// Two different signals both call onFinished: the CSS "transitionend"
// event, and a plain timer (setTimeout) set to the same duration as the
// CSS transition. Normally transitionend alone would be enough, but
// browsers are allowed to delay or drop transition events for a tab that
// isn't the front-most, active one (to save power) -- so relying on it
// alone risks leaving the page stuck with no visible way to continue. The
// "calledAlready" guard makes sure onFinished only actually runs once, no
// matter which of the two signals arrives first.
function animatePacket(card, reversed, onFinished) {
  var packet = card.querySelector(".packet");
  var calledAlready = false;

  function finishOnce() {
    if (calledAlready) {
      return;
    }
    calledAlready = true;
    onFinished();
  }

  var startLeft = reversed ? "90%" : "2%";
  var endLeft = reversed ? "2%" : "90%";

  packet.style.transition = "none";
  packet.style.left = startLeft;

  // Force the browser to paint the starting position before we switch on
  // the transition and change the target position -- otherwise it can
  // skip straight to the end position with no visible movement at all.
  void packet.offsetWidth;

  packet.style.transition = "";
  packet.addEventListener("transitionend", function handleDone() {
    packet.removeEventListener("transitionend", handleDone);
    finishOnce();
  });
  packet.style.left = endLeft;

  setTimeout(finishOnce, PACKET_TRAVEL_MS + 200);
}


// ==========================================================================
// STEP 1: GENERATE KEYS / RESET / LOAD SAMPLE
// ==========================================================================

function lockStep1Inputs() {
  var ids = ["alice-p", "alice-q", "alice-e", "bob-p", "bob-q", "bob-e"];
  for (var i = 0; i < ids.length; i = i + 1) {
    $(ids[i]).disabled = true;
  }
  $("generateKeysBtn").disabled = true;
  $("loadSampleBtn").disabled = true;
}

function unlockStep1Inputs() {
  var ids = ["alice-p", "alice-q", "alice-e", "bob-p", "bob-q", "bob-e"];
  for (var i = 0; i < ids.length; i = i + 1) {
    $(ids[i]).disabled = false;
    $(ids[i]).value = "";
  }
  $("generateKeysBtn").disabled = false;
  $("loadSampleBtn").disabled = false;
}

function onGenerateKeysClick() {
  var validated = validateInputs();
  if (!validated.ok) {
    return;
  }
  state.alice = validated.alice;
  state.bob = validated.bob;
  lockStep1Inputs();
  goToStep2();
}

function onLoadSampleClick() {
  $("alice-p").value = "5";
  $("alice-q").value = "11";
  $("alice-e").value = "3";
  $("bob-p").value = "7";
  $("bob-q").value = "11";
  $("bob-e").value = "7";
}

function resetLab() {
  state.currentStep = 1;
  state.alice = null;
  state.bob = null;
  state.a2b = null;
  state.b2a = null;

  unlockStep1Inputs();
  var errorIds = ["alice-p-error", "alice-q-error", "alice-e-error", "bob-p-error", "bob-q-error", "bob-e-error"];
  for (var i = 0; i < errorIds.length; i = i + 1) {
    $(errorIds[i]).textContent = "";
  }

  $("stepsArea").innerHTML = "";
  updateProgressBar();
  window.scrollTo({ top: 0, behavior: "smooth" });
}


// ==========================================================================
// STEP 2 / 3: KEY CARDS
// ==========================================================================

function goToStep2() {
  state.currentStep = 2;
  updateProgressBar();
  var body = buildKeysCardHtml("Alice", state.alice) +
    "<button class='btn btn-primary step-next-btn'>Next ▶</button>";
  var card = appendStepCard(2, "Alice's Keys", body);
  card.querySelector(".step-next-btn").addEventListener("click", goToStep3);
}

function goToStep3() {
  state.currentStep = 3;
  updateProgressBar();
  var body = buildKeysCardHtml("Bob", state.bob) +
    "<button class='btn btn-primary step-next-btn'>Next ▶</button>";
  var card = appendStepCard(3, "Bob's Keys", body);
  card.querySelector(".step-next-btn").addEventListener("click", goToStep4);
}


// ==========================================================================
// STEPS 4-7: ALICE -> BOB
// ==========================================================================

function goToStep4() {
  state.currentStep = 4;
  updateProgressBar();

  var flowHtml = buildFlowDiagramHtml(
    "Alice", "Bob",
    "Bob's PUBLIC key", "(" + state.bob.e + ", " + state.bob.n + ")",
    "Bob's PRIVATE key", "(" + state.bob.d + ", " + state.bob.n + ")"
  );
  var body = "<p><strong>Alice sends a message to Bob.</strong> Alice must encrypt " +
    "it with <em>Bob's public key</em>, not her own -- only Bob's matching " +
    "private key can undo that.</p>" + flowHtml +
    "<div class='field-group'>" +
    "<label for='a2b-message'>Alice's message (A–Z and spaces only)</label>" +
    "<input type='text' id='a2b-message' value='HELLO BOB'>" +
    "<span class='field-error' id='a2b-message-error'></span>" +
    "</div>" +
    "<button class='btn btn-primary' id='a2bEncryptBtn'>Encrypt Message ▶</button>";

  var card = appendStepCard(4, "Alice → Bob", body);
  card.querySelector("#a2bEncryptBtn").addEventListener("click", onA2BEncryptClick);
}

function onA2BEncryptClick() {
  var rawText = $("a2b-message").value;
  var checked = validateMessageCharacters(rawText);
  if (!checked.ok) {
    $("a2b-message-error").textContent =
      "\"" + checked.errorChar + "\" is not allowed — only A–Z and spaces.";
    return;
  }
  var fitsCheck = checkMessageFitsModulus(checked.cleaned, state.bob.n);
  if (!fitsCheck.ok) {
    $("a2b-message-error").textContent =
      "'" + fitsCheck.offendingChar + "' maps to " + fitsCheck.offendingValue +
      ", which is not smaller than n = " + state.bob.n +
      ". The modulus is too small — use larger classroom primes for Bob.";
    return;
  }
  $("a2b-message-error").textContent = "";

  var entries = rsaEncrypt(checked.cleaned, state.bob.e, state.bob.n);
  state.a2b = { message: checked.cleaned, entries: entries };
  goToStep5();
}

function goToStep5() {
  state.currentStep = 5;
  updateProgressBar();
  var body = "<p>Each letter of \"" + state.a2b.message + "\" is converted to a number, " +
    "then raised to Bob's public exponent, modulo Bob's n:</p>" +
    buildEncryptTableHtml(state.a2b.entries, state.bob.e, state.bob.n) +
    "<button class='btn btn-primary step-next-btn'>Send Ciphertext ▶</button>";
  var card = appendStepCard(5, "Encrypt Alice's Message", body);
  card.querySelector(".step-next-btn").addEventListener("click", goToStep6);
}

function goToStep6() {
  state.currentStep = 6;
  updateProgressBar();
  var body = buildCommAreaHtml("Alice", "\u{1F469}", "alice", "Bob", "\u{1F9D1}", "bob") +
    "<button class='btn btn-primary step-next-btn' hidden>Next ▶</button>";
  var card = appendStepCard(6, "Send Ciphertext", body);
  var nextBtn = card.querySelector(".step-next-btn");
  nextBtn.addEventListener("click", goToStep7);
  animatePacket(card, false, function () {
    nextBtn.hidden = false;
  });
}

function goToStep7() {
  state.currentStep = 7;
  updateProgressBar();
  var results = rsaDecrypt(state.a2b.entries, state.bob.d, state.bob.n);
  var decryptedText = entriesToText(results, "decryptedChar");
  state.a2b.decrypted = decryptedText;

  var body = "<p>Bob uses his own private key (d = " + state.bob.d + ", n = " + state.bob.n +
    ") to reverse the encryption, one character at a time:</p>" +
    buildDecryptTableHtml(results, state.bob.d, state.bob.n) +
    buildVerifyBoxHtml(state.a2b.message, decryptedText) +
    "<button class='btn btn-primary step-next-btn'>Next ▶</button>";
  var card = appendStepCard(7, "Bob Decrypts", body);
  card.querySelector(".step-next-btn").addEventListener("click", goToStep8);
}


// ==========================================================================
// STEPS 8-11: BOB -> ALICE
// ==========================================================================

function goToStep8() {
  state.currentStep = 8;
  updateProgressBar();

  var flowHtml = buildFlowDiagramHtml(
    "Bob", "Alice",
    "Alice's PUBLIC key", "(" + state.alice.e + ", " + state.alice.n + ")",
    "Alice's PRIVATE key", "(" + state.alice.d + ", " + state.alice.n + ")"
  );
  var body = "<p><strong>Bob replies to Alice.</strong> This time Bob encrypts with " +
    "<em>Alice's public key</em> -- only Alice's private key can undo it.</p>" + flowHtml +
    "<div class='field-group'>" +
    "<label for='b2a-message'>Bob's message (A–Z and spaces only)</label>" +
    "<input type='text' id='b2a-message' value='HOW ARE YOU'>" +
    "<span class='field-error' id='b2a-message-error'></span>" +
    "</div>" +
    "<button class='btn btn-primary' id='b2aEncryptBtn'>Encrypt Message ▶</button>";

  var card = appendStepCard(8, "Bob → Alice", body);
  card.querySelector("#b2aEncryptBtn").addEventListener("click", onB2AEncryptClick);
}

function onB2AEncryptClick() {
  var rawText = $("b2a-message").value;
  var checked = validateMessageCharacters(rawText);
  if (!checked.ok) {
    $("b2a-message-error").textContent =
      "\"" + checked.errorChar + "\" is not allowed — only A–Z and spaces.";
    return;
  }
  var fitsCheck = checkMessageFitsModulus(checked.cleaned, state.alice.n);
  if (!fitsCheck.ok) {
    $("b2a-message-error").textContent =
      "'" + fitsCheck.offendingChar + "' maps to " + fitsCheck.offendingValue +
      ", which is not smaller than n = " + state.alice.n +
      ". The modulus is too small — use larger classroom primes for Alice.";
    return;
  }
  $("b2a-message-error").textContent = "";

  var entries = rsaEncrypt(checked.cleaned, state.alice.e, state.alice.n);
  state.b2a = { message: checked.cleaned, entries: entries };
  goToStep9();
}

function goToStep9() {
  state.currentStep = 9;
  updateProgressBar();
  var body = "<p>Each letter of \"" + state.b2a.message + "\" is converted to a number, " +
    "then raised to Alice's public exponent, modulo Alice's n:</p>" +
    buildEncryptTableHtml(state.b2a.entries, state.alice.e, state.alice.n) +
    "<button class='btn btn-primary step-next-btn'>Send Ciphertext ▶</button>";
  var card = appendStepCard(9, "Encrypt Bob's Message", body);
  card.querySelector(".step-next-btn").addEventListener("click", goToStep10);
}

function goToStep10() {
  state.currentStep = 10;
  updateProgressBar();
  var body = buildCommAreaHtml("Bob", "\u{1F9D1}", "bob", "Alice", "\u{1F469}", "alice") +
    "<button class='btn btn-primary step-next-btn' hidden>Next ▶</button>";
  var card = appendStepCard(10, "Send Ciphertext", body);
  var nextBtn = card.querySelector(".step-next-btn");
  nextBtn.addEventListener("click", goToStep11);
  animatePacket(card, true, function () {
    nextBtn.hidden = false;
  });
}

function goToStep11() {
  state.currentStep = 11;
  updateProgressBar();
  var results = rsaDecrypt(state.b2a.entries, state.alice.d, state.alice.n);
  var decryptedText = entriesToText(results, "decryptedChar");
  state.b2a.decrypted = decryptedText;

  var body = "<p>Alice uses her own private key (d = " + state.alice.d + ", n = " + state.alice.n +
    ") to reverse the encryption, one character at a time:</p>" +
    buildDecryptTableHtml(results, state.alice.d, state.alice.n) +
    buildVerifyBoxHtml(state.b2a.message, decryptedText) +
    "<button class='btn btn-primary step-next-btn'>Next ▶</button>";
  var card = appendStepCard(11, "Alice Decrypts", body);
  card.querySelector(".step-next-btn").addEventListener("click", goToStep12);
}


// ==========================================================================
// STEP 12: FINAL VERIFICATION SUMMARY
// ==========================================================================

function goToStep12() {
  state.currentStep = 12;
  updateProgressBar();

  var body = "<h4>Alice → Bob</h4>" +
    buildVerifyBoxHtml(state.a2b.message, state.a2b.decrypted) +
    "<h4>Bob → Alice</h4>" +
    buildVerifyBoxHtml(state.b2a.message, state.b2a.decrypted) +
    "<p>Experiment complete. Click <strong>Reset</strong> above to try different primes.</p>";

  appendStepCard(12, "Verification", body);
}


// ==========================================================================
// WIRE UP THE STEP 1 BUTTONS
// ==========================================================================

$("generateKeysBtn").addEventListener("click", onGenerateKeysClick);
$("resetBtn").addEventListener("click", resetLab);
$("loadSampleBtn").addEventListener("click", onLoadSampleClick);

updateProgressBar();
