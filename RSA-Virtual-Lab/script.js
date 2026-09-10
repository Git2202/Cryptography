// ==========================================================================
// RSA messenger — script.js
//
// Plain JavaScript, plain named functions only (no classes, no modules, no
// async, no arrow-function chains, no framework, no library). Every RSA
// function has a short comment above it saying what it does and what it
// returns. BigInt is used ONLY inside modPow -- everywhere else ordinary
// numbers are used, because the primes this lab is built for stay small
// enough that ordinary numbers represent them exactly.
//
// Algorithm used, and nothing else:
//   n = p * q
//   phi(n) = (p-1)(q-1)
//   e is typed by the user; must satisfy 1 < e < phi(n) and gcd(e, phi(n)) = 1
//   d found by trying d = 1, 2, 3, ... until (e * d) mod phi(n) = 1
//   Public key (e, n)   Private key (d, n)
//   C = M^e mod n       M = C^d mod n
//   Letters: A=0, B=1, ... Z=25, one letter per block
// No Carmichael/lambda, no padding, no hashing, no signatures, no extended
// Euclid, no CRT. p, q and e are always typed by the user, never generated.
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

// Finds the private exponent d by brute force: try d = 1, then d = 2, and
// so on, stopping as soon as (e * d) mod phi equals 1. Deliberately the
// simple, obvious search, not the extended Euclidean algorithm.
// Returns the whole number d, or null if none exists in range (this should
// never actually happen once e has passed the gcd check, but the search is
// still bounded and can fail cleanly rather than loop forever).
function calculateD(e, phi) {
  for (var d = 1; d < phi; d = d + 1) {
    if ((e * d) % phi === 1) {
      return d;
    }
  }
  return null;
}

// Computes (base ^ exponent) mod modulus, using the "square-and-multiply"
// method (repeated squaring), which needs only about log2(exponent)
// multiplications instead of doing "exponent" multiplications one at a time.
//
// This is the ONE function on this page that uses BigInt. While working
// through the exponent bit by bit, the numbers being squared can briefly
// get larger than an ordinary JavaScript number can hold exactly (ordinary
// numbers are only exact up to 2^53); BigInt has no such limit. Math.pow
// and the ** operator both compute in floating point, which would round a
// large result instead of giving the exact whole-number remainder that
// cryptography needs, so neither is used here.
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
      result = (result * b) % m; // the lowest bit left is 1: multiply it in
    }
    b = (b * b) % m; // square the base, ready for the next bit
    e = e / 2n; // BigInt division drops the remainder -- moves to the next bit
  }

  return Number(result);
}

// Converts one uppercase letter A-Z into its number 0-25 (A=0, B=1, ...
// Z=25). Returns null for a space, since a space is never turned into a
// number -- it travels the wire untouched instead.
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

// Turns a whole message into one entry per character, ready for
// encryption. message must already be uppercase A-Z and spaces only.
// Returns an array of { char, isSpace, num } -- num is 0-25 for a letter,
// or null for a space.
function textToNumbers(message) {
  var entries = [];
  for (var i = 0; i < message.length; i = i + 1) {
    var ch = message.charAt(i);
    if (ch === " ") {
      entries.push({ char: ch, isSpace: true, num: null });
    } else {
      entries.push({ char: ch, isSpace: false, num: charToNum(ch) });
    }
  }
  return entries;
}

// Joins an array of entries (from textToNumbers or decryptMessage) back
// into a plain text string, reading the given field name on each entry.
// Returns a string.
function numbersToText(entries, field) {
  var text = "";
  for (var i = 0; i < entries.length; i = i + 1) {
    text = text + entries[i][field];
  }
  return text;
}

// Encrypts a list of number-entries (from textToNumbers) with a public key
// (e, n). Returns a new array of { char, isSpace, num, cipher } -- cipher
// is num^e mod n for a letter, or null for a space (spaces are never
// encrypted).
function encryptMessage(numberEntries, e, n) {
  var results = [];
  for (var i = 0; i < numberEntries.length; i = i + 1) {
    var entry = numberEntries[i];
    if (entry.isSpace) {
      results.push({ char: entry.char, isSpace: true, num: null, cipher: null });
    } else {
      var cipher = modPow(entry.num, e, n);
      results.push({ char: entry.char, isSpace: false, num: entry.num, cipher: cipher });
    }
  }
  return results;
}

// Decrypts a list of received blocks (matching encryptMessage's output
// shape) with a private key (d, n). Returns a new array of
// { isSpace, cipher, num, char } -- char is the recovered letter, or a
// space passed straight through.
function decryptMessage(cipherEntries, d, n) {
  var results = [];
  for (var i = 0; i < cipherEntries.length; i = i + 1) {
    var entry = cipherEntries[i];
    if (entry.isSpace) {
      results.push({ isSpace: true, cipher: null, num: null, char: " " });
    } else {
      var num = modPow(entry.cipher, d, n);
      results.push({ isSpace: false, cipher: entry.cipher, num: num, char: numToChar(num) });
    }
  }
  return results;
}


// ==========================================================================
// VALIDATION
// ==========================================================================

function isValidNonNegativeInteger(text) {
  if (text.length === 0) {
    return false;
  }
  return /^[0-9]+$/.test(text);
}

// Validates one party's three input fields (p, q, e) and, if they're all
// valid, computes n, phi(n) and d for them. prefix is "alice" or "bob".
// Returns { ok, p, q, e, n, phi, d, errors: {p,q,e}, partyError }.
// partyError holds a message that isn't about one single field (currently
// just "n is too small"); errors.* hold per-field messages. Both are ""
// when there's no problem.
function validateParty(prefix) {
  var pText = document.getElementById(prefix + "-p").value.trim();
  var qText = document.getElementById(prefix + "-q").value.trim();
  var eText = document.getElementById(prefix + "-e").value.trim();

  var result = {
    ok: true,
    p: null, q: null, e: null, n: null, phi: null, d: null,
    errors: { p: "", q: "", e: "" },
    partyError: ""
  };

  if (!isValidNonNegativeInteger(pText)) {
    result.errors.p = "p must be a whole number.";
    result.ok = false;
  } else {
    var pValue = parseInt(pText, 10);
    if (!isPrime(pValue)) {
      result.errors.p = "p must be prime.";
      result.ok = false;
    } else {
      result.p = pValue;
    }
  }

  if (!isValidNonNegativeInteger(qText)) {
    result.errors.q = "q must be a whole number.";
    result.ok = false;
  } else {
    var qValue = parseInt(qText, 10);
    if (!isPrime(qValue)) {
      result.errors.q = "q must be prime.";
      result.ok = false;
    } else {
      result.q = qValue;
    }
  }

  if (result.p !== null && result.q !== null && result.p === result.q) {
    result.errors.q = "q must be different from p.";
    result.ok = false;
    result.q = null;
  }

  if (result.p === null || result.q === null) {
    return result;
  }

  var n = result.p * result.q;
  var phi = (result.p - 1) * (result.q - 1);
  result.n = n;
  result.phi = phi;

  if (n <= 25) {
    result.partyError = "n = " + n + " is too small to hold every letter (need n > 25). Choose larger primes.";
    result.ok = false;
  }

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
    result.errors.e = "gcd(e, phi(n)) = " + eGcd + ", must be 1.";
    result.ok = false;
    return result;
  }
  result.e = eValue;
  result.d = calculateD(eValue, phi);

  return result;
}

// Checks that a typed message contains only uppercase letters A-Z and
// spaces (the text is uppercased first). Returns { ok, cleaned, badChar }.
function validateMessageCharacters(rawText) {
  var cleaned = rawText.toUpperCase();
  for (var i = 0; i < cleaned.length; i = i + 1) {
    var ch = cleaned.charAt(i);
    var isLetter = ch >= "A" && ch <= "Z";
    if (!isLetter && ch !== " ") {
      return { ok: false, cleaned: cleaned, badChar: ch };
    }
  }
  return { ok: true, cleaned: cleaned, badChar: null };
}


// ==========================================================================
// TINY HELPERS
// ==========================================================================

function $(id) {
  return document.getElementById(id);
}

function otherParty(prefix) {
  return prefix === "alice" ? "bob" : "alice";
}

function partyName(prefix) {
  return prefix === "alice" ? "Alice" : "Bob";
}

// Formats a Date as a 24-hour "HH:MM" clock reading. Returns a string.
function formatClockTime(date) {
  var hours = date.getHours();
  var minutes = date.getMinutes();
  var hoursText = hours < 10 ? "0" + hours : String(hours);
  var minutesText = minutes < 10 ? "0" + minutes : String(minutes);
  return hoursText + ":" + minutesText;
}

// Joins a list of entries into a comma-separated display line, e.g.
// "7, 4, 11, 11, 14", showing "␣" (a visible open-box mark) for each
// space entry. Returns a string.
function formatSequenceCommas(entries, field) {
  var parts = [];
  for (var i = 0; i < entries.length; i = i + 1) {
    var entry = entries[i];
    parts.push(entry.isSpace ? "␣" : String(entry[field]));
  }
  return parts.join(", ");
}

// Same idea as formatSequenceCommas, but space-separated with no commas,
// for the wire strip's wide letter-spaced display. Returns a string.
function formatSequenceSpaced(entries, field) {
  var parts = [];
  for (var i = 0; i < entries.length; i = i + 1) {
    var entry = entries[i];
    parts.push(entry.isSpace ? "␣" : String(entry[field]));
  }
  return parts.join("  ");
}

// Counts how many entries are real letters (not spaces) -- this is what
// "N blocks" means in the activity log and the encrypting-preview note,
// since spaces are never encrypted and so are never a block.
function countBlocks(entries) {
  var count = 0;
  for (var i = 0; i < entries.length; i = i + 1) {
    if (!entries[i].isSpace) {
      count = count + 1;
    }
  }
  return count;
}


// ==========================================================================
// STATE
// ==========================================================================

var state = {
  alice: null,
  bob: null,
  sendAs: "alice",
  hasMessages: false
};


// ==========================================================================
// RENDERING: KEYS PANEL
// ==========================================================================

// Updates one party's "working" block and public/private key rows to match
// their current (already-validated) key data, or shows a placeholder if
// their inputs aren't valid yet. Does not return anything.
function renderKeys(prefix, party) {
  var workingEl = $(prefix + "-working");
  var keysEl = $(prefix + "-keys");

  if (party.ok) {
    workingEl.className = "working-block mono";
    workingEl.textContent =
      "n = " + party.p + " × " + party.q + " = " + party.n + "\n" +
      "φ(n) = " + (party.p - 1) + " × " + (party.q - 1) + " = " + party.phi + "\n" +
      "d = " + party.d + " (" + party.e + "·" + party.d + " ≡ 1 mod " + party.phi + ")";

    keysEl.innerHTML =
      "<div class='key-row public'>&#128275; <span class='key-label'>public key (e, n)</span>" +
      "<span class='key-value'>(" + party.e + ", " + party.n + ")</span></div>" +
      "<div class='key-row private'>&#128274; <span class='key-label'>private key (d, n)</span>" +
      "<span class='key-value'>(" + party.d + ", " + party.n + ")</span></div>";
  } else {
    workingEl.className = "working-block mono placeholder";
    workingEl.textContent = "Enter valid p, q and e above to see the working.";
    keysEl.innerHTML = "";
  }
}

function showFieldErrors(prefix, errors) {
  $(prefix + "-p-error").textContent = errors.p;
  $(prefix + "-q-error").textContent = errors.q;
  $(prefix + "-e-error").textContent = errors.e;
}

function showPartyError(prefix, message) {
  var el = $(prefix + "-party-error");
  if (message) {
    el.textContent = message;
    el.classList.add("visible");
  } else {
    el.textContent = "";
    el.classList.remove("visible");
  }
}


// ==========================================================================
// RENDERING: ENCRYPTING-FOR PREVIEW AND COMPOSER HINT
// ==========================================================================

// Rebuilds the "Encrypting for ..." preview box in one party's panel.
// Only the panel belonging to the current sender shows live numbers; the
// other panel shows a placeholder. Does not return anything.
function renderEncryptingPreview(prefix) {
  var box = $(prefix + "-encrypting-preview");

  if (prefix !== state.sendAs) {
    box.className = "encrypting-body mono placeholder";
    box.textContent = "Not currently sending — switch \"Send as\" below to preview.";
    return;
  }

  var composerText = $("composerInput").value.toUpperCase();
  if (composerText.length === 0) {
    box.className = "encrypting-body mono placeholder";
    box.textContent = "Type a message below to preview encryption.";
    return;
  }

  var receiverPrefix = otherParty(prefix);
  var receiverParty = state[receiverPrefix];
  if (!receiverParty || !receiverParty.ok) {
    box.className = "encrypting-body mono placeholder";
    box.textContent = partyName(receiverPrefix) + "'s keys aren't valid yet.";
    return;
  }

  var firstChar = composerText.charAt(0);
  if (firstChar === " ") {
    box.className = "encrypting-body mono";
    box.textContent = "(space) → travels the wire unencrypted";
    return;
  }
  if (!(firstChar >= "A" && firstChar <= "Z")) {
    box.className = "encrypting-body mono placeholder";
    box.textContent = "'" + firstChar + "' isn't a letter A–Z.";
    return;
  }

  var num = charToNum(firstChar);
  var cipher = modPow(num, receiverParty.e, receiverParty.n);
  box.className = "encrypting-body mono";
  box.textContent = firstChar + " → " + num + "\n" +
    num + "^" + receiverParty.e + " mod " + receiverParty.n + " = " + cipher;
}

function updateEncryptingPreviews() {
  renderEncryptingPreview("alice");
  renderEncryptingPreview("bob");
}

// Updates the composer's muted hint line to describe whose public key the
// next message will be encrypted with. Does not return anything.
function updateComposerHint() {
  var receiverPrefix = otherParty(state.sendAs);
  var receiverParty = state[receiverPrefix];
  var hintEl = $("composerHint");
  if (receiverParty && receiverParty.ok) {
    hintEl.textContent = "encrypts with " + partyName(receiverPrefix) + "'s public key (" +
      receiverParty.e + ", " + receiverParty.n + ")";
  } else {
    hintEl.textContent = partyName(receiverPrefix) + "'s keys aren't valid yet.";
  }
}

function updateSendButtonState() {
  var bothValid = state.alice && state.bob && state.alice.ok && state.bob.ok;
  $("sendBtn").disabled = !bothValid;
}


// ==========================================================================
// CONVERSATION: CLEARING
// ==========================================================================

function showEmptyConversation() {
  var container = $("conversationMessages");
  container.innerHTML = "";
  var p = document.createElement("p");
  p.className = "conversation-empty";
  p.id = "conversationEmpty";
  p.textContent = "No messages yet — send one below.";
  container.appendChild(p);
  state.hasMessages = false;
}

function showConversationClearedByKeyChange() {
  var container = $("conversationMessages");
  container.innerHTML = "";
  var note = document.createElement("p");
  note.className = "keys-changed-note";
  note.textContent = "Keys changed — conversation cleared so it can never disagree with the panels above.";
  container.appendChild(note);
  state.hasMessages = false;
}


// ==========================================================================
// CONVERSATION: BUILDING ONE MESSAGE EXCHANGE'S DOM
// ==========================================================================

// Builds the three DOM pieces for one message exchange (sender bubble,
// wire strip, receiver bubble), fully filled in from the already-computed
// exchange data -- this function only displays numbers, it never
// calculates any. Returns { senderRow, wireStrip, receiverRow }, none of
// them attached to the page yet (animateSend inserts them in order).
function renderMessage(exchange) {
  var senderTintClass = exchange.senderPrefix === "alice" ? "alice-tint" : "bob-tint";
  var receiverTintClass = exchange.receiverPrefix === "alice" ? "alice-tint" : "bob-tint";
  var senderAlignClass = exchange.senderPrefix === "alice" ? "align-left" : "align-right";
  var receiverAlignClass = exchange.receiverPrefix === "alice" ? "align-left" : "align-right";

  var mLine = formatSequenceCommas(exchange.numberEntries, "num");
  var cFormula = "C = M^" + exchange.receiverPublicE + " mod " + exchange.n;
  var senderRow = document.createElement("div");
  senderRow.className = "message-row " + senderAlignClass;
  senderRow.innerHTML =
    "<div class='bubble sender " + senderTintClass + "'>" +
    "<div class='bubble-plaintext'>" + exchange.plaintext + "</div>" +
    "<div class='bubble-working mono'>M = " + mLine + "</div>" +
    "<div class='bubble-working mono'>" + cFormula + "</div>" +
    "<div class='bubble-with'>with " + exchange.receiverName + "'s public key</div>" +
    "<div class='bubble-caption'>sent " + exchange.time + ", encrypted for " + exchange.receiverName + "</div>" +
    "</div>";

  var wireStrip = document.createElement("div");
  wireStrip.className = "wire-strip";
  var travelClass = exchange.senderPrefix === "alice" ? "travel-ltr" : "travel-rtl";
  var cLine = formatSequenceSpaced(exchange.cipherEntries, "cipher");
  wireStrip.innerHTML =
    "<span class='wire-lock'>&#128274;</span>" +
    "<span class='wire-label'>on the wire</span>" +
    "<span class='wire-blocks mono " + travelClass + "'>" + cLine + "</span>" +
    "<span class='wire-destination'>→ " + exchange.receiverName + "</span>";

  var mFormula = "M = C^" + exchange.receiverPrivateD + " mod " + exchange.n;
  var recoveredLine = formatSequenceCommas(exchange.decryptedEntries, "num");
  var receiverRow = document.createElement("div");
  receiverRow.className = "message-row " + receiverAlignClass;
  receiverRow.innerHTML =
    "<div class='bubble receiver " + receiverTintClass + "'>" +
    "<div class='bubble-working mono'>" + mFormula + "</div>" +
    "<div class='bubble-with'>with " + exchange.receiverName + "'s private key</div>" +
    "<div class='bubble-working mono'>= " + recoveredLine + "</div>" +
    "<div class='bubble-plaintext'>" + exchange.decryptedText + "</div>" +
    "<div class='bubble-caption'>decrypted by " + exchange.receiverName + "</div>" +
    "</div>";

  return { senderRow: senderRow, wireStrip: wireStrip, receiverRow: receiverRow };
}


// ==========================================================================
// CONVERSATION: THE SEND ANIMATION
// ==========================================================================

// How long each stage of the send animation takes, in milliseconds. These
// match the CSS transition/animation durations in style.css (bubbleIn,
// the wire-blocks transition, and avatarPulse) so the JS timers and the
// CSS animations they're driving stay in step.
var BUBBLE_FADE_MS = 350;
var WIRE_TRAVEL_MS = 900;
var AVATAR_PULSE_MS = 600;
var SHORT_PAUSE_MS = 150;

// Plays the full send sequence for one message exchange: the sender
// bubble fades in, then the wire strip appears and its ciphertext blocks
// travel across, then the receiving avatar pulses, then the receiver
// bubble fades in with the decrypted result. Also writes both parties'
// activity log entries and keeps the conversation scrolled to the newest
// message. Uses CSS transitions/animations plus setTimeout only -- no
// promises, no async/await. Does not return anything.
function animateSend(exchange) {
  var conversationMessages = $("conversationMessages");
  var emptyMsg = $("conversationEmpty");
  if (emptyMsg) {
    emptyMsg.remove();
  }
  state.hasMessages = true;

  var pieces = renderMessage(exchange);

  conversationMessages.appendChild(pieces.senderRow);
  pieces.senderRow.scrollIntoView({ behavior: "smooth", block: "end" });
  addActivityEntry(exchange.senderPrefix, "sent", exchange.plaintext, countBlocks(exchange.numberEntries));

  setTimeout(function afterSenderBubble() {
    conversationMessages.appendChild(pieces.wireStrip);
    pieces.wireStrip.scrollIntoView({ behavior: "smooth", block: "end" });

    var blocksEl = pieces.wireStrip.querySelector(".wire-blocks");
    // Force the browser to paint the pre-travel position before switching
    // on the "arrived" class -- otherwise it can jump straight to the end
    // position with no visible movement at all.
    void blocksEl.offsetWidth;
    blocksEl.classList.add("arrived");

    setTimeout(function afterWireTravel() {
      var receiverAvatar = document.querySelector("#" + exchange.receiverPrefix + "Panel .avatar");
      receiverAvatar.classList.add("receiving");
      setTimeout(function stopPulse() {
        receiverAvatar.classList.remove("receiving");
      }, AVATAR_PULSE_MS);

      setTimeout(function afterPulseStarts() {
        conversationMessages.appendChild(pieces.receiverRow);
        pieces.receiverRow.scrollIntoView({ behavior: "smooth", block: "end" });
        addActivityEntry(exchange.receiverPrefix, "read", exchange.decryptedText, countBlocks(exchange.numberEntries));
      }, SHORT_PAUSE_MS);
    }, WIRE_TRAVEL_MS + SHORT_PAUSE_MS);
  }, BUBBLE_FADE_MS + SHORT_PAUSE_MS);
}

function addActivityEntry(prefix, verb, text, blockCount) {
  var time = formatClockTime(new Date());
  var li = document.createElement("li");
  var blockWord = blockCount === 1 ? "block" : "blocks";
  li.textContent = time + " " + verb + " " + text + ", " + blockCount + " " + blockWord;
  var log = $(prefix + "-activity");
  log.appendChild(li);
  log.scrollTop = log.scrollHeight;
}


// ==========================================================================
// EVENT HANDLERS
// ==========================================================================

function onPartyInputChange(prefix) {
  var party = validateParty(prefix);
  state[prefix] = party;

  showFieldErrors(prefix, party.errors);
  showPartyError(prefix, party.partyError);
  renderKeys(prefix, party);
  updateComposerHint();
  updateEncryptingPreviews();
  updateSendButtonState();

  if (state.hasMessages) {
    showConversationClearedByKeyChange();
  }
}

function onSendAsChange(prefix) {
  state.sendAs = prefix;
  var buttons = document.querySelectorAll(".send-as-btn");
  for (var i = 0; i < buttons.length; i = i + 1) {
    var btn = buttons[i];
    if (btn.getAttribute("data-party") === prefix) {
      btn.classList.add("active");
    } else {
      btn.classList.remove("active");
    }
  }
  updateComposerHint();
  updateEncryptingPreviews();
}

function onComposerInput() {
  updateEncryptingPreviews();
}

function onSendClick() {
  var senderPrefix = state.sendAs;
  var receiverPrefix = otherParty(senderPrefix);
  var senderParty = state[senderPrefix];
  var receiverParty = state[receiverPrefix];

  if (!senderParty || !senderParty.ok || !receiverParty || !receiverParty.ok) {
    $("composerError").textContent = "Fix both parties' keys before sending.";
    return;
  }

  var raw = $("composerInput").value;
  var checked = validateMessageCharacters(raw);
  if (!checked.ok) {
    $("composerError").textContent = "\"" + checked.badChar + "\" is not allowed — only A–Z and spaces.";
    return;
  }
  if (checked.cleaned.trim().length === 0) {
    $("composerError").textContent = "Type a message first.";
    return;
  }

  $("composerError").textContent = "";

  var numberEntries = textToNumbers(checked.cleaned);
  var cipherEntries = encryptMessage(numberEntries, receiverParty.e, receiverParty.n);
  var decryptedEntries = decryptMessage(cipherEntries, receiverParty.d, receiverParty.n);
  var decryptedText = numbersToText(decryptedEntries, "char");

  var exchange = {
    senderPrefix: senderPrefix,
    receiverPrefix: receiverPrefix,
    senderName: partyName(senderPrefix),
    receiverName: partyName(receiverPrefix),
    plaintext: checked.cleaned,
    numberEntries: numberEntries,
    cipherEntries: cipherEntries,
    decryptedEntries: decryptedEntries,
    decryptedText: decryptedText,
    n: receiverParty.n,
    receiverPublicE: receiverParty.e,
    receiverPrivateD: receiverParty.d,
    time: formatClockTime(new Date())
  };

  animateSend(exchange);
  $("composerInput").value = "";
  updateEncryptingPreviews();
}

function onShowWorkingToggle() {
  var container = $("conversationMessages");
  if ($("showWorkingToggle").checked) {
    container.classList.remove("hide-working");
  } else {
    container.classList.add("hide-working");
  }
}

function onClearClick() {
  showEmptyConversation();
}


// ==========================================================================
// WIRE UP THE PAGE
// ==========================================================================

var PARTY_INPUT_IDS = [
  "alice-p", "alice-q", "alice-e",
  "bob-p", "bob-q", "bob-e"
];

for (var i = 0; i < PARTY_INPUT_IDS.length; i = i + 1) {
  var inputId = PARTY_INPUT_IDS[i];
  var prefixForInput = inputId.indexOf("alice") === 0 ? "alice" : "bob";
  (function attachListener(id, prefix) {
    $(id).addEventListener("input", function () {
      onPartyInputChange(prefix);
    });
  })(inputId, prefixForInput);
}

var sendAsButtons = document.querySelectorAll(".send-as-btn");
for (var j = 0; j < sendAsButtons.length; j = j + 1) {
  (function attachSendAsListener(btn) {
    btn.addEventListener("click", function () {
      onSendAsChange(btn.getAttribute("data-party"));
    });
  })(sendAsButtons[j]);
}

$("composerInput").addEventListener("input", onComposerInput);
$("sendBtn").addEventListener("click", onSendClick);
$("showWorkingToggle").addEventListener("change", onShowWorkingToggle);
$("clearBtn").addEventListener("click", onClearClick);

onPartyInputChange("alice");
onPartyInputChange("bob");
