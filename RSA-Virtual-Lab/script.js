// ==========================================================================
// RSA Cryptography Virtual Laboratory — script.js
//
// Plain JavaScript, plain functions only (no classes, no modules). Every
// function has a short comment above it saying what it does and what it
// returns. BigInt is used ONLY inside modPow — everywhere else we use
// ordinary JavaScript numbers, because these are small "classroom" primes
// and ordinary numbers are exact and simpler to read for every other
// calculation on this page.
// ==========================================================================


// ---- ORDER OF THE BOXES IN EACH FLOW DIAGRAM ----------------------------
// Used by highlightBox() below to know which boxes come "before" which.

var KEYGEN_BOX_ORDER = ["kgBox1", "kgBox2", "kgBox3", "kgBox4", "kgBox5"];
var MESSAGE_BOX_ORDER = ["mfBox1", "mfBox2", "mfBox3", "mfBox4", "mfBox5"];


// ==========================================================================
// BASIC MATH FUNCTIONS
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

// Finds the modular inverse of "a" under modulus "m": the whole number x,
// between 0 and m-1, such that (a * x) mod m equals 1. This is what turns
// the public exponent e into the private exponent d.
//
// It uses the extended Euclidean algorithm. Alongside the normal Euclidean
// algorithm's remainders (r), it also tracks a second running number (s).
// By the time the remainder reaches 1, that matching "s" value is exactly
// the answer we want -- this is a standard result, not something derived
// on this page, so this function just runs the bookkeeping.
//
// Returns an object: { value: <the inverse, or null if none exists>,
// steps: <an array of rows so the page can display the working> }.
function modInverse(a, m) {
  var oldR = a;
  var r = m;
  var oldS = 1;
  var s = 0;

  var steps = [];
  steps.push({ r: oldR, quotient: null, s: oldS });

  while (r !== 0) {
    var quotient = Math.floor(oldR / r);

    // Move the algorithm forward one step: the new remainder is what's
    // left over after dividing oldR by r as many times as possible.
    var newR = oldR - quotient * r;
    oldR = r;
    r = newR;

    // Track the matching "s" coefficient the same way, one step behind
    // the remainder above -- this is the part that lets us read off the
    // inverse at the end instead of just the gcd.
    var newS = oldS - quotient * s;
    oldS = s;
    s = newS;

    // The quotient we just used belongs to the PREVIOUS row (it's what
    // produced this new row), so fill it in on the row before this one.
    steps[steps.length - 1].quotient = quotient;
    steps.push({ r: oldR, quotient: null, s: oldS });
  }

  if (oldR !== 1) {
    // The final remainder (the gcd of a and m) is not 1, so a and m share
    // a common factor and no inverse exists.
    return { value: null, steps: steps };
  }

  // oldS is the answer, but it can come out negative (e.g. -13). Adding m
  // to it brings it into the normal range [0, m) without changing what it
  // means modulo m.
  var inverse = oldS % m;
  if (inverse < 0) {
    inverse = inverse + m;
  }
  return { value: inverse, steps: steps };
}

// Computes (base ^ exponent) mod modulus, using the "square-and-multiply"
// method, which needs only about log2(exponent) multiplications instead of
// doing "exponent" multiplications one at a time.
//
// This is the ONE place on this page that uses BigInt. Two reasons:
//   1. While working through the exponent bit by bit, the numbers being
//      squared can briefly get larger than a normal JavaScript number can
//      hold exactly (normal numbers are only exact up to 2^53). BigInt has
//      no such limit.
//   2. JavaScript's Math.pow(base, exponent) computes in floating point,
//      which rounds large results instead of giving an exact whole-number
//      answer -- unusable for cryptography, where the exact remainder is
//      the entire point.
// BigInt values are converted from normal numbers right at the start of
// this function, and the final BigInt result is converted back to a
// normal number right before returning, so the rest of the program never
// has to deal with BigInt at all. (BigInt and normal numbers cannot be
// mixed in the same calculation -- JavaScript throws an error if you try
// -- which is exactly why the conversion happens at the boundary here.)
function modPow(base, exponent, modulus) {
  var result = 1n;
  var b = BigInt(base) % BigInt(modulus);
  var e = BigInt(exponent);
  var m = BigInt(modulus);

  while (e > 0n) {
    if (e % 2n === 1n) {
      // The current lowest bit of the exponent is 1, so multiply this
      // power of the base into the running result.
      result = (result * b) % m;
    }
    b = (b * b) % m; // square the base, ready for the next bit
    e = e / 2n; // BigInt division drops the remainder, same as moving to the next bit
  }

  return Number(result);
}

// Searches for a valid public exponent e: a whole number with
// 1 < e < phi, and gcd(e, phi) equal to 1 (sharing no common factor with
// phi). Tries e = 2, 3, 4, ... in order and stops at the first one that
// works, recording every value it tried along the way.
// Returns an object: { value: <the chosen e, or null if none exists>,
// candidates: <an array of every e tried, with its gcd and whether it
// was accepted> }.
function findPublicExponent(phi) {
  var candidates = [];
  for (var e = 2; e < phi; e = e + 1) {
    var gcdValue = gcd(e, phi);
    var isValid = (gcdValue === 1);
    candidates.push({ value: e, gcdValue: gcdValue, isValid: isValid });
    if (isValid) {
      return { value: e, candidates: candidates };
    }
  }
  return { value: null, candidates: candidates };
}


// ==========================================================================
// READING AND VALIDATING THE INPUT FIELDS
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

// Reads every input field, checks it, and works out whether the page has
// enough valid information to run the RSA demonstration. Every problem
// found is recorded against the specific field it belongs to, so the page
// can show each message next to the field it's about (never a popup).
//
// Returns an object: { ok: true/false, p, q, m, eOverride, errors }.
// p, q, m and eOverride are the parsed numbers where valid, or null where
// not. errors.p / errors.q / errors.m / errors.e are the message strings
// to display (empty string means "no problem with this field").
function validateInputs() {
  var pText = document.getElementById("inputP").value.trim();
  var qText = document.getElementById("inputQ").value.trim();
  var mText = document.getElementById("inputM").value.trim();
  var eText = document.getElementById("inputE").value.trim();

  var result = {
    ok: true,
    p: null,
    q: null,
    m: null,
    eOverride: null,
    errors: { p: "", q: "", m: "", e: "" }
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

  // --- p and q must not be so small that no public exponent can exist ---
  // phi(n) = (p-1)(q-1) needs to be at least 3 for the range 1 < e < phi
  // to contain any whole number at all. (The only prime pair this ever
  // rejects is p=2 with q=3, or the other way round.)
  if (result.p !== null && result.q !== null) {
    var previewPhi = (result.p - 1) * (result.q - 1);
    if (previewPhi < 3) {
      result.errors.q =
        "p and q are too small: phi(n) would be " + previewPhi +
        ", leaving no valid public exponent. Choose larger primes.";
      result.ok = false;
      result.p = null;
      result.q = null;
    }
  }

  // --- M ---
  if (!isValidNonNegativeInteger(mText)) {
    result.errors.m = "M must be a non-negative whole number.";
    result.ok = false;
  } else {
    var mValue = parseInt(mText, 10);
    if (result.p !== null && result.q !== null) {
      var previewN = result.p * result.q;
      if (mValue >= previewN) {
        result.errors.m =
          "M must be smaller than n (M = " + mValue + ", n = " + previewN +
          "). The message must be smaller than the modulus.";
        result.ok = false;
      } else {
        result.m = mValue;
      }
    } else {
      // p or q is invalid, so we can't check M against n yet, but M itself
      // is at least a valid whole number.
      result.m = mValue;
    }
  }

  // --- optional custom e ---
  if (eText.length > 0) {
    if (!isValidNonNegativeInteger(eText)) {
      result.errors.e = "e must be a whole number.";
      result.ok = false;
    } else if (result.p === null || result.q === null) {
      result.errors.e = "fix p and q first, then choose a custom e.";
      result.ok = false;
    } else {
      var eValue = parseInt(eText, 10);
      var phiForE = (result.p - 1) * (result.q - 1);
      if (eValue <= 1 || eValue >= phiForE) {
        result.errors.e =
          "e must satisfy 1 < e < phi(n) (phi(n) = " + phiForE + ").";
        result.ok = false;
      } else if (gcd(eValue, phiForE) !== 1) {
        result.errors.e =
          "e must share no common factor with phi(n) = " + phiForE +
          " (gcd(e, phi(n)) must be 1).";
        result.ok = false;
      } else {
        result.eOverride = eValue;
      }
    }
  }

  return result;
}

// Puts the error messages from validateInputs() onto the page, next to
// each field. Does not return anything.
function showFieldErrors(errors) {
  document.getElementById("errorP").textContent = errors.p;
  document.getElementById("errorQ").textContent = errors.q;
  document.getElementById("errorM").textContent = errors.m;
  document.getElementById("errorE").textContent = errors.e;
}


// ==========================================================================
// BUILDING THE RESULT CARDS
// ==========================================================================

// Builds one result-step card as an HTML element, ready to be added to the
// page. stepNumber and title go in the card's heading; bodyHtml is the
// card's main content (already-built HTML, since it's made only from
// numbers this page calculated itself, not from raw user text). extraClass
// adds a special colour (for the public/private key cards and the
// verification card). delayIndex controls how long this card waits before
// its fade-in animation starts, so cards appear one after another.
// Returns the new card element.
function createStepCard(stepNumber, title, bodyHtml, extraClass, delayIndex) {
  var card = document.createElement("div");
  card.className = "step-card";
  if (extraClass) {
    card.className = card.className + " " + extraClass;
  }
  card.style.animationDelay = (delayIndex * 0.12) + "s";

  var badge = document.createElement("div");
  badge.className = "step-badge";
  badge.textContent = "Step " + stepNumber;
  card.appendChild(badge);

  var heading = document.createElement("h3");
  heading.textContent = title;
  card.appendChild(heading);

  var body = document.createElement("div");
  body.innerHTML = bodyHtml;
  card.appendChild(body);

  return card;
}

// Builds the small HTML table listing every candidate e that was tried
// while looking for a public exponent, with its gcd against phi(n) and
// whether it was accepted. Returns an HTML string.
function buildCandidateTableHtml(candidates) {
  var html = "<table class='working-table'><tr><th>e tried</th><th>gcd(e, &phi;(n))</th><th>valid?</th></tr>";
  for (var i = 0; i < candidates.length; i = i + 1) {
    var row = candidates[i];
    var rowClass = row.isValid ? "row-valid" : "row-invalid";
    html = html + "<tr class='" + rowClass + "'><td>" + row.value + "</td><td>" +
      row.gcdValue + "</td><td>" + (row.isValid ? "yes" : "no") + "</td></tr>";
  }
  html = html + "</table>";
  return html;
}

// Builds the small HTML table showing the extended Euclidean algorithm's
// working while it searches for d. Returns an HTML string.
function buildEuclidTableHtml(steps) {
  var html = "<table class='working-table'><tr><th>r</th><th>quotient</th><th>s</th></tr>";
  for (var i = 0; i < steps.length; i = i + 1) {
    var row = steps[i];
    html = html + "<tr><td>" + row.r + "</td><td>" +
      (row.quotient === null ? "&mdash;" : row.quotient) + "</td><td>" + row.s + "</td></tr>";
  }
  html = html + "</table>";
  return html;
}


// ==========================================================================
// FLOW DIAGRAM HIGHLIGHTING
// ==========================================================================

// Marks one box in a flow diagram as the current ("active") stage, and
// every box before it in the given order as already completed ("done").
// orderList is one of KEYGEN_BOX_ORDER or MESSAGE_BOX_ORDER above.
// Does not return anything.
function highlightBox(orderList, activeBoxId) {
  var reachedActive = false;
  for (var i = 0; i < orderList.length; i = i + 1) {
    var boxElement = document.getElementById(orderList[i]);
    boxElement.classList.remove("active");
    boxElement.classList.remove("done");
    if (orderList[i] === activeBoxId) {
      boxElement.classList.add("active");
      reachedActive = true;
    } else if (!reachedActive) {
      boxElement.classList.add("done");
    }
  }
}

// Removes all highlighting from both flow diagrams, back to their starting
// (plain) state. Does not return anything.
function resetDiagrams() {
  var allBoxIds = KEYGEN_BOX_ORDER.concat(MESSAGE_BOX_ORDER);
  for (var i = 0; i < allBoxIds.length; i = i + 1) {
    var boxElement = document.getElementById(allBoxIds[i]);
    boxElement.classList.remove("active");
    boxElement.classList.remove("done");
  }
}


// ==========================================================================
// MAIN BUTTON ACTIONS
// ==========================================================================

// Runs the whole RSA demonstration: reads and validates the inputs, and
// if they're all valid, builds and shows every result card in order,
// updating the two flow diagrams as it goes. This is the click handler
// for the "Generate RSA" button. Does not return anything.
function generateRSA() {
  var resultsArea = document.getElementById("resultsArea");
  resultsArea.innerHTML = "";
  resetDiagrams();

  var inputs = validateInputs();
  showFieldErrors(inputs.errors);
  if (!inputs.ok) {
    return; // stop here -- no cards are shown until every input is valid
  }

  var p = inputs.p;
  var q = inputs.q;
  var m = inputs.m;

  // Show the progress bar and let its CSS transition animate it filling up.
  var progressTrack = document.getElementById("progressTrack");
  var progressFill = document.getElementById("progressFill");
  progressTrack.hidden = false;
  progressFill.classList.remove("filled");
  // Reading offsetWidth forces the browser to notice the class was removed
  // before we add it back, so the fill animation restarts every time this
  // button is clicked (otherwise a second click with no change would not
  // re-trigger the CSS transition).
  void progressFill.offsetWidth;
  progressFill.classList.add("filled");

  var stepNumber = 1;
  var delay = 0;

  // Step 1: confirm p and q passed validation.
  resultsArea.appendChild(createStepCard(
    stepNumber, "Validate p and q",
    "<p>p = <b>" + p + "</b> is prime. &#10003;</p>" +
    "<p>q = <b>" + q + "</b> is prime. &#10003;</p>" +
    "<p>p and q are different. &#10003;</p>",
    "", delay
  ));
  stepNumber = stepNumber + 1;
  delay = delay + 1;
  highlightBox(KEYGEN_BOX_ORDER, "kgBox1");

  // Step 2: n = p * q
  var n = p * q;
  resultsArea.appendChild(createStepCard(
    stepNumber, "Compute the modulus n",
    "<p class='formula'>n = p &times; q</p>" +
    "<p class='formula-sub'>n = " + p + " &times; " + q + " = <b>" + n + "</b></p>",
    "", delay
  ));
  stepNumber = stepNumber + 1;
  delay = delay + 1;

  // Step 3: phi(n) = (p-1)(q-1)
  var phi = (p - 1) * (q - 1);
  resultsArea.appendChild(createStepCard(
    stepNumber, "Compute φ(n)",
    "<p class='formula'>&phi;(n) = (p &minus; 1)(q &minus; 1)</p>" +
    "<p class='formula-sub'>&phi;(n) = (" + p + " &minus; 1)(" + q + " &minus; 1) = " +
    (p - 1) + " &times; " + (q - 1) + " = <b>" + phi + "</b></p>",
    "", delay
  ));
  stepNumber = stepNumber + 1;
  delay = delay + 1;
  highlightBox(KEYGEN_BOX_ORDER, "kgBox2");

  // Step 4: choose e (auto-search, or use the caller's override).
  var ePick;
  if (inputs.eOverride !== null) {
    ePick = {
      value: inputs.eOverride,
      candidates: [{ value: inputs.eOverride, gcdValue: 1, isValid: true }]
    };
  } else {
    ePick = findPublicExponent(phi);
  }
  // ePick.value cannot be null here, because validateInputs() already
  // rejected any p/q pair small enough for that to happen -- but the check
  // stays in as a safety net rather than assuming that reasoning holds
  // forever if this code is ever changed.
  if (ePick.value === null) {
    document.getElementById("errorE").textContent =
      "No valid public exponent e exists for phi(n) = " + phi + ".";
    progressTrack.hidden = true;
    return;
  }
  var e = ePick.value;
  var eNote = inputs.eOverride !== null ? " (chosen by you)" : "";
  resultsArea.appendChild(createStepCard(
    stepNumber, "Choose the public exponent e",
    "<p class='formula'>1 &lt; e &lt; &phi;(n) and gcd(e, &phi;(n)) = 1</p>" +
    buildCandidateTableHtml(ePick.candidates) +
    "<p>Chosen e = <b>" + e + "</b>" + eNote + "</p>",
    "", delay
  ));
  stepNumber = stepNumber + 1;
  delay = delay + 1;
  highlightBox(KEYGEN_BOX_ORDER, "kgBox3");

  // Step 5: find d, the modular inverse of e mod phi(n).
  var dResult = modInverse(e, phi);
  var d = dResult.value;
  var check = (d * e) % phi;
  resultsArea.appendChild(createStepCard(
    stepNumber, "Find the private exponent d",
    "<p class='formula'>(d &times; e) mod &phi;(n) = 1</p>" +
    buildEuclidTableHtml(dResult.steps) +
    "<p>d = <b>" + d + "</b> &nbsp; (check: " + d + " &times; " + e + " mod " + phi + " = " + check + ")</p>",
    "", delay
  ));
  stepNumber = stepNumber + 1;
  delay = delay + 1;
  highlightBox(KEYGEN_BOX_ORDER, "kgBox4");

  // Step 6: public key card.
  resultsArea.appendChild(createStepCard(
    stepNumber, "Public Key",
    "<p class='key-display'>(e, n) = (" + e + ", " + n + ")</p>" +
    "<p class='key-note'>This pair can be shared with anyone.</p>",
    "public-key-card", delay
  ));
  stepNumber = stepNumber + 1;
  delay = delay + 1;

  // Step 7: private key card.
  resultsArea.appendChild(createStepCard(
    stepNumber, "Private Key",
    "<p class='key-display'>(d, n) = (" + d + ", " + n + ")</p>" +
    "<p class='key-note'>This pair must be kept secret.</p>",
    "private-key-card", delay
  ));
  stepNumber = stepNumber + 1;
  delay = delay + 1;
  highlightBox(KEYGEN_BOX_ORDER, "kgBox5");
  highlightBox(MESSAGE_BOX_ORDER, "mfBox1");

  // Step 8: encrypt. C = M^e mod n
  var c = modPow(m, e, n);
  resultsArea.appendChild(createStepCard(
    stepNumber, "Encrypt",
    "<p class='formula'>C = M<sup>e</sup> mod n</p>" +
    "<p class='formula-sub'>C = " + m + "<sup>" + e + "</sup> mod " + n + " = <b>" + c + "</b></p>",
    "", delay
  ));
  stepNumber = stepNumber + 1;
  delay = delay + 1;
  highlightBox(MESSAGE_BOX_ORDER, "mfBox2");

  // Step 9: decrypt. M = C^d mod n
  var decrypted = modPow(c, d, n);
  resultsArea.appendChild(createStepCard(
    stepNumber, "Decrypt",
    "<p class='formula'>M = C<sup>d</sup> mod n</p>" +
    "<p class='formula-sub'>M = " + c + "<sup>" + d + "</sup> mod " + n + " = <b>" + decrypted + "</b></p>",
    "", delay
  ));
  stepNumber = stepNumber + 1;
  delay = delay + 1;
  highlightBox(MESSAGE_BOX_ORDER, "mfBox4");

  // Step 10: verification.
  var success = (decrypted === m);
  var verifyHtml = success
    ? "<p>&#9989; Verification Successful &mdash; the decrypted value (" + decrypted +
      ") equals the original message M (" + m + ").</p>"
    : "<p>&#10060; Verification Failed &mdash; the decrypted value (" + decrypted +
      ") does not equal the original message M (" + m + ").</p>";
  resultsArea.appendChild(createStepCard(
    stepNumber, "Verification",
    verifyHtml,
    success ? "verify-success" : "verify-fail", delay
  ));
  highlightBox(MESSAGE_BOX_ORDER, "mfBox5");
}

// Clears every input field, error message, result card and diagram
// highlight, back to the page's starting state. This is the click handler
// for the "Clear / Reset" button. Does not return anything.
function resetLab() {
  document.getElementById("inputP").value = "";
  document.getElementById("inputQ").value = "";
  document.getElementById("inputM").value = "";
  document.getElementById("inputE").value = "";

  showFieldErrors({ p: "", q: "", m: "", e: "" });

  document.getElementById("resultsArea").innerHTML = "";
  resetDiagrams();

  var progressTrack = document.getElementById("progressTrack");
  progressTrack.hidden = true;
  document.getElementById("progressFill").classList.remove("filled");
}


// ==========================================================================
// WIRE UP THE BUTTONS
// ==========================================================================

document.getElementById("generateBtn").addEventListener("click", generateRSA);
document.getElementById("resetBtn").addEventListener("click", resetLab);
