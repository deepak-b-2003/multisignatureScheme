const crypto = require("crypto");
const bigInt = require("big-integer");

function findGenerator(p, q) {
  for (let i = 2; i < p; i++) {
    if (isGenerator(i, p, q)) {
      return i;
    }
  }
  return -1; // No generator found
}

// Function to check if 'a' is a generator of order 'q' in Zp*
function isGenerator(a, p, q) {
  let result = BigInt(1);
  for (let i = 1; i <= q - 1; i++) {
    result = (result * BigInt(a)) % BigInt(p);
    if (result === BigInt(1)) {
      return false;
    }
  }
  result = (result * BigInt(a)) % BigInt(p);
  return result === BigInt(1);
}

// Step 1: Key Generation
function generateKeys(n, p, q, a) {
  const keys = [];
  for (let i = 0; i < n; i++) {
    const xi = bigInt(Math.floor(Math.random() * (q - 1)) + 1); // Secret key
    const yi = bigInt(a).modPow(xi, p); // Public key
    keys.push({ xi, yi });
  }
  console.log("Keys:");
  console.log(keys);

  return keys;
}

// Step 2: Multisignature Generation Phase
function generateMultisignature(message, keys, p, a, q) {
  const kValues = [];
  const partialSignatures = [];

  // Each signer generates random k and calculates ri
  keys.forEach(() => {
    const ki = bigInt(Math.floor(Math.random() * (q - 1)) + 1);
    const ri = bigInt(a).modPow(ki, p);
    kValues.push(ki);
    partialSignatures.push(ri);
  });
  console.log("kValues:");
  console.log(kValues);
  console.log("KpartialSignatures:");
  console.log(partialSignatures);

  // Calculate commitment value R
  hashedMessages = [];
  const commitmentValue = bigInt(
    partialSignatures.reduce((acc, ri, index) => {
      const hi = bigInt(
        crypto.createHash("sha256").update(message[index]).digest("hex"),
        16
      );
      hashedMessages.push(hi);
      return acc.multiply(ri.modPow(hi, p)).mod(p);
    }, bigInt(1))
  );
  console.log("Hashed Messages :");
  console.log(hashedMessages);
  console.log(`Commitment value : ${commitmentValue}`);

  msgHash = [];
  let concatHash = "";
  message.forEach((msg) => {
    let hi = crypto.createHash("sha256").update(msg).digest("hex");
    msgHash.push(hi);
    concatHash += hi;
  });
  concatHash += String(commitmentValue);
  messageHash = bigInt(
    crypto.createHash("sha256").update(concatHash).digest("hex"),
    16
  );
  console.log(`messageHash : ${messageHash}`);

  const signatures = [];
  keys.forEach((key, index) => {
    const { xi, yi } = key;
    const si = bigInt(
      yi.mod(q) * xi.mod(q) * messageHash.mod(q) +
        commitmentValue.mod(q) *
          kValues[index].mod(q) *
          hashedMessages[index].mod(q)
    );
    signatures.push(si.mod(q));
  });
  console.log("Signatures of users :");
  console.log(signatures);

  signatures.forEach((sign, index) => {
    const lhs = bigInt(a).modPow(sign, p);
    const { xi, yi } = keys[index];
    const rhs = bigInt(
      yi
        .modPow(messageHash.multiply(yi), p)
        .multiply(
          partialSignatures[index].modPow(
            commitmentValue.multiply(hashedMessages[index]),
            p
          )
        )
    ).mod(p);
    const isValid = lhs.compare(rhs) ? false : true;
    console.log(`Signature for Signer ${index + 1} is valid:`, isValid);
  });

  const multisignature = signatures.reduce(
    (acc, si) => bigInt(acc + si).mod(q),
    bigInt(0)
  );
  return { commitmentValue, multisignature };
}

// Step 3: Multisignature Verification
function verifyMultisignature(
  message,
  multisignature,
  commitmentValue,
  groupPublicKey,
  p,
  a
) {
  msgHash = [];
  let concatHash = "";
  message.forEach((msg) => {
    let hi = crypto.createHash("sha256").update(msg).digest("hex");
    msgHash.push(hi);
    concatHash += hi;
  });
  concatHash += String(commitmentValue);
  messageHash = bigInt(
    crypto.createHash("sha256").update(concatHash).digest("hex"),
    16
  );
  const lhs = bigInt(a).modPow(multisignature, p);

  // const expectedMultisignature =
  //   (groupPublicKey ** messageHash * commitmentValue ** commitmentValue) % p;
  const expectedMultisignature = bigInt(
    groupPublicKey
      .modPow(messageHash, p)
      .multiply(commitmentValue.modPow(commitmentValue, p))
  ).mod(p);
  return lhs.compare(expectedMultisignature) ? false : true;
}

//Test
const n = 3; // Number of signers
const p = bigInt(11); // Large prime
const q = bigInt(5); // Prime divisor
const a = findGenerator(p, q); // Generator of cyclic group of order q
console.log("Generator of cyclic group:", a);

const message = ["Hello", "World", "Example"]; // Message to be signed

const keys = generateKeys(n, p, q, a);
const { commitmentValue, multisignature } = generateMultisignature(
  message,
  keys,
  p,
  a,
  q
);

//Generating group public key
const groupPublicKey = bigInt(
  keys.reduce((acc, key) => {
    try {
      const yi = bigInt(key.yi);
      return acc.multiply(bigInt(yi).modPow(yi, p)).mod(p);
    } catch (error) {
      console.error("Error processing key:", key, error);
      return null;
    }
  }, bigInt(1))
);
console.log(`Group public key : ${groupPublicKey}`);

console.log("Multisignature:", multisignature);
console.log(
  "Is Valid:",
  verifyMultisignature(
    message,
    multisignature,
    commitmentValue,
    groupPublicKey,
    p,
    a
  )
);
