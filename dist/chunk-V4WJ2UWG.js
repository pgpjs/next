// src/client.ts
import { readPublicKey, readKey, encrypt, verify } from "@pgpjs/core";
async function encryptForServer(message, serverPublicKey) {
  const pubKey = typeof serverPublicKey === "string" ? await readPublicKey({ armoredKey: serverPublicKey }) : serverPublicKey;
  if (pubKey.isPrivate()) {
    throw new Error("Security violation: private key must never be used in client bundle");
  }
  const encrypted = await encrypt({
    message,
    encryptionKeys: pubKey,
    format: "armored"
  });
  return encrypted;
}
async function verifyFromServer(message, serverPublicKey, signature) {
  const pubKey = typeof serverPublicKey === "string" ? await readPublicKey({ armoredKey: serverPublicKey }) : serverPublicKey;
  return verify({
    message,
    signature,
    verificationKeys: pubKey
  });
}
async function secureRequest(options) {
  const pubKey = typeof options.encryptWith === "string" ? await readPublicKey({ armoredKey: options.encryptWith }) : options.encryptWith;
  let signingKey;
  if (options.signWith) {
    signingKey = typeof options.signWith === "string" ? await readKey({ armoredKey: options.signWith }) : options.signWith;
    if (options.passphrase && !signingKey.isDecrypted) {
      await signingKey.decrypt(options.passphrase);
    }
  }
  const payload = typeof options.body === "string" ? options.body : JSON.stringify(options.body);
  const encrypted = await encrypt({
    message: payload,
    encryptionKeys: pubKey,
    signingKeys: signingKey,
    format: "armored"
  });
  const response = await fetch(options.url, {
    method: "POST",
    headers: {
      "Content-Type": "application/pgp-encrypted",
      ...options.fetchOptions?.headers || {}
    },
    body: encrypted,
    ...options.fetchOptions
  });
  const resText = await response.text();
  try {
    return JSON.parse(resText);
  } catch {
    return resText;
  }
}

export {
  encryptForServer,
  verifyFromServer,
  secureRequest
};
