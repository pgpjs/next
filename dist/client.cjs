"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/client.ts
var client_exports = {};
__export(client_exports, {
  encryptForServer: () => encryptForServer,
  secureRequest: () => secureRequest,
  verifyFromServer: () => verifyFromServer
});
module.exports = __toCommonJS(client_exports);
var import_core = require("@pgpjs/core");
async function encryptForServer(message, serverPublicKey) {
  const pubKey = typeof serverPublicKey === "string" ? await (0, import_core.readPublicKey)({ armoredKey: serverPublicKey }) : serverPublicKey;
  if (pubKey.isPrivate()) {
    throw new Error("Security violation: private key must never be used in client bundle");
  }
  const encrypted = await (0, import_core.encrypt)({
    message,
    encryptionKeys: pubKey,
    format: "armored"
  });
  return encrypted;
}
async function verifyFromServer(message, serverPublicKey, signature) {
  const pubKey = typeof serverPublicKey === "string" ? await (0, import_core.readPublicKey)({ armoredKey: serverPublicKey }) : serverPublicKey;
  return (0, import_core.verify)({
    message,
    signature,
    verificationKeys: pubKey
  });
}
async function secureRequest(options) {
  const pubKey = typeof options.encryptWith === "string" ? await (0, import_core.readPublicKey)({ armoredKey: options.encryptWith }) : options.encryptWith;
  let signingKey;
  if (options.signWith) {
    signingKey = typeof options.signWith === "string" ? await (0, import_core.readKey)({ armoredKey: options.signWith }) : options.signWith;
    if (options.passphrase && !signingKey.isDecrypted) {
      await signingKey.decrypt(options.passphrase);
    }
  }
  const payload = typeof options.body === "string" ? options.body : JSON.stringify(options.body);
  const encrypted = await (0, import_core.encrypt)({
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
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  encryptForServer,
  secureRequest,
  verifyFromServer
});
