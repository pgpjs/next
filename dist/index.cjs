"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
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
var __reExport = (target, mod, secondTarget) => (__copyProps(target, mod, "default"), secondTarget && __copyProps(secondTarget, mod, "default"));
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var index_exports = {};
__export(index_exports, {
  createServerActionDecrypt: () => createServerActionDecrypt,
  createServerActionSign: () => createServerActionSign,
  decryptInRouteHandler: () => decryptInRouteHandler,
  encryptForServer: () => encryptForServer,
  pgp: () => pgp,
  secureRequest: () => secureRequest,
  verifyFromServer: () => verifyFromServer
});
module.exports = __toCommonJS(index_exports);

// src/client.ts
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

// src/server.ts
var import_core2 = require("@pgpjs/core");
var import_core3 = __toESM(require("@pgpjs/core"), 1);
function pgp(handler, options = {}) {
  return async function POST(request) {
    const rawPayload = await request.text();
    const serverPrivateKey = options.privateKey ?? process.env.PGP_SERVER_PRIVATE_KEY;
    if (!serverPrivateKey) {
      return new Response(JSON.stringify({ error: "Server PGP private key is not configured" }), {
        status: 500,
        headers: { "Content-Type": "application/json" }
      });
    }
    const secKey = typeof serverPrivateKey === "string" ? await (0, import_core2.readKey)({ armoredKey: serverPrivateKey }) : serverPrivateKey;
    if (options.passphrase && !secKey.isDecrypted) {
      await secKey.decrypt(options.passphrase);
    }
    let verificationKeys;
    if (options.clientPublicKey) {
      verificationKeys = typeof options.clientPublicKey === "string" ? await (0, import_core2.readPublicKey)({ armoredKey: options.clientPublicKey }) : options.clientPublicKey;
    }
    const decrypted = await (0, import_core2.decrypt)({
      message: rawPayload,
      decryptionKeys: secKey,
      verificationKeys
    });
    const primarySig = decrypted.signatures[0];
    if (options.requireSignature && (!primarySig || !primarySig.valid)) {
      return new Response(JSON.stringify({ error: "Unauthorized: Invalid or missing client signature" }), {
        status: 401,
        headers: { "Content-Type": "application/json" }
      });
    }
    let parsedData;
    const bodyStr = decrypted.text ?? new TextDecoder().decode(decrypted.data);
    if (bodyStr.startsWith("json:")) {
      parsedData = JSON.parse(bodyStr.slice(5));
    } else if (bodyStr.startsWith("str:")) {
      parsedData = bodyStr.slice(4);
    } else if (bodyStr.startsWith("bin:")) {
      parsedData = Buffer.from(bodyStr.slice(4), "base64");
    } else {
      try {
        parsedData = JSON.parse(bodyStr);
      } catch {
        parsedData = bodyStr;
      }
    }
    const result = await handler({
      data: parsedData,
      sender: primarySig ? { keyID: primarySig.keyID, fingerprint: primarySig.fingerprint, valid: primarySig.valid } : void 0,
      request,
      rawPayload
    });
    if (verificationKeys) {
      const encryptedResponse = await import_core3.default.seal(result, {
        to: verificationKeys,
        from: secKey
      });
      return new Response(encryptedResponse, {
        status: 200,
        headers: { "Content-Type": "application/pgp-encrypted" }
      });
    }
    return new Response(JSON.stringify(result), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    });
  };
}
async function decryptInRouteHandler(request, options) {
  const bodyText = await request.text();
  return (0, import_core2.decrypt)({
    message: bodyText,
    decryptionKeys: options.decryptionKeys,
    passwords: options.passwords
  });
}
function createServerActionDecrypt(options) {
  return async function handleDecrypt(encryptedMessage) {
    let keys = options.decryptionKeys;
    if (!keys && options.privateKey) {
      const k = await (0, import_core2.readKey)({ armoredKey: options.privateKey });
      if (options.passphrase && !k.isDecrypted) {
        await k.decrypt(options.passphrase);
      }
      keys = k;
    }
    return (0, import_core2.decrypt)({
      message: encryptedMessage,
      decryptionKeys: keys,
      passwords: options.passwords
    });
  };
}
function createServerActionSign(options) {
  return async function handleSign(data, detached = false) {
    let keys = options.signingKeys;
    if (!keys && options.signingKey) {
      const k = await (0, import_core2.readKey)({ armoredKey: options.signingKey });
      if (options.passphrase && !k.isDecrypted) {
        await k.decrypt(options.passphrase);
      }
      keys = k;
    }
    return (0, import_core2.sign)({
      message: data,
      signingKeys: keys,
      detached,
      format: "armored"
    });
  };
}

// src/index.ts
__reExport(index_exports, require("@pgpjs/core"), module.exports);
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  createServerActionDecrypt,
  createServerActionSign,
  decryptInRouteHandler,
  encryptForServer,
  pgp,
  secureRequest,
  verifyFromServer,
  ...require("@pgpjs/core")
});
