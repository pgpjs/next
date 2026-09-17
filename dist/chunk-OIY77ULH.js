// src/server.ts
import { decrypt, sign, readKey, readPublicKey } from "@pgpjs/core";
import PGPJS from "@pgpjs/core";
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
    const secKey = typeof serverPrivateKey === "string" ? await readKey({ armoredKey: serverPrivateKey }) : serverPrivateKey;
    if (options.passphrase && !secKey.isDecrypted) {
      await secKey.decrypt(options.passphrase);
    }
    let verificationKeys;
    if (options.clientPublicKey) {
      verificationKeys = typeof options.clientPublicKey === "string" ? await readPublicKey({ armoredKey: options.clientPublicKey }) : options.clientPublicKey;
    }
    const decrypted = await decrypt({
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
      const encryptedResponse = await PGPJS.seal(result, {
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
  return decrypt({
    message: bodyText,
    decryptionKeys: options.decryptionKeys,
    passwords: options.passwords
  });
}
function createServerActionDecrypt(options) {
  return async function handleDecrypt(encryptedMessage) {
    let keys = options.decryptionKeys;
    if (!keys && options.privateKey) {
      const k = await readKey({ armoredKey: options.privateKey });
      if (options.passphrase && !k.isDecrypted) {
        await k.decrypt(options.passphrase);
      }
      keys = k;
    }
    return decrypt({
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
      const k = await readKey({ armoredKey: options.signingKey });
      if (options.passphrase && !k.isDecrypted) {
        await k.decrypt(options.passphrase);
      }
      keys = k;
    }
    return sign({
      message: data,
      signingKeys: keys,
      detached,
      format: "armored"
    });
  };
}

export {
  pgp,
  decryptInRouteHandler,
  createServerActionDecrypt,
  createServerActionSign
};
