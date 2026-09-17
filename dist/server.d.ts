import { Key, DecryptResult } from '@pgpjs/core';

interface PGPRouteHandlerContext<T = any> {
    data: T;
    sender?: {
        keyID?: string;
        fingerprint?: string;
        valid: boolean;
    };
    request: Request;
    rawPayload: string;
}
interface PGPRouteHandlerOptions {
    privateKey?: Key | string;
    passphrase?: string;
    clientPublicKey?: Key | string;
    requireSignature?: boolean;
}
/**
 * Next.js Route Handler middleware that automatically handles:
 * incoming encrypted request -> decrypt -> verify signature -> call handler -> encrypt response.
 */
declare function pgp<T = any, R = any>(handler: (ctx: PGPRouteHandlerContext<T>) => Promise<R> | R, options?: PGPRouteHandlerOptions): (request: Request) => Promise<Response>;
/**
 * Server-only helper to decrypt encrypted request payloads in Next.js Route Handlers.
 */
declare function decryptInRouteHandler(request: Request, options: {
    decryptionKeys: Key | Key[];
    passwords?: string[];
}): Promise<DecryptResult>;
/**
 * Higher-order helper for Next.js Server Actions to securely decrypt client-submitted encrypted payloads.
 */
declare function createServerActionDecrypt(options: {
    privateKey?: string;
    decryptionKeys?: Key | Key[];
    passphrase?: string;
    passwords?: string[];
}): (encryptedMessage: string) => Promise<DecryptResult>;
/**
 * Higher-order helper for Next.js Server Actions to sign responses before sending to clients.
 */
declare function createServerActionSign(options: {
    signingKey?: string;
    signingKeys?: Key | Key[];
    passphrase?: string;
}): (data: string | Uint8Array, detached?: boolean) => Promise<string | Uint8Array>;

export { type PGPRouteHandlerContext, type PGPRouteHandlerOptions, createServerActionDecrypt, createServerActionSign, decryptInRouteHandler, pgp };
