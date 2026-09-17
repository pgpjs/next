import { Key, VerifyResult } from '@pgpjs/core';

/**
 * Client-safe helper to encrypt data intended for the server.
 * Never takes or requires private keys.
 */
declare function encryptForServer(message: string | Uint8Array, serverPublicKey: Key | string): Promise<string>;
/**
 * Client-safe helper to verify server-signed responses.
 */
declare function verifyFromServer(message: string | Uint8Array, serverPublicKey: Key | string, signature?: string): Promise<VerifyResult>;
interface SecureRequestOptions {
    url: string;
    body: any;
    encryptWith: Key | string;
    signWith?: Key | string;
    passphrase?: string;
    fetchOptions?: RequestInit;
}
/**
 * Client-safe helper that encrypts and optionally signs a payload, transmits it to an API route,
 * and parses the response.
 */
declare function secureRequest<T = any>(options: SecureRequestOptions): Promise<T>;

export { type SecureRequestOptions, encryptForServer, secureRequest, verifyFromServer };
