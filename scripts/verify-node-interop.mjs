import { execFileSync } from 'node:child_process';
import { webcrypto } from 'node:crypto';

const fixture = JSON.parse(execFileSync('cargo', ['run', '--quiet', '--example', 'node_interop'], { encoding: 'utf8' }));
const crypto = webcrypto;
const enc = new TextEncoder();
const canonical = Buffer.from(fixture.headers.signed_data, 'base64url');
const publicKey = await crypto.subtle.importKey('jwk', fixture.public_jwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
const validSignature = await crypto.subtle.verify(
  { name: 'ECDSA', hash: 'SHA-256' },
  publicKey,
  Buffer.from(fixture.headers.signature, 'base64url'),
  canonical,
);
if (!validSignature) throw new Error('Node WebCrypto rejected Rust P1363 signature');
const payload = JSON.parse(canonical);
if (JSON.stringify(payload) !== JSON.stringify(fixture.payload)) throw new Error('signed_data payload differs from Rust payload');
const material = await crypto.subtle.importKey('raw', enc.encode(fixture.secret), 'HKDF', false, ['deriveBits']);
const hmacKey = new Uint8Array(await crypto.subtle.deriveBits({
  name: 'HKDF', hash: 'SHA-256', salt: enc.encode('bpc-protocol-hmac-salt-v1'), info: enc.encode('bpc-v1-hmac-key'),
}, material, 256));
const hmac = await crypto.subtle.importKey('raw', hmacKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
const expectedHmac = Buffer.from(await crypto.subtle.sign('HMAC', hmac, enc.encode(payload.nonce + String(payload.timestamp)))).toString('base64url');
if (expectedHmac !== payload.secret_hmac) throw new Error('Node WebCrypto HMAC differs from Rust payload');
const expectedBodyHash = 'sha256:' + Buffer.from(await crypto.subtle.digest('SHA-256', Buffer.from(fixture.body_base64url, 'base64url'))).toString('base64url');
if (expectedBodyHash !== payload.body_hash) throw new Error('Node body hash differs from Rust payload');
console.log('Node WebCrypto verified Rust BPC signature, HKDF/HMAC, canonical payload, and body hash.');
