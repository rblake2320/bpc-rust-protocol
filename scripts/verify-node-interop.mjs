import { execFileSync } from 'node:child_process';
import { webcrypto } from 'node:crypto';

const fixture = JSON.parse(execFileSync('cargo', ['run', '--quiet', '--example', 'node_interop'], { encoding: 'utf8' }));
const crypto = webcrypto;
const enc = new TextEncoder();
const canonical = Buffer.from(fixture.headers.signed_data, 'base64url');
const payload = JSON.parse(canonical);
if (JSON.stringify(payload) !== JSON.stringify(fixture.payload)) throw new Error('signed_data payload differs from Rust payload');
if (payload.version !== '2.0' || payload.purpose !== 'http-request') throw new Error('Rust emitted non-v2 request core');
const material = await crypto.subtle.importKey('raw', enc.encode(fixture.secret), 'HKDF', false, ['deriveBits']);
const hmacKey = new Uint8Array(await crypto.subtle.deriveBits({
  name: 'HKDF', hash: 'SHA-256', salt: enc.encode('bpc-protocol-hmac-salt-v2'), info: enc.encode('bpc-v2-request-hmac-key'),
}, material, 256));
const hmac = await crypto.subtle.importKey('raw', hmacKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
const expectedHmac = Buffer.from(await crypto.subtle.sign('HMAC', hmac, Buffer.concat([Buffer.from('BPC-HMAC-v2\0'), canonical]))).toString('base64url');
if (expectedHmac !== fixture.headers.hmac) throw new Error('Node WebCrypto HMAC differs from Rust header');
const transcript = Buffer.concat([Buffer.from('BPC-SIGN-v2\0'), canonical, Buffer.from([0]), Buffer.from(fixture.headers.hmac, 'ascii')]);
const publicKey = await crypto.subtle.importKey('jwk', fixture.public_jwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
const validSignature = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, publicKey, Buffer.from(fixture.headers.signature, 'base64url'), transcript);
if (!validSignature) throw new Error('Node WebCrypto rejected Rust BPC v2 P1363 signature');
const expectedBodyHash = 'sha256:' + Buffer.from(await crypto.subtle.digest('SHA-256', Buffer.from(fixture.body_base64url, 'base64url'))).toString('base64url');
if (expectedBodyHash !== payload.body_hash) throw new Error('Node body hash differs from Rust payload');
console.log('Node WebCrypto verified Rust BPC v2 request HMAC, signature transcript, canonical core, and body hash.');
