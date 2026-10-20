import { webcrypto } from 'node:crypto';
import { writeFileSync } from 'node:fs';

const crypto = webcrypto;
const enc = new TextEncoder();
const b64url = (bytes) => Buffer.from(bytes).toString('base64url');

const secret = 'InteropSecret9!@';
const pairId = 'pair_nodeinterop';
const method = 'POST';
const path = '/v1/widgets?source=node';
const body = Buffer.from('{"widget":"bpc","count":2}', 'utf8');
const nonce = '123e4567-e89b-42d3-a456-426614174000';
const timestamp = 1740000000000;

const material = await crypto.subtle.importKey('raw', enc.encode(secret), 'HKDF', false, ['deriveBits']);
const hmacKey = new Uint8Array(await crypto.subtle.deriveBits({
  name: 'HKDF', hash: 'SHA-256', salt: enc.encode('bpc-protocol-hmac-salt-v1'), info: enc.encode('bpc-v1-hmac-key'),
}, material, 256));
const hmac = await crypto.subtle.importKey('raw', hmacKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
const secretHmac = b64url(await crypto.subtle.sign('HMAC', hmac, enc.encode(nonce + String(timestamp))));
const bodyHash = 'sha256:' + b64url(await crypto.subtle.digest('SHA-256', body));
const payload = { body_hash: bodyHash, method, nonce, pair_id: pairId, path, secret_hmac: secretHmac, timestamp, version: '1.0' };
const canonical = JSON.stringify(Object.fromEntries(Object.entries(payload).sort(([a], [b]) => a.localeCompare(b))));
const keyPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
const publicJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
const signature = b64url(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keyPair.privateKey, enc.encode(canonical)));
const fixture = {
  generated_by: 'Node.js WebCrypto ECDSA P-256 + HKDF-SHA256',
  registration_secret: secret,
  request_hmac_key: b64url(hmacKey),
  public_jwk: { kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x, y: publicJwk.y, key_ops: publicJwk.key_ops, ext: publicJwk.ext },
  body_base64url: b64url(body),
  payload,
  headers: { pair_id: pairId, signature, signed_data: b64url(enc.encode(canonical)), version: '1.0' },
};
writeFileSync(new URL('../tests/fixtures/node-webcrypto-v1.json', import.meta.url), JSON.stringify(fixture, null, 2) + '\n');
