import { generateKeyPair } from '../src/crypto.js';

const keys = generateKeyPair();
console.log(JSON.stringify(keys, null, 2));
console.error('\nStore privateKey in Secret Manager. Never commit it or paste it in chat.');
console.error('Only the address / publicKey are safe to share.');
