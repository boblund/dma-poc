import {createHash, createPublicKey, webcrypto} from 'node:crypto';
const {sign, verify} = webcrypto.subtle; //browser compatability
import {readFileSync, writeFileSync} from 'node:fs';

function ab2str(buf) { return String.fromCharCode.apply(null, new Uint8Array(buf)); }

const namePrefix = process.argv.lenght < 3 ? '' : process.argv[2];

async function exportKey(_type, key) {
	const type = _type.toUpperCase();
	const format = type == 'PUBLIC' ? "spki" : type == 'PRIVATE' ? 'pkcs8' : '';
	const exportedAsBase64 = Buffer.from(ab2str(await webcrypto.subtle.exportKey(format, key)), 'binary').toString('base64');
	const pemExported = `-----BEGIN ${type} KEY-----\n${exportedAsBase64}\n-----END ${type} KEY-----`;
	writeFileSync(`${namePrefix}-${_type}Key.pem`, pemExported);
}

(async () => {
	const alg = {name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256"};
	const {privateKey, publicKey} = await webcrypto.subtle.generateKey(alg, true, ["sign", "verify"]);
	await exportKey('private', privateKey);
	await exportKey('public', publicKey);
})();


