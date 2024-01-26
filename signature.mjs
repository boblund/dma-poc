// Wrap webcrypto.subtle sign/verify so Base64 signatures and pem keys are passed and returned, i.e. like NodeJS crypto

import {webcrypto} from 'node:crypto';
export { sign, verify };

const pemHeader = "-----BEGIN PUBLIC KEY-----\n",
	pemFooter = "\n-----END PUBLIC KEY-----",
	sigAlg = {name: "RSASSA-PKCS1-v1_5", saltLength: 32},
	pemAlg = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
	enc = new TextEncoder();


function str2ab(str) {
	const buf = new ArrayBuffer(str.length);
	const bufView = new Uint8Array(buf);
	for (let i = 0, strLen = str.length; i < strLen; i++) {
		bufView[i] = str.charCodeAt(i);
	}
	return buf;
}

function abTob64( buffer ) {
	var binary = '';
	var bytes = new Uint8Array( buffer );
	var len = bytes.byteLength;
	for (var i = 0; i < len; i++) {
		binary += String.fromCharCode( bytes[ i ] );
	}
	return global.btoa( binary );
}

function b64Toab(base64) {
	var binary_string =  global.atob(base64);
	var len = binary_string.length;
	var bytes = new Uint8Array( len );
	for (var i = 0; i < len; i++)        {
		bytes[i] = binary_string.charCodeAt(i);
	}
	return bytes.buffer;
}

async function importPrivateKey(pem) {
	const pemContents = pem.substring(
		pemHeader.length,
		pem.length - pemFooter.length
	);

	return await webcrypto.subtle.importKey( "pkcs8", str2ab(global.atob(pemContents)), pemAlg, true, ["sign"] );
};

async function importRsaKey(pem) {
	const pemContents = pem.substring(
		pemHeader.length,
		pem.length - pemFooter.length
	);

	return await webcrypto.subtle.importKey( "spki", str2ab(global.atob(pemContents)), pemAlg, true, ["verify"] );
};

async function sign(pemPrivateKey, data) {
	return abTob64(
		await webcrypto.subtle.sign(
			sigAlg,
			await importPrivateKey(pemPrivateKey),
			enc.encode(data)
		)
	);
}

async function verify(pemPublicKey, signature, data) {
	let r = undefined;
	try {
		r= await webcrypto.subtle.verify(
			sigAlg,
			await importRsaKey(pemPublicKey),
			b64Toab(signature),
			enc.encode(data)
		);
		return r;
	} catch(e) {
		console.error(e);
	}
}
