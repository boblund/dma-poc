import {x509cert} from './x509.mjs';

const enc = new TextEncoder();

function delay(msec){
	return new Promise(res => {
		setTimeout(()=>{res();}, msec);
	});
}

async function sha256(data) {
	let buf = await crypto.subtle.digest("SHA-256", new TextEncoder("utf-8").encode(data));
	const hash = Array.prototype.map
		.call(new Uint8Array(buf), x=>(('00'+x.toString(16)).slice(-2)))
		.join('');
	return hash;
}

function b64Toab(base64) {
	let binary_string =  atob(base64),
		bytes = new Uint8Array(binary_string.length);

	for(let i=0; i<binary_string.length; i++){
		bytes[i] = binary_string.charCodeAt(i);
	}
	return bytes.buffer;
}

chrome.webRequest.onCompleted.addListener(
	async function(details) {
		let assetHeader;
		if((assetHeader = details.responseHeaders.find(e => e.name == 'x-asset')) != undefined){
			console.log(`x-asset`);
			let {fingerprint, signature} = JSON.parse(assetHeader.value);
			// check that fingerprint has required fields
			const pemHeader = '-----BEGIN CERTIFICATE-----\n',
				pemFooter = '\n-----END CERTIFICATE-----\n',
				{certificate} = x509cert(fingerprint.raCert.substring(pemHeader.length, fingerprint.raCert.length - pemFooter.length)),
				alg = certificate.tbsCertificate.signature.algorithm;

			if (alg !== "1.2.840.113549.1.1.5" && alg !== "1.2.840.113549.1.1.11") {
				throw new Error("Signature algorithm " + alg + " is not supported yet.");
			}
		
			const hashName = alg === "1.2.840.113549.1.1.11" ? "SHA-256" : "SHA-1",
				publicKey = await crypto.subtle.importKey(
					'spki',
					certificate.tbsCertificate.subjectPublicKeyInfo.asn1.raw,
					{name: "RSASSA-PKCS1-v1_5", hash: {name: hashName}},
					true,
					["verify"]
				);

			let verified = await crypto.subtle.verify(
				{name: "RSASSA-PKCS1-v1_5", hash: {name: hashName}},
				publicKey,
				certificate.signatureValue.bits.bytes,
				certificate.tbsCertificate.asn1.raw
			);
			
			if(!verified /* || TBD certificate issuer not trusted */) {
				chrome.action.setBadgeText({ tabId: details.tabId, text: ' ' });
				chrome.action.setBadgeBackgroundColor({tabId: details.tabId, color: '#FF0000'});
				chrome.action.setTitle({tabId: details.tabId, title: 'Invalid or untrusted Registration Authority PORcertiticate'});
				return;
			}

			verified = await crypto.subtle.verify(
				{name: "RSASSA-PKCS1-v1_5", hash: {name: hashName}},
				publicKey,
				b64Toab(signature),
				enc.encode(await sha256(JSON.stringify(fingerprint)))
			);
			
			let hash = '';
			if(verified){
				await delay(50);	// so DOM finishes loading before running following script
				let s = await chrome.scripting.executeScript({
					target: { tabId: details.tabId },
					function: () => {
						let s = document.getElementsByTagName('html')[0]
							.outerHTML.toString()
							.replace(/[\n|\t]/g,'');
						return s;
					}
				});

				hash = await sha256(s[0].result);
			}

			chrome.action.setBadgeText({ tabId: details.tabId, text: ' ' });
			chrome.action.setBadgeBackgroundColor({
				tabId: details.tabId,
				color: (verified && hash == fingerprint.contentHash) ? '#00FF00' : '#FF0000'
			});
			chrome.action.setTitle({
				tabId: details.tabId,
				title: `Credential details: \n\  CN: ${fingerprint.creatorCN}\n\  O: ${fingerprint.creatorO}\n${!verified ? 'cannot verify signature' : hash != fingerprint.contentHash ? 'content modified' : ''}`
			});
		}
		return;
	}, {urls: ['https://*/*', 'http://*/*']}, ['responseHeaders']
);
