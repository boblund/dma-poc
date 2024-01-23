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
			let {fingerprint, caaCert, signature} = JSON.parse(assetHeader.value);
			const pemHeader = '-----BEGIN CERTIFICATE-----\n',
				pemFooter = '\n-----END CERTIFICATE-----\n',
				{certificate, subject} = x509cert(caaCert.substring(pemHeader.length, caaCert.length - pemFooter.length));

			if(subject.CN != 'caa.com'){ // Browser would replace with real certificate check
				chrome.action.setBadgeText({ tabId: details.tabId, text: ' ' });
				chrome.action.setBadgeBackgroundColor({tabId: details.tabId, color: '#FF0000'});
				chrome.action.setTitle({tabId: details.tabId, title: 'Untrusted certiticate'});
				return;
			}
			console.log('subject.CN == caa.com');
			var alg = certificate.tbsCertificate.signature.algorithm;
			if (alg !== "1.2.840.113549.1.1.5" && alg !== "1.2.840.113549.1.1.11") {
				throw new Error("Signature algorithm " + alg + " is not supported yet.");
			}
		
			const hashName = alg === "1.2.840.113549.1.1.11" ? "SHA-256" : "SHA-1";
		
			const publicKey = await crypto.subtle.importKey(
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
			console.log(`content hash: ${hash}\nfingerprint.contentHash: ${fingerprint.contentHash}`);
			chrome.action.setBadgeText({ tabId: details.tabId, text: ' ' });
			chrome.action.setBadgeBackgroundColor({
				tabId: details.tabId,
				color: (verified && hash == fingerprint.contentHash) ? '#00FF00' : '#FF0000'
			});
			chrome.action.setTitle({
				tabId: details.tabId,
				title: `${(verified && hash == fingerprint.contentHash) ? 'From' : 'NOT from'} ${fingerprint.creator}. `});
		}
		return;
	}, {urls: ['https://*/*', 'http://*/*']}, ['responseHeaders']
);
