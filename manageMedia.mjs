// DMA simple sign/verify and CRA

import {createHash, createPublicKey} from 'node:crypto';
import {createInterface} from 'readline';
import {readFileSync, writeFileSync} from 'node:fs';

import {sign, verify} from './signature.mjs';
import {Channel} from './js-caf.mjs';

const assetsFile = './assets.json',
	registeredContentFile = './registeredContent.json',
	chans = {},
	publicKeys = {},
	privateKeys = {},
	certs = {};

let assets = {},
	registeredContent = {};

function sha256(media) {  
	return createHash("SHA256").update(media).digest('hex');
}

const creators = ['creator.com'],
	ra = 'ra.com' /*,
	presenters = ['presentation']*/;

[...creators, ra, /*...presenters,*/ 'controller'].forEach(e => chans[e] = new Channel);
[...creators, ra].forEach(e => {
	publicKeys[e] = readFileSync(`./keys/${e}-publicKey.pem`, 'utf-8');
	privateKeys[e] = readFileSync(`./keys/${e}-privateKey.pem`, 'utf-8');
	certs[e] = readFileSync(`./keys/${e}-cert.pem`, 'utf-8');
});

function Message(type, data){this.type = type; this.data = data;}

// creator
async function startCreator(name) {
	try{ assets = JSON.parse(readFileSync(assetsFile)); }
	catch(e){ assets[name] = {}; }

	while(true) {
		let msg = await chans[name].take(),
			data = JSON.parse(msg.data); 

		switch(msg.type){
			case 'add':
				let content = readFileSync(data.fileName);
				if(data.fileName.match(/.*\.html$/) != null) {
					content = content.toString().replace(/[\n|\t]/g,'');
				}
				const contentHash = sha256(content);
				const signature = await sign(privateKeys[name], sha256(JSON.stringify({creator: name, contentHash})));
				await chans[ra].put(new Message('register', JSON.stringify({creator: name, fileName: data.fileName, contentHash, signature})));
				break;

			case 'registerResponse':
				assets[name][data.fileName] = data;
				writeFileSync(assetsFile, JSON.stringify(assets, null, 2));
				chans['controller'].put(`creator: ${name}, asset registered: ${data.fileName}`);	
				break;
				
			case 'registerFailed':
				chans['controller'].put(data.message);
				break;

			case 'delete': 
				if(assets[name][data.fileName] != undefined) {
					const signature = await sign(privateKeys[name], sha256(JSON.stringify({creator: name, contentHash: assets[name][data.fileName].fingerprint.contentHash})));
					chans[ra].put(new Message('delete', JSON.stringify({
						creator: name,
						fileName: data.fileName,
						contentHash: assets[name][data.fileName].fingerprint.contentHash,
						signature})));
					delete assets[name][data.fileName];
				} else {
					chans['controller'].put(`creator: ${name} ${data.fileName} does not exist`);
				}
				break;

			case 'deleteResponse':
				chans['controller'].put(`creator: ${name} ${data.message}`);
				break;

			default:
		} //switch(msg.type)
	} //while(true)
};

// ra
async function startCaa(ra) {
	try{ registeredContent = JSON.parse(readFileSync(registeredContentFile)); }
	catch(e){ registeredContent = {}; }

	while(true) {
		let msg = await chans[ra].take();

		switch(msg.type){
			case 'register':
				let {creator, contentHash, fileName, signature} = JSON.parse(msg.data);
				let creatorPublicKey = createPublicKey(certs[creator]).export({type:'spki', format:'pem'});
				if(await verify( creatorPublicKey, signature, sha256(JSON.stringify({creator, contentHash})) ) ){
					if(registeredContent[contentHash] == undefined){
						registeredContent[contentHash] = {date: new Date, creator, fileName};
						writeFileSync(registeredContentFile, JSON.stringify(registeredContent, null, 2));
						const fingerprint = {contentHash, creator, ra};
						const signature = await sign(privateKeys[ra], sha256(JSON.stringify(fingerprint)));
						chans[creator].put(new Message('registerResponse', JSON.stringify({fileName,fingerprint, signature})));
					} else {
						chans[creator].put(new Message('registerFailed', JSON.stringify({message: `Content filename {$fileName} hash ${contentHash} already registered`})));
					}
				} else {
					chans[creator].put(new Message('registerFailed', JSON.stringify({message: `filename {$fileName} verify(${creator}, ${contentHash}) failed`})));
				}
				break;

			case 'delete':
				{
					const {creator, contentHash, fileName, signature} = JSON.parse(msg.data);
					const creatorPublicKey = createPublicKey(certs[creator]).export({type:'spki', format:'pem'});
					if(await verify(creatorPublicKey, signature, sha256(JSON.stringify({creator, contentHash})))){
						if(registeredContent[contentHash] == undefined){
							chans[creator].put(new Message('deleteResponse', JSON.stringify({message:`${fileName} not registered`})));
						} else {
							delete registeredContent[contentHash];
							chans[creator].put(new Message('deleteResponse', JSON.stringify({message:`${fileName} deleted`})));
						}
					} else {
						chans[creator].put(new Message('deleteResponse', JSON.stringify({message: `verify(${creator}, ${fileName}) failed`})));
					}
				}
				break;
			
			default:
				break;
		} //switch(msg.type)
	} //while(true)
};

const readline = createInterface({
	input: process.stdin,
	output: process.stdout
});

function getCommand(){
	return new Promise((res, rej) => {
		readline.question(`Enter a command: `, resp => {
			if(resp == '') readline.close();
			res(resp);
		});
	});
};

function replacer(key, value){
	if(typeof(value) == 'string' && value.length>30){
		value = `${value.slice(0,10)}...${value.slice(-10)}`;
	}
	return value;
}

// Controller
async function startController(){
	while(true){
		let [cmd, ...args] = (await getCommand()).split(':');
		if(cmd == '') process.exit(1);
		switch(cmd){
			case 'add':
				chans[args[0]].put(new Message(cmd, JSON.stringify({fileName: args[1]})));
				break;

			case 'delete':
				chans[args[0]].put(new Message(cmd, JSON.stringify({fileName: args[1]})));
				break;

			case 'list':
				console.log(`assets\n`);
				console.log(`${JSON.stringify(assets, replacer, 2)}`);
				console.log(`\nregisteredContent`);
				console.log(`${JSON.stringify(registeredContent, replacer, 2)}`);
				console.log('\n');
				break;
	
			default:
				break;
		} //switch(cmd)
		if(cmd != 'list') console.log(await chans.controller.take());
	} //while(true)
};

creators.forEach(creator => startCreator(creator));
startCaa('ra.com');
startController();
