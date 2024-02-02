#!/usr/bin/env node

// License: Creative Commons Attribution-NonCommercial 4.0 International

'use strict';

const express = require('express');
const fs = require('fs');
const os = require('os');
const {existsSync, readFileSync} = require('fs');
const hostName = os.hostname(); //'bobsm1.local';

const httpServer = process.env.HTTPS
	? require('https').createServer({
		key: fs.readFileSync(`${hostName}.key`),
		cert: fs.readFileSync(`${hostName}.cert`)
	})
	: require('http').createServer();

const portRange = [ 10000, 60000 ];
function generatePort() {return (Math.floor(Math.random() * (portRange[1] - portRange[0] + 1)) + portRange[0]);}

function listen(server) {
	return new Promise((res, rej) => {
		const port = hostName == 'lv-nextgen'
			? (process.env.HTTPS ? 443 : 80)
			: process.env.PORT ? process.env.PORT : generatePort();
		server.listen(port, function() { res(port); })
			.on('error', e => {
				rej(e);
			});
	});
}

const assets = JSON.parse(readFileSync('./assets.json'));

function setHeaders(res, path){
	let file = path.match(/.*?(media.*$)/)[1];
	if(assets['creator.com'][file] != undefined){
		res.setHeader('x-asset', JSON.stringify({
			fingerprint: {...assets['creator.com'][file].fingerprint},
			//caaCert: fs.readFileSync(`./keys/caa.com-cert.pem`).toString(),
			signature: assets['creator.com'][file].signature
		}));
	}
}

(async () => {
	let app = express(),
		root = './media';
	if(existsSync(root)) {
		//app = app ? app : express(); //app if necessary
		app.use(express.static(root, {setHeaders}));
	} else {
		console.error(`{root} does not exist`);
		process.exit(1);
	}

	if(app) httpServer.on('request', app);

	let port = null;
	while(true) {
		try {
			if(port = await listen(httpServer))
				break;
		} catch(e){
			if(e.code == 'EADDRINUSE' && !(os.hostname() == 'lv-nextgen') && !process.env.PORT && !process.env.HTTPS) continue;
			console.error(`server error: ${e.code}`);
			process.exit(1);
		}
	}
	process.stdout.write(`HTTP${process.env.HTTPS ? 'S' : ''} server listening on ${port}\n`);
})();
