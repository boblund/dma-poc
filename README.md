# Digital Media Authentication Proof-Of-Concept

Digital Media Authentication (DMA) is a mechanism whereby media is bound to a cryptographic ownership credential. The ownership credential can be used to determine:
- The identity of the content owner
- Is the content unaltered

This determination can be done by any 3rd party using the ownership credential and the existing digital certificate infrastructure.

This proof-of-concept (POC) implements the essential components of DMA:
- Request by a content owner to register a content item with a registration authority thereby receiving an associated ownership credential.
- Delivery of the content and the credential (aka asset) over HTTP.
- A browser extension that uses the credential to check the content authenticity and provide an indication to the user of: authentic, fake or unknown (no credential).

The POC consists of:
- A DMA web server (server.js).
- Media management tools to register new content.
- An asset file (assets.json) with example assers that a content provider uses.
- A registered media file (registeredContent.json) that a Registration Authority uses.
- A chrome extension (chrome-extension/aaset-authn) demonstrating media authentication of html files in a browser.

## Installing the POC

Install [NodeJS](https://nodejs.org), if necessary.

Install the dma-poc respository.

```
git clone git@github.com:boblund/dma-poc.git
cd dma-poc
npm i
```

Install the chrome extension following ```chrome-extension/README.md```. This can be installed on any chromium based browser.

Start the webserver

```
[PORT=xxxx] node server.js
```

The server will start on ```PORT```, if specified, otherwise it will start on a random, unused port.

## Using The Extension
Go to ```http://localhost:PORT/creator-media.html```. The extension icon should show authentic media.
</br></br><img src="./authenticMedia.png" alt="icon" width="200"/>  

Go to ```http://localhost:PORT/fake-media.html```. The extension icon should show fake media (valid ownership credential but wrong media).
</br></br><img src="./fakeMedia.png" alt="icon" width="200"/>   

Entering any other URL will show unknown media, i.e. no credential.
</br></br><img src="./nocred.png" alt="icon" width="200"/>  

## Content Management

Adding new content is a three step process:

1. The Creator ingests the content file and creates a content registration request consisting of the SHA256 hash of the content and the creators common name from their digital certificate. ```server.js``` expects to find content in the ```media``` directory. The Creator signs this information and sends it to the Registration Authority, along with the content file name which serves as a human friendly content identifier.
2. The Regsitration Authority (RA) verifies the request using the signature and also that the content hash is unique. If these tests are successful, the RA saves the date and time, the creators name in a table ```registeredContent.json``` indexed by the content hash and creates an ownership credential consisting of the creator's name, the content hash and the RA's name. This is signed by the RA and sent back to the Creator, along with the filename.
3. The creator saves the ownership credential in a table ```assets.json``` indexed by the file name.

Three tools are provided for adding content: makeKeys.mjs, makeCert.sh and manageMedia.mjs.

### makeKeys.mjs

This takes the Creator or RA name as an argument and creates a new webcrypto.subtle private/public key pair for a new Creator or RA and exports these as PEM keys. Browsers only support Webcryto.subtle qnd require that key format. New keys are only required if adding a new Creator or RA.

Keys must be placed in the ```keys``` directory.

### makeCert.sh

This takes the Creator or RA name as an argument and creates a self-signed organization validated digital certificate using the key pair generated by ```makeKeys.mjs```. In a real-world environment this certificate would be issues by a trusted Certificate Authority.

Certificates must be placed in the ```keys``` directory.

### manageMedia.mjs

This emulates the work flow for ingesting and registering new content, making clear the roles of the Creator and RA. All media is expected to be in the ```media``` directoy. It is implemented as a set JaveScript asyncronous functions that communicate via channels. Three commands are implemented:

```add:creator name: filename``` causes the creator to ingest the content and initiate the registration.

```list``` displays the contents of ```assets.json``` and ```registeredContent.json```

```delete:creator name: filename``` deletes the media from```assets.json``` and ```registeredContent.json```.

## Acknowledgements

This software and associated documentation is the intellectual property of [Cable Television Laboratories, Inc](www.cablelabs.com).

## License

Creative Commons Attribution-NonCommercial 4.0 International

**THIS SOFTWARE COMES WITHOUT ANY WARRANTY, TO THE EXTENT PERMITTED BY APPLICABLE LAW.**

© CableLabs Inc. 2024
